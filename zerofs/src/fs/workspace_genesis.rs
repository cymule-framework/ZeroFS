//! Non-default, protocol-neutral Workspace genesis mechanics.
//!
//! This module consumes only sealed, already-verified inputs. It deliberately
//! has no production constructor for that seal until Rhizome's canonical CDDL,
//! dual-language fixtures, capability verifier, and receipt signer are wired.
//! The durable operation lifecycle remains the existing 0x0A ledger; 0x0C is
//! only the immutable domain result of the genesis effect.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "feature-staged until the normative verifier and signer are wired"
    )
)]

use crate::db::Db;
use crate::fs::export_authority::{
    ExportIdentity, ExportReverseBinding, encode_reverse_binding, reverse_binding_keys,
};
use crate::fs::key_codec::KeyCodec;
use crate::fs::workspace_operation::{
    CanonicalRequestDigest, EffectDispatchClaim, WorkspaceOperationError, WorkspaceOperationKey,
    WorkspaceOperationLookup, WorkspaceOperationRecord, WorkspaceOperationState,
    WorkspaceTerminalOutcome,
};
use crate::fs::write_coordinator::WriteCoordinator;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use slatedb::object_store::{ObjectStore, path::Path};
#[cfg(test)]
use slatedb::object_store::{ObjectStoreExt, PutMode, PutOptions, PutPayload};
use std::sync::Arc;

const RECORD_MAGIC: &[u8; 4] = b"RWGN";
const RECORD_VERSION: u8 = 1;
const SHA256_SIZE: usize = 32;
const MAX_ID_BYTES: usize = 1024;
const MAX_OBJECT_KEY_BYTES: usize = 4096;
const RECORD_CHECKSUM_DOMAIN: &[u8] = b"rhizome.workspace-genesis-record.v1\0";
const ROOT_OBJECT_PREFIX: &str = "rhizome/workspace-genesis/sha256/";
const EFFECT_CLAIM_DOMAIN: &[u8] = b"rhizome.workspace-genesis-object-create.v1\0";

#[async_trait::async_trait]
trait GenesisObjectCreator: Send + Sync {
    async fn create_once(&self, path: &Path, bytes: &Bytes) -> Result<(), GenesisError>;
    async fn get_exact(&self, path: &Path) -> Result<Bytes, GenesisError>;
}

#[cfg(not(test))]
struct UnavailableGenesisObjectCreator;

#[cfg(not(test))]
#[async_trait::async_trait]
impl GenesisObjectCreator for UnavailableGenesisObjectCreator {
    async fn create_once(&self, _path: &Path, _bytes: &Bytes) -> Result<(), GenesisError> {
        Err(GenesisError::Storage)
    }

    async fn get_exact(&self, _path: &Path) -> Result<Bytes, GenesisError> {
        Err(GenesisError::ObjectOutcomeUnknown)
    }
}

#[cfg(test)]
struct DirectTestGenesisObjectCreator(Arc<dyn ObjectStore>);

#[cfg(test)]
#[async_trait::async_trait]
impl GenesisObjectCreator for DirectTestGenesisObjectCreator {
    async fn create_once(&self, path: &Path, bytes: &Bytes) -> Result<(), GenesisError> {
        match self
            .0
            .put_opts(
                path,
                PutPayload::from(bytes.clone()),
                PutOptions::from(PutMode::Create),
            )
            .await
        {
            Ok(_) | Err(slatedb::object_store::Error::AlreadyExists { .. }) => Ok(()),
            Err(_) => Err(GenesisError::ObjectOutcomeUnknown),
        }
    }

    async fn get_exact(&self, path: &Path) -> Result<Bytes, GenesisError> {
        self.0
            .get(path)
            .await
            .map_err(|_| GenesisError::ObjectOutcomeUnknown)?
            .bytes()
            .await
            .map_err(|_| GenesisError::ObjectOutcomeUnknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContentDigest([u8; SHA256_SIZE]);

impl ContentDigest {
    pub(crate) const fn new(bytes: [u8; SHA256_SIZE]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; SHA256_SIZE] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisCommand {
    pub operation: WorkspaceOperationKey,
    pub request_digest: CanonicalRequestDigest,
    pub actor: String,
    pub actor_generation: u64,
    pub home_cell: String,
    pub home_revision: u64,
    pub authority_epoch: u64,
    pub tenant: String,
    pub template: String,
    pub root_policy: String,
    pub source_create_actor_request_digest: ContentDigest,
    pub object_lineage: String,
    pub storage_shard_id: String,
    pub storage_routing_revision: u64,
    pub virtual_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisMaterializationPlan {
    pub export_name: Vec<u8>,
    pub root_digest: ContentDigest,
    pub root_bytes: Bytes,
}

/// Type-state proof that the caller passed the canonical command through the
/// external Rhizome verifier. Production construction intentionally does not
/// exist in this candidate.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedGenesisInput {
    command: GenesisCommand,
    plan: GenesisMaterializationPlan,
}

impl VerifiedGenesisInput {
    #[cfg(any(test, dst))]
    pub(crate) fn for_test(
        command: GenesisCommand,
        plan: GenesisMaterializationPlan,
    ) -> Result<Self, GenesisError> {
        validate_command(&command, &plan)?;
        Ok(Self { command, plan })
    }

    fn command(&self) -> &GenesisCommand {
        &self.command
    }

    fn plan(&self) -> &GenesisMaterializationPlan {
        &self.plan
    }
}

/// Exact signed terminal bytes produced outside this crate. Like the command
/// seal, this has no production constructor until the normative signer exists.
pub(crate) struct VerifiedGenesisTerminal {
    operation: WorkspaceOperationKey,
    request_digest: CanonicalRequestDigest,
    receipt: GenesisDurabilityReceipt,
    bytes: Bytes,
}

impl VerifiedGenesisTerminal {
    #[cfg(any(test, dst))]
    pub(crate) fn for_test(
        operation: WorkspaceOperationKey,
        request_digest: CanonicalRequestDigest,
        receipt: GenesisDurabilityReceipt,
        bytes: Bytes,
    ) -> Result<Self, GenesisError> {
        if bytes.is_empty() {
            return Err(GenesisError::Invalid);
        }
        Ok(Self {
            operation,
            request_digest,
            receipt,
            bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisDomainRecord {
    pub workspace_id: String,
    pub operation_kind: i32,
    pub request_id: String,
    pub actor: String,
    pub actor_generation: u64,
    pub home_cell: String,
    pub home_revision: u64,
    pub authority_epoch: u64,
    pub tenant: String,
    pub template: String,
    pub root_policy: String,
    pub source_create_actor_request_digest: ContentDigest,
    pub object_lineage: String,
    pub storage_shard_id: String,
    pub storage_routing_revision: u64,
    pub effect_claim: Bytes,
    pub request_digest: CanonicalRequestDigest,
    pub root_digest: ContentDigest,
    pub root_object_key: String,
    pub export: ExportIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisDurabilityReceipt {
    pub record: GenesisDomainRecord,
    pub writer_epoch: u64,
    pub durable_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GenesisMaterializeResult {
    Materialized(Box<GenesisDurabilityReceipt>),
    AlreadyTerminal(WorkspaceOperationRecord),
    Rejected(Box<GenesisRejection>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenesisRejectionReason {
    ObjectConflict,
    PhysicalConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisRejection {
    pub(super) operation: WorkspaceOperationKey,
    pub(super) request_digest: CanonicalRequestDigest,
    pub(super) effect_claim: Bytes,
    pub(super) reason: GenesisRejectionReason,
}

pub(crate) struct VerifiedGenesisNegativeTerminal {
    rejection: GenesisRejection,
    bytes: Bytes,
}

impl VerifiedGenesisNegativeTerminal {
    #[cfg(any(test, dst))]
    pub(crate) fn for_test(
        rejection: GenesisRejection,
        bytes: Bytes,
    ) -> Result<Self, GenesisError> {
        if bytes.is_empty() {
            return Err(GenesisError::Invalid);
        }
        Ok(Self { rejection, bytes })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GenesisError {
    #[error("invalid Workspace genesis input")]
    Invalid,
    #[error("Workspace genesis request conflicts with durable state")]
    Conflict,
    #[error("Workspace genesis record is corrupt")]
    Corrupt,
    #[error("Workspace genesis commit outcome is unknown; use durable readback")]
    CommitOutcomeUnknown,
    #[error("Workspace genesis object-store outcome is unknown")]
    ObjectOutcomeUnknown,
    #[error("Workspace genesis storage failure")]
    Storage,
}

impl From<WorkspaceOperationError> for GenesisError {
    fn from(value: WorkspaceOperationError) -> Self {
        match value {
            WorkspaceOperationError::RequestConflict
            | WorkspaceOperationError::TerminalImmutable => Self::Conflict,
            WorkspaceOperationError::CommitOutcomeUnknown => Self::CommitOutcomeUnknown,
            WorkspaceOperationError::InvalidIdentity(_) => Self::Invalid,
            WorkspaceOperationError::CorruptRecord(_) => Self::Corrupt,
            WorkspaceOperationError::Storage(_) => Self::Storage,
        }
    }
}

#[derive(Clone)]
pub(crate) struct WorkspaceGenesisStore {
    db: Arc<Db>,
    coordinator: WriteCoordinator,
    operations: crate::fs::workspace_operation::WorkspaceOperationLedger,
    object_creator: Arc<dyn GenesisObjectCreator>,
    local_storage_shard_id: Arc<str>,
}

impl WorkspaceGenesisStore {
    pub(crate) fn new(
        db: Arc<Db>,
        coordinator: WriteCoordinator,
        operations: crate::fs::workspace_operation::WorkspaceOperationLedger,
        object_store: Arc<dyn ObjectStore>,
    ) -> Self {
        #[cfg(test)]
        let object_creator: Arc<dyn GenesisObjectCreator> =
            Arc::new(DirectTestGenesisObjectCreator(object_store));
        #[cfg(not(test))]
        let object_creator: Arc<dyn GenesisObjectCreator> = {
            let _ = object_store;
            Arc::new(UnavailableGenesisObjectCreator)
        };
        Self {
            db,
            coordinator,
            operations,
            object_creator,
            #[cfg(test)]
            local_storage_shard_id: "test-shard".into(),
            #[cfg(not(test))]
            local_storage_shard_id: "unconfigured".into(),
        }
    }

    pub(crate) async fn materialize(
        &self,
        verified: VerifiedGenesisInput,
    ) -> Result<GenesisMaterializeResult, GenesisError> {
        let command = verified.command();
        let plan = verified.plan();
        validate_command(command, plan)?;
        if command.storage_shard_id != self.local_storage_shard_id.as_ref() {
            return Err(GenesisError::Invalid);
        }
        let operation = self
            .operations
            .begin(&command.operation, command.request_digest)
            .await?;
        if operation.state.is_terminal() {
            return Ok(GenesisMaterializeResult::AlreadyTerminal(operation));
        }

        let object_key = content_object_key(plan.root_digest);
        let (claim_bytes, dispatch_create) = match operation.state {
            WorkspaceOperationState::Pending => {
                let installer = uuid::Uuid::new_v4().to_string();
                let candidate = effect_claim(plan.root_digest, &object_key, &installer);
                match self
                    .operations
                    .claim_effect_dispatch(
                        &command.operation,
                        command.request_digest,
                        candidate.clone(),
                    )
                    .await
                {
                    Ok(EffectDispatchClaim::Installed(_)) => (candidate, true),
                    Ok(EffectDispatchClaim::Existing(record)) => match &record.state {
                        WorkspaceOperationState::EffectDispatched(existing) => {
                            (existing.clone(), false)
                        }
                        state if state.is_terminal() => {
                            return Ok(GenesisMaterializeResult::AlreadyTerminal(record));
                        }
                        _ => return Err(GenesisError::Conflict),
                    },
                    Err(WorkspaceOperationError::CommitOutcomeUnknown) => {
                        // This exact invocation has not dispatched Create yet.
                        // Only its random installer token can authorize the
                        // one attempt after durable claim readback.
                        match self
                            .operations
                            .lookup(&command.operation, command.request_digest)
                            .await?
                        {
                            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                                state: WorkspaceOperationState::EffectDispatched(existing),
                                ..
                            }) if existing == candidate => (candidate, true),
                            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                                state: WorkspaceOperationState::EffectDispatched(existing),
                                ..
                            }) => (existing, false),
                            _ => return Err(GenesisError::CommitOutcomeUnknown),
                        }
                    }
                    Err(WorkspaceOperationError::RequestConflict) => match self
                        .operations
                        .lookup(&command.operation, command.request_digest)
                        .await?
                    {
                        WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                            state: WorkspaceOperationState::EffectDispatched(existing),
                            ..
                        }) => (existing, false),
                        _ => return Err(GenesisError::Conflict),
                    },
                    Err(error) => return Err(error.into()),
                }
            }
            WorkspaceOperationState::EffectDispatched(existing) => (existing, false),
            _ => return Ok(GenesisMaterializeResult::AlreadyTerminal(operation)),
        };
        if dispatch_create {
            let path = Path::from(object_key.as_str());
            let _ = self
                .object_creator
                .create_once(&path, &plan.root_bytes)
                .await;
        }
        if let Err(error) = get_content_addressed_exact(
            &self.object_creator,
            &object_key,
            plan.root_digest,
            &plan.root_bytes,
        )
        .await
        {
            if error == GenesisError::Conflict {
                return Ok(GenesisMaterializeResult::Rejected(Box::new(
                    GenesisRejection {
                        operation: command.operation.clone(),
                        request_digest: command.request_digest,
                        effect_claim: claim_bytes,
                        reason: GenesisRejectionReason::ObjectConflict,
                    },
                )));
            }
            return Err(error);
        }

        let record = GenesisDomainRecord {
            workspace_id: command.operation.workspace_id.clone(),
            operation_kind: command.operation.kind,
            request_id: command.operation.request_id.clone(),
            actor: command.actor.clone(),
            actor_generation: command.actor_generation,
            home_cell: command.home_cell.clone(),
            home_revision: command.home_revision,
            authority_epoch: command.authority_epoch,
            tenant: command.tenant.clone(),
            template: command.template.clone(),
            root_policy: command.root_policy.clone(),
            source_create_actor_request_digest: command.source_create_actor_request_digest,
            object_lineage: command.object_lineage.clone(),
            storage_shard_id: command.storage_shard_id.clone(),
            storage_routing_revision: command.storage_routing_revision,
            effect_claim: claim_bytes.clone(),
            request_digest: command.request_digest,
            root_digest: plan.root_digest,
            root_object_key: object_key,
            export: ExportIdentity {
                nbd_directory_inode: 0,
                name: plan.export_name.clone(),
                inode: 0,
                advertised_size: command.virtual_size_bytes,
            },
        };
        let receipt = match self.coordinator.materialize_workspace_genesis(record).await {
            Ok(receipt) => receipt,
            Err(GenesisError::Invalid | GenesisError::Conflict) => {
                return Ok(GenesisMaterializeResult::Rejected(Box::new(
                    GenesisRejection {
                        operation: command.operation.clone(),
                        request_digest: command.request_digest,
                        effect_claim: claim_bytes,
                        reason: GenesisRejectionReason::PhysicalConflict,
                    },
                )));
            }
            Err(error) => return Err(error),
        };
        Ok(GenesisMaterializeResult::Materialized(Box::new(receipt)))
    }

    pub(crate) async fn complete(
        &self,
        verified: &VerifiedGenesisInput,
        terminal: VerifiedGenesisTerminal,
    ) -> Result<WorkspaceOperationLookup, GenesisError> {
        let command = verified.command();
        if terminal.operation != command.operation
            || terminal.request_digest != command.request_digest
        {
            return Err(GenesisError::Conflict);
        }
        let durable = self
            .lookup_record_durable(&command.operation.workspace_id)
            .await?
            .ok_or(GenesisError::Conflict)?;
        if durable != terminal.receipt.record {
            return Err(GenesisError::Conflict);
        }
        validate_durable_graph(&self.db, &durable).await?;
        if terminal.receipt.writer_epoch == 0 || terminal.receipt.durable_seq == 0 {
            return Err(GenesisError::Conflict);
        }
        self.operations
            .complete_claimed_effect(
                &command.operation,
                command.request_digest,
                &durable.effect_claim,
                WorkspaceTerminalOutcome::Succeeded(terminal.bytes),
            )
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn complete_rejection(
        &self,
        verified: &VerifiedGenesisInput,
        terminal: VerifiedGenesisNegativeTerminal,
    ) -> Result<WorkspaceOperationRecord, GenesisError> {
        let command = verified.command();
        if terminal.rejection.operation != command.operation
            || terminal.rejection.request_digest != command.request_digest
        {
            return Err(GenesisError::Conflict);
        }
        self.coordinator
            .complete_workspace_genesis_rejection(terminal.rejection, terminal.bytes)
            .await
    }

    pub(crate) async fn lookup_record_durable(
        &self,
        workspace_id: &str,
    ) -> Result<Option<GenesisDomainRecord>, GenesisError> {
        validate_id(workspace_id)?;
        let key = KeyCodec::new().workspace_genesis_key(workspace_id);
        let Some(bytes) = self
            .db
            .get_bytes_durable(&key)
            .await
            .map_err(|_| GenesisError::Storage)?
        else {
            return Ok(None);
        };
        decode_record(&key, &bytes).map(Some)
    }
}

pub(super) struct WorkspaceGenesisRequest {
    pub record: GenesisDomainRecord,
}

pub(super) struct WorkspaceGenesisRejectionRequest {
    pub rejection: GenesisRejection,
    pub terminal_bytes: Bytes,
}

pub(crate) async fn read_record_current(
    db: &Db,
    workspace_id: &str,
) -> Result<Option<GenesisDomainRecord>, GenesisError> {
    validate_id(workspace_id)?;
    let key = KeyCodec::new().workspace_genesis_key(workspace_id);
    let Some(bytes) = db
        .get_bytes(&key)
        .await
        .map_err(|_| GenesisError::Storage)?
    else {
        return Ok(None);
    };
    decode_record(&key, &bytes).map(Some)
}

pub(crate) fn validate_activation_genesis(
    record: &GenesisDomainRecord,
    workspace_id: &str,
    authority: &crate::fs::export_authority::AuthorityVersion,
    export: &ExportIdentity,
) -> Result<(), GenesisError> {
    if record.workspace_id == workspace_id
        && record.actor == authority.actor
        && record.actor_generation == authority.actor_generation
        && record.home_cell == authority.home_cell
        && authority.home_revision >= record.home_revision
        && authority.authority_epoch >= record.authority_epoch
        && authority.placement_epoch > 0
        && authority.assignment_revision > 0
        && record.export == *export
    {
        Ok(())
    } else {
        Err(GenesisError::Conflict)
    }
}

async fn validate_durable_graph(db: &Db, record: &GenesisDomainRecord) -> Result<(), GenesisError> {
    crate::fs::write_coordinator::validate_physical_export(db, &KeyCodec::new(), &record.export)
        .await
        .map_err(|_| GenesisError::Corrupt)?;
    let binding = reverse_binding(record);
    let (name_key, inode_key) = reverse_binding_keys(&binding);
    if crate::fs::export_authority::read_reverse_binding_durable(db, &name_key)
        .await
        .map_err(|_| GenesisError::Storage)?
        != Some(binding.clone())
        || crate::fs::export_authority::read_reverse_binding_durable(db, &inode_key)
            .await
            .map_err(|_| GenesisError::Storage)?
            != Some(binding)
    {
        return Err(GenesisError::Corrupt);
    }
    Ok(())
}

pub(super) fn encode_record(
    key: &[u8],
    record: &GenesisDomainRecord,
) -> Result<Bytes, GenesisError> {
    validate_record(record)?;
    let mut payload = Vec::new();
    push_string(&mut payload, &record.workspace_id)?;
    payload.extend_from_slice(&record.operation_kind.to_be_bytes());
    push_string(&mut payload, &record.request_id)?;
    push_string(&mut payload, &record.actor)?;
    payload.extend_from_slice(&record.actor_generation.to_be_bytes());
    push_string(&mut payload, &record.home_cell)?;
    payload.extend_from_slice(&record.home_revision.to_be_bytes());
    payload.extend_from_slice(&record.authority_epoch.to_be_bytes());
    push_string(&mut payload, &record.tenant)?;
    push_string(&mut payload, &record.template)?;
    push_string(&mut payload, &record.root_policy)?;
    payload.extend_from_slice(record.source_create_actor_request_digest.as_bytes());
    push_string(&mut payload, &record.object_lineage)?;
    push_string(&mut payload, &record.storage_shard_id)?;
    payload.extend_from_slice(&record.storage_routing_revision.to_be_bytes());
    push_bytes(&mut payload, &record.effect_claim)?;
    payload.extend_from_slice(record.request_digest.as_bytes());
    payload.extend_from_slice(record.root_digest.as_bytes());
    push_string_limit(&mut payload, &record.root_object_key, MAX_OBJECT_KEY_BYTES)?;
    payload.extend_from_slice(&record.export.nbd_directory_inode.to_be_bytes());
    push_bytes(&mut payload, &record.export.name)?;
    payload.extend_from_slice(&record.export.inode.to_be_bytes());
    payload.extend_from_slice(&record.export.advertised_size.to_be_bytes());

    let key_digest: [u8; SHA256_SIZE] = Sha256::digest(key).into();
    let payload_len = u32::try_from(payload.len()).map_err(|_| GenesisError::Invalid)?;
    let mut out = Vec::with_capacity(4 + 1 + 32 + 4 + payload.len() + 32);
    out.extend_from_slice(RECORD_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&key_digest);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&payload);
    let checksum: [u8; SHA256_SIZE] = Sha256::new()
        .chain_update(RECORD_CHECKSUM_DOMAIN)
        .chain_update(&out)
        .finalize()
        .into();
    out.extend_from_slice(&checksum);
    Ok(Bytes::from(out))
}

pub(crate) fn decode_record(key: &[u8], bytes: &[u8]) -> Result<GenesisDomainRecord, GenesisError> {
    const HEADER: usize = 4 + 1 + 32 + 4;
    if bytes.len() < HEADER + 32 || &bytes[..4] != RECORD_MAGIC || bytes[4] != RECORD_VERSION {
        return Err(GenesisError::Corrupt);
    }
    let expected_key_digest: [u8; SHA256_SIZE] = Sha256::digest(key).into();
    if bytes[5..37] != expected_key_digest {
        return Err(GenesisError::Corrupt);
    }
    let payload_len = u32::from_be_bytes(bytes[37..41].try_into().unwrap()) as usize;
    let checksum_offset = HEADER
        .checked_add(payload_len)
        .ok_or(GenesisError::Corrupt)?;
    if checksum_offset + SHA256_SIZE != bytes.len() {
        return Err(GenesisError::Corrupt);
    }
    let expected_checksum: [u8; SHA256_SIZE] = Sha256::new()
        .chain_update(RECORD_CHECKSUM_DOMAIN)
        .chain_update(&bytes[..checksum_offset])
        .finalize()
        .into();
    if bytes[checksum_offset..] != expected_checksum {
        return Err(GenesisError::Corrupt);
    }
    let mut input = &bytes[HEADER..checksum_offset];
    let workspace_id = take_string(&mut input, MAX_ID_BYTES)?;
    let operation_kind = take_i32(&mut input)?;
    let request_id = take_string(&mut input, MAX_ID_BYTES)?;
    let actor = take_string(&mut input, MAX_ID_BYTES)?;
    let actor_generation = take_u64(&mut input)?;
    let home_cell = take_string(&mut input, MAX_ID_BYTES)?;
    let home_revision = take_u64(&mut input)?;
    let authority_epoch = take_u64(&mut input)?;
    let tenant = take_string(&mut input, MAX_ID_BYTES)?;
    let template = take_string(&mut input, MAX_ID_BYTES)?;
    let root_policy = take_string(&mut input, MAX_ID_BYTES)?;
    let source_create_actor_request_digest = ContentDigest::new(take_array(&mut input)?);
    let object_lineage = take_string(&mut input, MAX_ID_BYTES)?;
    let storage_shard_id = take_string(&mut input, MAX_ID_BYTES)?;
    let storage_routing_revision = take_u64(&mut input)?;
    let effect_claim = Bytes::from(take_bytes(&mut input, MAX_OBJECT_KEY_BYTES)?);
    let request_digest = CanonicalRequestDigest::new(take_array(&mut input)?);
    let root_digest = ContentDigest::new(take_array(&mut input)?);
    let root_object_key = take_string(&mut input, MAX_OBJECT_KEY_BYTES)?;
    let nbd_directory_inode = take_u64(&mut input)?;
    let name = take_bytes(&mut input, MAX_ID_BYTES)?;
    let inode = take_u64(&mut input)?;
    let advertised_size = take_u64(&mut input)?;
    if !input.is_empty() {
        return Err(GenesisError::Corrupt);
    }
    let record = GenesisDomainRecord {
        workspace_id,
        operation_kind,
        request_id,
        actor,
        actor_generation,
        home_cell,
        home_revision,
        authority_epoch,
        tenant,
        template,
        root_policy,
        source_create_actor_request_digest,
        object_lineage,
        storage_shard_id,
        storage_routing_revision,
        effect_claim,
        request_digest,
        root_digest,
        root_object_key,
        export: ExportIdentity {
            nbd_directory_inode,
            name,
            inode,
            advertised_size,
        },
    };
    validate_record(&record).map_err(|_| GenesisError::Corrupt)?;
    if KeyCodec::new()
        .workspace_genesis_key(&record.workspace_id)
        .as_ref()
        != key
    {
        return Err(GenesisError::Corrupt);
    }
    Ok(record)
}

fn validate_command(
    command: &GenesisCommand,
    plan: &GenesisMaterializationPlan,
) -> Result<(), GenesisError> {
    validate_id(&command.operation.workspace_id)?;
    validate_id(&command.operation.request_id)?;
    validate_id(&command.actor)?;
    validate_id(&command.home_cell)?;
    validate_id(&command.tenant)?;
    validate_id(&command.template)?;
    validate_id(&command.root_policy)?;
    validate_id(&command.object_lineage)?;
    validate_id(&command.storage_shard_id)?;
    if command.operation.kind <= 0
        || command.actor_generation == 0
        || command.home_revision == 0
        || command.authority_epoch == 0
        || command.storage_routing_revision == 0
        || plan.export_name.is_empty()
        || plan.export_name.len() > crate::fs::NAME_MAX
        || plan.export_name == b"."
        || plan.export_name == b".."
        || command.virtual_size_bytes == 0
        || !command.virtual_size_bytes.is_multiple_of(512)
        || plan.root_bytes.is_empty()
        || Sha256::digest(&plan.root_bytes).as_slice() != plan.root_digest.as_bytes()
    {
        return Err(GenesisError::Invalid);
    }
    Ok(())
}

fn validate_record(record: &GenesisDomainRecord) -> Result<(), GenesisError> {
    validate_id(&record.workspace_id)?;
    validate_id(&record.request_id)?;
    validate_id(&record.actor)?;
    validate_id(&record.home_cell)?;
    validate_id(&record.tenant)?;
    validate_id(&record.template)?;
    validate_id(&record.root_policy)?;
    validate_id(&record.object_lineage)?;
    validate_id(&record.storage_shard_id)?;
    if record.operation_kind <= 0
        || record.actor_generation == 0
        || record.home_revision == 0
        || record.authority_epoch == 0
        || record.storage_routing_revision == 0
        || record.effect_claim.is_empty()
        || record.export.nbd_directory_inode == 0
        || record.export.inode == 0
        || record.export.name.is_empty()
        || record.export.name.len() > crate::fs::NAME_MAX
        || record.export.advertised_size == 0
        || !record.export.advertised_size.is_multiple_of(512)
        || record.root_object_key != content_object_key(record.root_digest)
    {
        return Err(GenesisError::Invalid);
    }
    validate_effect_claim(record)?;
    Ok(())
}

fn validate_id(value: &str) -> Result<(), GenesisError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.as_bytes().contains(&0) {
        Err(GenesisError::Invalid)
    } else {
        Ok(())
    }
}

fn content_object_key(digest: ContentDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(ROOT_OBJECT_PREFIX.len() + SHA256_SIZE * 2);
    out.push_str(ROOT_OBJECT_PREFIX);
    for byte in digest.as_bytes() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn effect_claim(digest: ContentDigest, object_key: &str, installer: &str) -> Bytes {
    let mut out = Vec::with_capacity(
        EFFECT_CLAIM_DOMAIN.len() + SHA256_SIZE + object_key.len() + installer.len() + 2,
    );
    out.extend_from_slice(EFFECT_CLAIM_DOMAIN);
    out.extend_from_slice(digest.as_bytes());
    out.extend_from_slice(object_key.as_bytes());
    out.push(0);
    out.extend_from_slice(installer.as_bytes());
    Bytes::from(out)
}

fn validate_effect_claim(record: &GenesisDomainRecord) -> Result<(), GenesisError> {
    let mut prefix = Vec::with_capacity(
        EFFECT_CLAIM_DOMAIN.len() + SHA256_SIZE + record.root_object_key.len() + 1,
    );
    prefix.extend_from_slice(EFFECT_CLAIM_DOMAIN);
    prefix.extend_from_slice(record.root_digest.as_bytes());
    prefix.extend_from_slice(record.root_object_key.as_bytes());
    prefix.push(0);
    let Some(installer) = record.effect_claim.strip_prefix(prefix.as_slice()) else {
        return Err(GenesisError::Invalid);
    };
    let installer = std::str::from_utf8(installer).map_err(|_| GenesisError::Invalid)?;
    let parsed = uuid::Uuid::parse_str(installer).map_err(|_| GenesisError::Invalid)?;
    if parsed.to_string() != installer {
        return Err(GenesisError::Invalid);
    }
    Ok(())
}

async fn get_content_addressed_exact(
    creator: &Arc<dyn GenesisObjectCreator>,
    object_key: &str,
    digest: ContentDigest,
    bytes: &Bytes,
) -> Result<(), GenesisError> {
    let path = Path::from(object_key);
    let read = creator.get_exact(&path).await?;
    if read.len() != bytes.len()
        || Sha256::digest(&read).as_slice() != digest.as_bytes()
        || read != *bytes
    {
        return Err(GenesisError::Conflict);
    }
    Ok(())
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), GenesisError> {
    push_string_limit(out, value, MAX_ID_BYTES)
}

fn push_string_limit(out: &mut Vec<u8>, value: &str, max: usize) -> Result<(), GenesisError> {
    if value.len() > max {
        return Err(GenesisError::Invalid);
    }
    push_bytes(out, value.as_bytes())
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), GenesisError> {
    let len = u16::try_from(value.len()).map_err(|_| GenesisError::Invalid)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn take_bytes(input: &mut &[u8], max: usize) -> Result<Vec<u8>, GenesisError> {
    if input.len() < 2 {
        return Err(GenesisError::Corrupt);
    }
    let len = u16::from_be_bytes(input[..2].try_into().unwrap()) as usize;
    if len > max || input.len() < 2 + len {
        return Err(GenesisError::Corrupt);
    }
    let value = input[2..2 + len].to_vec();
    *input = &input[2 + len..];
    Ok(value)
}

fn take_string(input: &mut &[u8], max: usize) -> Result<String, GenesisError> {
    String::from_utf8(take_bytes(input, max)?).map_err(|_| GenesisError::Corrupt)
}

fn take_u64(input: &mut &[u8]) -> Result<u64, GenesisError> {
    if input.len() < 8 {
        return Err(GenesisError::Corrupt);
    }
    let value = u64::from_be_bytes(input[..8].try_into().unwrap());
    *input = &input[8..];
    Ok(value)
}

fn take_i32(input: &mut &[u8]) -> Result<i32, GenesisError> {
    if input.len() < 4 {
        return Err(GenesisError::Corrupt);
    }
    let value = i32::from_be_bytes(input[..4].try_into().unwrap());
    *input = &input[4..];
    Ok(value)
}

fn take_array(input: &mut &[u8]) -> Result<[u8; SHA256_SIZE], GenesisError> {
    if input.len() < SHA256_SIZE {
        return Err(GenesisError::Corrupt);
    }
    let value = input[..SHA256_SIZE].try_into().unwrap();
    *input = &input[SHA256_SIZE..];
    Ok(value)
}

pub(super) fn reverse_binding(record: &GenesisDomainRecord) -> ExportReverseBinding {
    ExportReverseBinding {
        workspace_id: record.workspace_id.clone(),
        actor: record.actor.clone(),
        actor_generation: record.actor_generation,
        export: record.export.clone(),
    }
}

pub(super) type EncodedReverseBindings = ((Bytes, Bytes), (Bytes, Bytes));

pub(super) fn encoded_reverse_bindings(
    record: &GenesisDomainRecord,
) -> Result<EncodedReverseBindings, GenesisError> {
    let binding = reverse_binding(record);
    let (name_key, inode_key) = reverse_binding_keys(&binding);
    let name_value =
        encode_reverse_binding(&binding, &name_key).map_err(|_| GenesisError::Corrupt)?;
    let inode_value =
        encode_reverse_binding(&binding, &inode_key).map_err(|_| GenesisError::Corrupt)?;
    Ok(((name_key, name_value), (inode_key, inode_value)))
}

/// Deterministic explicit-codec/cross-key model used by the repository DST
/// binary. This does not construct a verified production command.
#[cfg(dst)]
#[doc(hidden)]
pub fn dst_workspace_genesis_codec_model(seed: u64) {
    let workspace_id = format!("workspace-{seed}");
    let digest: [u8; 32] = Sha256::digest(seed.to_be_bytes()).into();
    let record = GenesisDomainRecord {
        workspace_id: workspace_id.clone(),
        operation_kind: 101,
        request_id: format!("request-{seed}"),
        actor: format!("actor-{seed}"),
        actor_generation: seed.saturating_add(1),
        home_cell: "cells/dst".into(),
        home_revision: 1,
        authority_epoch: 1,
        tenant: "tenants/dst".into(),
        template: "templates/dst@sha256:01".into(),
        root_policy: "policies/dst@1".into(),
        source_create_actor_request_digest: ContentDigest::new(digest),
        object_lineage: format!("lineage-{seed}"),
        storage_shard_id: "shard-dst".into(),
        storage_routing_revision: 1,
        effect_claim: effect_claim(
            ContentDigest::new(digest),
            &content_object_key(ContentDigest::new(digest)),
            "00000000-0000-4000-8000-000000000001",
        ),
        request_digest: CanonicalRequestDigest::new(digest),
        root_digest: ContentDigest::new(digest),
        root_object_key: content_object_key(ContentDigest::new(digest)),
        export: ExportIdentity {
            nbd_directory_inode: seed.saturating_add(2),
            name: format!("disk-{seed}").into_bytes(),
            inode: seed.saturating_add(3),
            advertised_size: 4096,
        },
    };
    let key = KeyCodec::new().workspace_genesis_key(&workspace_id);
    let encoded = encode_record(&key, &record).expect("DST valid genesis record");
    assert_eq!(
        decode_record(&key, &encoded).expect("DST genesis round trip"),
        record
    );
    let wrong_key = KeyCodec::new().workspace_genesis_key(&format!("other-{seed}"));
    assert_eq!(
        decode_record(&wrong_key, &encoded),
        Err(GenesisError::Corrupt)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_transformer::ZeroFsBlockTransformer;
    use crate::config::CompressionConfig;
    use crate::db::SlateDbHandle;
    use crate::frame_codec::FrameCodec;
    use crate::fs::ZeroFS;
    use crate::fs::export_authority::{
        ActivateExport, AuthorityVersion, ExportSessionState, ShardProcessGuard,
    };
    use slatedb::object_store::path::Path;
    use slatedb::{BlockTransformer, DbBuilder};

    async fn new_fs() -> ZeroFS {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.mkdir(
            &crate::fs::test_util::test_creds(),
            0,
            b".nbd",
            &crate::fs::types::SetAttributes::default(),
        )
        .await
        .unwrap();
        fs
    }

    async fn open_reopen_fs(object_store: Arc<dyn ObjectStore>) -> ZeroFS {
        let test_key = [0u8; 32];
        let transformer: Arc<dyn BlockTransformer> =
            ZeroFsBlockTransformer::try_new_arc(&test_key, CompressionConfig::default()).unwrap();
        let db = Arc::new(
            DbBuilder::new(Path::from("workspace-genesis-reopen"), object_store.clone())
                .with_block_transformer(transformer)
                .with_filter_policies(crate::fs::filter_policy::filter_policies())
                .with_segment_extractor(Arc::new(crate::segment_extractor::ZeroFsSegmentExtractor))
                .build()
                .await
                .unwrap(),
        );
        let codec = FrameCodec::try_new(
            &test_key,
            crate::segment::SEGMENT_INFO,
            CompressionConfig::default(),
        )
        .unwrap();
        let fs = ZeroFS::new_with_slatedb(
            SlateDbHandle::ReadWrite(db),
            u64::MAX,
            None,
            false,
            object_store,
            codec,
        )
        .await
        .unwrap();
        if fs
            .lookup(&crate::fs::test_util::test_creds(), 0, b".nbd")
            .await
            .is_err()
        {
            fs.mkdir(
                &crate::fs::test_util::test_creds(),
                0,
                b".nbd",
                &crate::fs::types::SetAttributes::default(),
            )
            .await
            .unwrap();
        }
        fs
    }

    fn verified(workspace: &str, request: &str, root: &'static [u8]) -> VerifiedGenesisInput {
        let root_bytes = Bytes::from_static(root);
        VerifiedGenesisInput::for_test(
            GenesisCommand {
                operation: WorkspaceOperationKey::new(workspace, 101, request),
                request_digest: CanonicalRequestDigest::new(Sha256::digest(request).into()),
                actor: format!("tenants/t/actors/{workspace}"),
                actor_generation: 7,
                home_cell: "cells/c".into(),
                home_revision: 1,
                authority_epoch: 1,
                tenant: "tenants/t".into(),
                template: "templates/base@sha256:01".into(),
                root_policy: "policies/root@1".into(),
                source_create_actor_request_digest: ContentDigest::new([9; 32]),
                object_lineage: "lineage-a".into(),
                storage_shard_id: "test-shard".into(),
                storage_routing_revision: 1,
                virtual_size_bytes: 4096,
            },
            GenesisMaterializationPlan {
                export_name: format!("{workspace}.img").into_bytes(),
                root_digest: ContentDigest::new(Sha256::digest(&root_bytes).into()),
                root_bytes,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn materializes_sparse_export_record_and_reverse_graph_atomically() {
        let fs = new_fs().await;
        let input = verified("workspace-a", "request-a", b"root-a");
        let receipt = match fs
            .workspace_genesis
            .materialize(input.clone())
            .await
            .unwrap()
        {
            GenesisMaterializeResult::Materialized(receipt) => receipt,
            other => panic!("unexpected result: {other:?}"),
        };
        assert!(receipt.writer_epoch > 0);
        assert!(receipt.durable_seq > 0);
        let durable = fs
            .workspace_genesis
            .lookup_record_durable("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(durable, receipt.record);
        assert_eq!(
            fs.inode_store
                .get(durable.export.inode)
                .await
                .unwrap()
                .size(),
            4096
        );
        assert_eq!(
            fs.directory_store
                .get(durable.export.nbd_directory_inode, &durable.export.name)
                .await
                .unwrap(),
            durable.export.inode
        );
        let binding = reverse_binding(&durable);
        let (name_key, inode_key) = reverse_binding_keys(&binding);
        assert_eq!(
            crate::fs::export_authority::read_reverse_binding_current(&fs.db, &name_key)
                .await
                .unwrap(),
            Some(binding.clone())
        );
        assert_eq!(
            crate::fs::export_authority::read_reverse_binding_current(&fs.db, &inode_key)
                .await
                .unwrap(),
            Some(binding)
        );

        let terminal = VerifiedGenesisTerminal::for_test(
            input.command().operation.clone(),
            input.command().request_digest,
            (*receipt).clone(),
            Bytes::from_static(b"signed-receipt"),
        )
        .unwrap();
        assert!(matches!(
            fs.workspace_genesis
                .complete(&input, terminal)
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                state: WorkspaceOperationState::Succeeded(_),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn unknown_genesis_reply_converges_without_a_second_export() {
        let fs = new_fs().await;
        let input = verified("workspace-a", "request-a", b"root-a");
        fs.workspace_genesis
            .materialize(input.clone())
            .await
            .unwrap();
        fs.write_coordinator.dst_drop_next_workspace_durable_reply();
        assert_eq!(
            fs.workspace_genesis.materialize(input.clone()).await,
            Err(GenesisError::CommitOutcomeUnknown)
        );
        let durable = fs
            .workspace_genesis
            .lookup_record_durable("workspace-a")
            .await
            .unwrap()
            .unwrap();
        let replay = fs.workspace_genesis.materialize(input).await.unwrap();
        let GenesisMaterializeResult::Materialized(replay) = replay else {
            panic!("pending operation must replay materialization");
        };
        assert_eq!(replay.record, durable);
    }

    #[tokio::test]
    async fn unknown_reply_converges_after_cold_reopen() {
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let first = open_reopen_fs(object_store.clone()).await;
        let input = verified("workspace-a", "request-a", b"root-a");
        first
            .workspace_genesis
            .materialize(input.clone())
            .await
            .unwrap();
        first
            .write_coordinator
            .dst_drop_next_workspace_durable_reply();
        assert_eq!(
            first.workspace_genesis.materialize(input.clone()).await,
            Err(GenesisError::CommitOutcomeUnknown)
        );
        let committed = first
            .workspace_genesis
            .lookup_record_durable("workspace-a")
            .await
            .unwrap()
            .unwrap();
        first.db.close().await.unwrap();
        let reopened = open_reopen_fs(object_store).await;
        let replay = reopened.workspace_genesis.materialize(input).await.unwrap();
        let GenesisMaterializeResult::Materialized(replay) = replay else {
            panic!("pending operation must replay materialization after reopen");
        };
        assert_eq!(replay.record, committed);
    }

    #[tokio::test]
    async fn invalid_physical_precondition_leaves_no_genesis_domain_record() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let input = verified("workspace-a", "request-a", b"root-a");
        let GenesisMaterializeResult::Rejected(rejection) = fs
            .workspace_genesis
            .materialize(input.clone())
            .await
            .unwrap()
        else {
            panic!("missing .nbd is a typed physical rejection");
        };
        let failed = fs
            .workspace_genesis
            .complete_rejection(
                &input,
                VerifiedGenesisNegativeTerminal::for_test(
                    (*rejection).clone(),
                    Bytes::from_static(b"signed-physical-rejection"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(failed.state, WorkspaceOperationState::Failed(_)));
        assert_eq!(
            fs.workspace_genesis
                .lookup_record_durable("workspace-a")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn conditional_create_response_loss_converges_by_exact_get() {
        let fs = new_fs().await;
        let inner: Arc<dyn ObjectStore> = Arc::new(slatedb::object_store::memory::InMemory::new());
        let (fault, controls) = crate::fault_store::FaultStore::new(inner);
        controls.fail_puts_after_apply(1);
        let store = WorkspaceGenesisStore {
            db: fs.workspace_genesis.db.clone(),
            coordinator: fs.workspace_genesis.coordinator.clone(),
            operations: fs.workspace_genesis.operations.clone(),
            object_creator: Arc::new(DirectTestGenesisObjectCreator(fault)),
            local_storage_shard_id: "test-shard".into(),
        };
        assert!(matches!(
            store
                .materialize(verified("workspace-a", "request-a", b"root-a"))
                .await
                .unwrap(),
            GenesisMaterializeResult::Materialized(_)
        ));
        assert_eq!(controls.put_count(), 1);
        assert_eq!(controls.get_count(), 1);
    }

    #[tokio::test]
    async fn exact_claim_reply_loss_retains_unique_installer_and_dispatches_once() {
        let fs = new_fs().await;
        let inner: Arc<dyn ObjectStore> = Arc::new(slatedb::object_store::memory::InMemory::new());
        let (fault, controls) = crate::fault_store::FaultStore::new(inner);
        let store = WorkspaceGenesisStore {
            db: fs.workspace_genesis.db.clone(),
            coordinator: fs.workspace_genesis.coordinator.clone(),
            operations: fs.workspace_genesis.operations.clone(),
            object_creator: Arc::new(DirectTestGenesisObjectCreator(fault)),
            local_storage_shard_id: "test-shard".into(),
        };
        let input = verified("workspace-a", "request-a", b"root-a");
        store
            .operations
            .begin(&input.command().operation, input.command().request_digest)
            .await
            .unwrap();
        store.operations.dst_lose_next_commit_reply();
        assert!(matches!(
            store.materialize(input).await.unwrap(),
            GenesisMaterializeResult::Materialized(_)
        ));
        assert_eq!(controls.put_count(), 1);
        assert_eq!(controls.get_count(), 1);
    }

    #[tokio::test]
    async fn unavailable_exact_get_keeps_physical_genesis_absent() {
        let fs = new_fs().await;
        let inner: Arc<dyn ObjectStore> = Arc::new(slatedb::object_store::memory::InMemory::new());
        let (fault, controls) = crate::fault_store::FaultStore::new(inner);
        controls.fail_gets(1);
        let store = WorkspaceGenesisStore {
            db: fs.workspace_genesis.db.clone(),
            coordinator: fs.workspace_genesis.coordinator.clone(),
            operations: fs.workspace_genesis.operations.clone(),
            object_creator: Arc::new(DirectTestGenesisObjectCreator(fault)),
            local_storage_shard_id: "test-shard".into(),
        };
        assert_eq!(
            store
                .materialize(verified("workspace-a", "request-a", b"root-a"))
                .await,
            Err(GenesisError::ObjectOutcomeUnknown)
        );
        assert!(
            store
                .lookup_record_durable("workspace-a")
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store
                .materialize(verified("workspace-a", "request-a", b"root-a"))
                .await
                .unwrap(),
            GenesisMaterializeResult::Materialized(_)
        ));
        assert_eq!(controls.put_count(), 1);
        assert_eq!(controls.get_count(), 2);
    }

    #[tokio::test]
    async fn local_shard_mismatch_rejects_before_lookup_or_object_effect() {
        let fs = new_fs().await;
        let inner: Arc<dyn ObjectStore> = Arc::new(slatedb::object_store::memory::InMemory::new());
        let (fault, controls) = crate::fault_store::FaultStore::new(inner);
        let store = WorkspaceGenesisStore {
            db: fs.workspace_genesis.db.clone(),
            coordinator: fs.workspace_genesis.coordinator.clone(),
            operations: fs.workspace_genesis.operations.clone(),
            object_creator: Arc::new(DirectTestGenesisObjectCreator(fault)),
            local_storage_shard_id: "test-shard".into(),
        };
        let mut input = verified("workspace-a", "request-a", b"root-a");
        input.command.storage_shard_id = "other-shard".into();
        assert_eq!(
            store.materialize(input.clone()).await,
            Err(GenesisError::Invalid)
        );
        assert_eq!(controls.put_count(), 0);
        assert_eq!(controls.get_count(), 0);
        assert_eq!(
            store
                .operations
                .lookup(&input.command().operation, input.command().request_digest)
                .await
                .unwrap(),
            WorkspaceOperationLookup::Unknown
        );
    }

    #[tokio::test]
    async fn object_conflict_has_typed_failed_terminal_without_physical_effect() {
        let fs = new_fs().await;
        let inner = Arc::new(slatedb::object_store::memory::InMemory::new());
        let input = verified("workspace-a", "request-a", b"root-a");
        let path = Path::from(content_object_key(input.plan().root_digest));
        inner
            .put(&path, Bytes::from_static(b"wrong-root").into())
            .await
            .unwrap();
        let creator: Arc<dyn ObjectStore> = inner;
        let store = WorkspaceGenesisStore {
            db: fs.workspace_genesis.db.clone(),
            coordinator: fs.workspace_genesis.coordinator.clone(),
            operations: fs.workspace_genesis.operations.clone(),
            object_creator: Arc::new(DirectTestGenesisObjectCreator(creator)),
            local_storage_shard_id: "test-shard".into(),
        };
        let GenesisMaterializeResult::Rejected(rejection) =
            store.materialize(input.clone()).await.unwrap()
        else {
            panic!("wrong content at exact digest key must reject");
        };
        assert_eq!(rejection.reason, GenesisRejectionReason::ObjectConflict);
        let failed = store
            .complete_rejection(
                &input,
                VerifiedGenesisNegativeTerminal::for_test(
                    (*rejection).clone(),
                    Bytes::from_static(b"signed-object-conflict"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(failed.state, WorkspaceOperationState::Failed(_)));
        assert!(
            store
                .lookup_record_durable("workspace-a")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_workspace_genesis_has_one_domain_winner_and_typed_loser() {
        let fs = new_fs().await;
        let first = verified("workspace-a", "request-a", b"root-a");
        let second = verified("workspace-a", "request-b", b"root-b");
        let (a, b) = tokio::join!(
            fs.workspace_genesis.materialize(first.clone()),
            fs.workspace_genesis.materialize(second.clone())
        );
        let (winner_input, winner_receipt, loser_input, rejection) = match (a.unwrap(), b.unwrap())
        {
            (
                GenesisMaterializeResult::Materialized(receipt),
                GenesisMaterializeResult::Rejected(rejection),
            ) => (first, receipt, second, rejection),
            (
                GenesisMaterializeResult::Rejected(rejection),
                GenesisMaterializeResult::Materialized(receipt),
            ) => (second, receipt, first, rejection),
            other => panic!("expected one winner and one typed loser: {other:?}"),
        };
        fs.workspace_genesis
            .complete(
                &winner_input,
                VerifiedGenesisTerminal::for_test(
                    winner_input.command().operation.clone(),
                    winner_input.command().request_digest,
                    (*winner_receipt).clone(),
                    Bytes::from_static(b"signed-success"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let failed = fs
            .workspace_genesis
            .complete_rejection(
                &loser_input,
                VerifiedGenesisNegativeTerminal::for_test(
                    (*rejection).clone(),
                    Bytes::from_static(b"signed-conflict"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(failed.state, WorkspaceOperationState::Failed(_)));
    }

    #[tokio::test]
    async fn reserved_genesis_namespace_rejects_raw_transactions() {
        let fs = new_fs().await;
        let key = KeyCodec::new().workspace_genesis_key("workspace-a");
        let mut txn = fs.db.new_transaction().unwrap();
        txn.put_bytes(&key, Bytes::from_static(b"forged"));
        assert_eq!(
            fs.write_coordinator.commit(txn).await,
            Err(crate::fs::errors::FsError::OperationNotPermitted)
        );
        assert!(fs.db.get_bytes(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn genesis_forward_row_rebuilds_raw_write_deny_index_after_reopen() {
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let first = open_reopen_fs(object_store.clone()).await;
        let GenesisMaterializeResult::Materialized(receipt) = first
            .workspace_genesis
            .materialize(verified("workspace-a", "request-a", b"root-a"))
            .await
            .unwrap()
        else {
            panic!("expected materialized genesis");
        };
        let binding = reverse_binding(&receipt.record);
        let (name_key, inode_key) = reverse_binding_keys(&binding);
        first
            .db
            .inject_reserved_authority_delete_for_test(name_key)
            .await
            .unwrap();
        first
            .db
            .inject_reserved_authority_delete_for_test(inode_key)
            .await
            .unwrap();
        first.db.flush().await.unwrap();
        first.db.close().await.unwrap();

        let reopened = open_reopen_fs(object_store).await;
        let mut inode = reopened
            .inode_store
            .get(receipt.record.export.inode)
            .await
            .unwrap();
        let crate::fs::inode::Inode::File(file) = &mut inode else {
            panic!("genesis export must be a file");
        };
        file.mode = 0o640;
        let mut txn = reopened.db.new_transaction().unwrap();
        reopened
            .inode_store
            .save(&mut txn, receipt.record.export.inode, &inode)
            .unwrap();
        assert_eq!(
            reopened.write_coordinator.commit(txn).await,
            Err(crate::fs::errors::FsError::OperationNotPermitted)
        );
    }

    async fn reopened_with_genesis_row() -> ZeroFS {
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let first = open_reopen_fs(object_store.clone()).await;
        first
            .workspace_genesis
            .materialize(verified("workspace-a", "request-a", b"root-a"))
            .await
            .unwrap();
        first.db.close().await.unwrap();
        open_reopen_fs(object_store).await
    }

    #[tokio::test]
    async fn genesis_deny_index_setup_scan_failure_is_sticky() {
        let fs = reopened_with_genesis_row().await;
        fs.db.dst_fail_scan_setup_on(3);
        assert!(matches!(
            fs.create(
                &crate::fs::test_util::test_creds(),
                0,
                b"unrelated",
                &crate::fs::types::SetAttributes::default(),
            )
            .await,
            Err(crate::fs::errors::FsError::InvalidData)
        ));
        assert!(matches!(
            fs.create(
                &crate::fs::test_util::test_creds(),
                0,
                b"still-poisoned",
                &crate::fs::types::SetAttributes::default(),
            )
            .await,
            Err(crate::fs::errors::FsError::InvalidData)
        ));
    }

    #[tokio::test]
    async fn genesis_deny_index_midstream_scan_failure_is_sticky() {
        let fs = reopened_with_genesis_row().await;
        fs.db.dst_fail_scan_midstream_on(3);
        assert!(matches!(
            fs.create(
                &crate::fs::test_util::test_creds(),
                0,
                b"unrelated",
                &crate::fs::types::SetAttributes::default(),
            )
            .await,
            Err(crate::fs::errors::FsError::InvalidData)
        ));
        assert!(matches!(
            fs.create(
                &crate::fs::test_util::test_creds(),
                0,
                b"still-poisoned",
                &crate::fs::types::SetAttributes::default(),
            )
            .await,
            Err(crate::fs::errors::FsError::InvalidData)
        ));
    }

    #[tokio::test]
    async fn success_terminal_requires_exact_materialized_receipt() {
        let fs = new_fs().await;
        let input = verified("workspace-a", "request-a", b"root-a");
        fs.workspace_operations
            .begin(&input.command().operation, input.command().request_digest)
            .await
            .unwrap();
        let forged = GenesisDurabilityReceipt {
            record: GenesisDomainRecord {
                workspace_id: "workspace-a".into(),
                operation_kind: 101,
                request_id: "request-a".into(),
                actor: "tenants/t/actors/workspace-a".into(),
                actor_generation: 7,
                home_cell: "cells/c".into(),
                home_revision: 1,
                authority_epoch: 1,
                tenant: "tenants/t".into(),
                template: "templates/base@sha256:01".into(),
                root_policy: "policies/root@1".into(),
                source_create_actor_request_digest: ContentDigest::new([9; 32]),
                object_lineage: "lineage-a".into(),
                storage_shard_id: "test-shard".into(),
                storage_routing_revision: 1,
                effect_claim: effect_claim(
                    input.plan().root_digest,
                    &content_object_key(input.plan().root_digest),
                    "00000000-0000-4000-8000-000000000002",
                ),
                request_digest: input.command().request_digest,
                root_digest: input.plan().root_digest,
                root_object_key: content_object_key(input.plan().root_digest),
                export: ExportIdentity {
                    nbd_directory_inode: 1,
                    name: b"workspace-a.img".to_vec(),
                    inode: 2,
                    advertised_size: 4096,
                },
            },
            writer_epoch: 1,
            durable_seq: 1,
        };
        assert_eq!(
            fs.workspace_genesis
                .complete(
                    &input,
                    VerifiedGenesisTerminal::for_test(
                        input.command().operation.clone(),
                        input.command().request_digest,
                        forged,
                        Bytes::from_static(b"forged-success"),
                    )
                    .unwrap(),
                )
                .await,
            Err(GenesisError::Conflict)
        );
    }

    #[tokio::test]
    async fn claimed_effect_rejects_generic_terminal_completion() {
        let fs = new_fs().await;
        let input = verified("workspace-a", "request-a", b"root-a");
        fs.workspace_operations
            .begin(&input.command().operation, input.command().request_digest)
            .await
            .unwrap();
        fs.workspace_operations
            .claim_effect_dispatch(
                &input.command().operation,
                input.command().request_digest,
                effect_claim(
                    input.plan().root_digest,
                    &content_object_key(input.plan().root_digest),
                    "installer-test",
                ),
            )
            .await
            .unwrap();
        assert_eq!(
            fs.workspace_operations
                .complete(
                    &input.command().operation,
                    input.command().request_digest,
                    WorkspaceTerminalOutcome::Failed(Bytes::from_static(b"negative")),
                )
                .await,
            Err(WorkspaceOperationError::TerminalImmutable)
        );
    }

    #[tokio::test]
    async fn activation_gate_requires_exact_genesis_binding() {
        let fs = new_fs().await;
        let input = verified("workspace-a", "request-a", b"root-a");
        let GenesisMaterializeResult::Materialized(receipt) = fs
            .workspace_genesis
            .materialize(input.clone())
            .await
            .unwrap()
        else {
            panic!("expected materialized genesis");
        };
        fs.export_authority
            .install_process_guard(ShardProcessGuard::for_test())
            .unwrap();
        fs.export_authority
            .enable_standalone_profile()
            .await
            .unwrap();
        fs.write_coordinator.dst_enable_workspace_genesis_gate();
        let authority = AuthorityVersion {
            actor: receipt.record.actor.clone(),
            actor_generation: receipt.record.actor_generation,
            home_cell: "cells/c".into(),
            home_revision: 1,
            authority_epoch: 1,
            placement_epoch: 1,
            assignment_revision: 1,
        };
        let pending = fs
            .export_authority
            .activate(ActivateExport {
                workspace_id: receipt.record.workspace_id.clone(),
                export: receipt.record.export.clone(),
                authority: authority.clone(),
                session: ExportSessionState {
                    session_id: "session-a".into(),
                    capability_id: "capability-a".into(),
                    expires_at_unix_millis: u64::MAX - 1,
                    node_incarnation_id: "node-a".into(),
                    runtime_id: "runtime-a".into(),
                    server_boot_id: "replaced".into(),
                    committed_through_sequence: 0,
                },
            })
            .await;
        assert_eq!(
            pending,
            Err(crate::fs::export_authority::ExportAuthorityError::Conflict)
        );
        fs.workspace_genesis
            .complete(
                &input,
                VerifiedGenesisTerminal::for_test(
                    input.command().operation.clone(),
                    input.command().request_digest,
                    (*receipt).clone(),
                    Bytes::from_static(b"signed-receipt"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let active = fs
            .export_authority
            .activate(ActivateExport {
                workspace_id: receipt.record.workspace_id.clone(),
                export: receipt.record.export.clone(),
                authority: authority.clone(),
                session: ExportSessionState {
                    session_id: "session-a".into(),
                    capability_id: "capability-a".into(),
                    expires_at_unix_millis: u64::MAX - 1,
                    node_incarnation_id: "node-a".into(),
                    runtime_id: "runtime-a".into(),
                    server_boot_id: "replaced".into(),
                    committed_through_sequence: 0,
                },
            })
            .await
            .unwrap();
        assert_eq!(active.export, receipt.record.export);

        let missing = fs
            .export_authority
            .activate(ActivateExport {
                workspace_id: "workspace-missing".into(),
                export: receipt.record.export,
                authority,
                session: ExportSessionState {
                    session_id: "session-b".into(),
                    capability_id: "capability-b".into(),
                    expires_at_unix_millis: u64::MAX - 1,
                    node_incarnation_id: "node-a".into(),
                    runtime_id: "runtime-b".into(),
                    server_boot_id: "replaced".into(),
                    committed_through_sequence: 0,
                },
            })
            .await;
        assert_eq!(
            missing,
            Err(crate::fs::export_authority::ExportAuthorityError::NotFound)
        );
    }

    #[test]
    fn explicit_codec_rejects_cross_key_copy_and_trailing_bytes() {
        let mut record = GenesisDomainRecord {
            workspace_id: "workspace-a".into(),
            operation_kind: 101,
            request_id: "request-a".into(),
            actor: "actor-a".into(),
            actor_generation: 1,
            home_cell: "cells/c".into(),
            home_revision: 1,
            authority_epoch: 1,
            tenant: "tenants/t".into(),
            template: "templates/base@sha256:01".into(),
            root_policy: "policies/root@1".into(),
            source_create_actor_request_digest: ContentDigest::new([3; 32]),
            object_lineage: "lineage-a".into(),
            storage_shard_id: "test-shard".into(),
            storage_routing_revision: 1,
            effect_claim: effect_claim(
                ContentDigest::new([2; 32]),
                &content_object_key(ContentDigest::new([2; 32])),
                "00000000-0000-4000-8000-000000000003",
            ),
            request_digest: CanonicalRequestDigest::new([1; 32]),
            root_digest: ContentDigest::new([2; 32]),
            root_object_key: content_object_key(ContentDigest::new([2; 32])),
            export: ExportIdentity {
                nbd_directory_inode: 1,
                name: b"disk-a".to_vec(),
                inode: 2,
                advertised_size: 4096,
            },
        };
        let key = KeyCodec::new().workspace_genesis_key("workspace-a");
        let encoded = encode_record(&key, &record).unwrap();
        assert_eq!(decode_record(&key, &encoded).unwrap(), record);
        let other = KeyCodec::new().workspace_genesis_key("workspace-b");
        assert_eq!(decode_record(&other, &encoded), Err(GenesisError::Corrupt));
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(decode_record(&key, &trailing), Err(GenesisError::Corrupt));
        record.root_object_key.push('x');
        assert_eq!(encode_record(&key, &record), Err(GenesisError::Invalid));
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn failpoint_after_durable_commit_requires_exact_readback() {
        crate::test_helpers::isolated_failpoint::run(
            "fs::workspace_genesis::tests::failpoint_after_durable_commit_requires_exact_readback",
            crate::test_helpers::isolated_failpoint::Runtime::CurrentThread,
            || async {
                let fs = new_fs().await;
                let input = verified("workspace-a", "request-a", b"root-a");
                fs.workspace_operations
                    .begin(&input.command().operation, input.command().request_digest)
                    .await
                    .unwrap();
                let armed = crate::test_helpers::isolated_failpoint::arm(
                    crate::failpoints::WORKSPACE_GENESIS_AFTER_COMMIT_BEFORE_REPLY,
                    "return",
                );
                assert_eq!(
                    fs.workspace_genesis.materialize(input.clone()).await,
                    Err(GenesisError::CommitOutcomeUnknown)
                );
                drop(armed);
                let committed = fs
                    .workspace_genesis
                    .lookup_record_durable("workspace-a")
                    .await
                    .unwrap()
                    .unwrap();
                let GenesisMaterializeResult::Materialized(replay) =
                    fs.workspace_genesis.materialize(input).await.unwrap()
                else {
                    panic!("pending operation must replay durable genesis");
                };
                assert_eq!(replay.record, committed);
            },
        );
    }
}
