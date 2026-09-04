//! Non-default, protocol-neutral per-export durability barrier mechanics.
//!
//! The barrier reuses the Workspace operation ledger for PENDING, the unique
//! effect-dispatch claim, and the eventual signed terminal bytes. This module
//! stores only the current Workspace head and immutable mechanical barrier cut.
//! It neither parses protobuf nor verifies/signs COSE.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "feature-staged until the normative verifier and signer are wired"
    )
)]

use crate::db::Db;
use crate::fs::export_authority::{AuthorityVersion, MutationFenceToken};
use crate::fs::key_codec::KeyCodec;
use crate::fs::workspace_genesis::GenesisDomainRecord;
use crate::fs::workspace_operation::{
    CanonicalRequestDigest, EffectDispatchClaim, WorkspaceOperationError, WorkspaceOperationKey,
    WorkspaceOperationLookup, WorkspaceOperationRecord, WorkspaceOperationState,
    WorkspaceTerminalOutcome,
};
use crate::fs::write_coordinator::WriteCoordinator;
use bincode::Options;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[cfg(test)]
use std::{future::Future, pin::Pin};

pub(crate) const CREATE_BARRIER_KIND: i32 = 4;
const RECORD_VERSION: u8 = 1;
const HEAD_MAGIC: &[u8; 4] = b"RWBH";
const BARRIER_MAGIC: &[u8; 4] = b"RWBR";
const MAX_RECORD_BYTES: usize = 128 * 1024;
const MAX_ID_BYTES: usize = 1024;
const ENVELOPE_DOMAIN: &[u8] = b"rhizome.workspace-barrier-envelope.v1\0";
const COMMAND_DOMAIN: &[u8] = b"rhizome.workspace-barrier-command.v1\0";
const CLAIM_DOMAIN: &[u8] = b"rhizome.workspace-barrier-dispatch.v1\0";
const INITIAL_HEAD_DOMAIN: &[u8] = b"rhizome.workspace-head.initial.v1\0";
const NEXT_HEAD_DOMAIN: &[u8] = b"rhizome.workspace-head.barrier.v1\0";
const HEAD_DIGEST_DOMAIN: &[u8] = b"rhizome.workspace-head.digest.v1\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"rhizome.workspace-barrier-receipt.v1\0";

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_RECORD_BYTES as u64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HeadDigest(pub(crate) [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WorkspaceHead {
    pub workspace_id: String,
    pub base_root_digest: [u8; 32],
    pub base_root_position: u64,
    pub committed_tail_position: u64,
    pub tail_chain_digest: [u8; 32],
    pub workspace_version: u64,
    pub object_lineage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WorkspaceHeadRecord {
    pub head: WorkspaceHead,
    pub last_barrier_request_id: Option<String>,
    pub last_barrier_request_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BarrierCommand {
    pub operation: WorkspaceOperationKey,
    pub request_digest: CanonicalRequestDigest,
    pub token: MutationFenceToken,
    pub expected_head_digest: HeadDigest,
    pub storage_shard_id: String,
    pub storage_routing_revision: u64,
}

/// Type-state proof that a future external verifier accepted the canonical
/// barrier command. Production construction intentionally does not exist.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedBarrierInput {
    command: BarrierCommand,
}

impl VerifiedBarrierInput {
    #[cfg(any(test, dst))]
    pub(crate) fn for_test(command: BarrierCommand) -> Result<Self, BarrierError> {
        validate_command(&command)?;
        Ok(Self { command })
    }

    fn command(&self) -> &BarrierCommand {
        &self.command
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BarrierDurabilityReceipt {
    pub workspace_id: String,
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub effect_claim: Bytes,
    pub token: MutationFenceToken,
    pub expected_head_digest: HeadDigest,
    pub head: WorkspaceHead,
    pub barrier_id: String,
    pub included_write_sequence: u64,
    pub zerofs_writer_epoch: u64,
    pub zerofs_manifest_id: u64,
    pub zerofs_durable_sequence: u64,
    pub storage_shard_id: String,
    pub storage_routing_revision: u64,
    pub committed_at_unix_seconds: u64,
    pub committed_at_nanos: u32,
    pub receipt_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BarrierMaterializeResult {
    Materialized(Box<BarrierDurabilityReceipt>),
    AlreadyTerminal(WorkspaceOperationRecord),
}

pub(crate) struct VerifiedBarrierTerminal {
    receipt: BarrierDurabilityReceipt,
    bytes: Bytes,
}

impl VerifiedBarrierTerminal {
    #[cfg(any(test, dst))]
    pub(crate) fn for_test(
        receipt: BarrierDurabilityReceipt,
        bytes: Bytes,
    ) -> Result<Self, BarrierError> {
        if bytes.is_empty() {
            return Err(BarrierError::Invalid);
        }
        validate_receipt(&receipt)?;
        Ok(Self { receipt, bytes })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkspaceBarrierRequest {
    pub command: BarrierCommand,
    pub effect_claim: Bytes,
    pub barrier_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BarrierError {
    #[error("invalid Workspace barrier input")]
    Invalid,
    #[error("Workspace barrier request conflicts with durable state")]
    Conflict,
    #[error("Workspace barrier graph is corrupt")]
    Corrupt,
    #[error("Workspace barrier outcome is unknown; use exact durable readback")]
    CommitOutcomeUnknown,
    #[error("Workspace barrier storage failure")]
    Storage,
}

impl From<WorkspaceOperationError> for BarrierError {
    fn from(value: WorkspaceOperationError) -> Self {
        match value {
            WorkspaceOperationError::InvalidIdentity(_) => Self::Invalid,
            WorkspaceOperationError::RequestConflict
            | WorkspaceOperationError::TerminalImmutable => Self::Conflict,
            WorkspaceOperationError::CorruptRecord(_) => Self::Corrupt,
            WorkspaceOperationError::CommitOutcomeUnknown => Self::CommitOutcomeUnknown,
            WorkspaceOperationError::Storage(_) => Self::Storage,
        }
    }
}

#[derive(Clone)]
pub(crate) struct WorkspaceBarrierStore {
    db: Arc<Db>,
    coordinator: WriteCoordinator,
    operations: crate::fs::workspace_operation::WorkspaceOperationLedger,
    admission_locks: Arc<crate::fs::lock_manager::KeyedLockManager<String>>,
    #[cfg(test)]
    after_claim_hook: Arc<std::sync::Mutex<Option<BarrierAfterClaimHook>>>,
}

#[cfg(test)]
type BarrierAfterClaimHook = Arc<
    dyn Fn(&Bytes, &str) -> Pin<Box<dyn Future<Output = Result<(), BarrierError>> + Send>>
        + Send
        + Sync,
>;

impl WorkspaceBarrierStore {
    pub(crate) fn new(
        db: Arc<Db>,
        coordinator: WriteCoordinator,
        operations: crate::fs::workspace_operation::WorkspaceOperationLedger,
        admission_locks: Arc<crate::fs::lock_manager::KeyedLockManager<String>>,
    ) -> Self {
        Self {
            db,
            coordinator,
            operations,
            admission_locks,
            #[cfg(test)]
            after_claim_hook: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub(crate) fn dst_set_after_claim_hook(&self, hook: BarrierAfterClaimHook) {
        let mut installed = self.after_claim_hook.lock().unwrap();
        assert!(installed.replace(hook).is_none());
    }

    pub(crate) async fn materialize(
        &self,
        verified: VerifiedBarrierInput,
    ) -> Result<BarrierMaterializeResult, BarrierError> {
        let command = verified.command();
        validate_command(command)?;
        if let Some(receipt) = self.lookup_materialized(command).await? {
            return Ok(BarrierMaterializeResult::Materialized(Box::new(receipt)));
        }
        let operation = self
            .operations
            .begin(&command.operation, command.request_digest)
            .await?;
        if operation.state.is_terminal() {
            return Ok(BarrierMaterializeResult::AlreadyTerminal(operation));
        }

        let barrier_id = uuid::Uuid::new_v4().to_string();
        let installer_id = uuid::Uuid::new_v4().to_string();
        let candidate = effect_claim(command, &barrier_id, &installer_id);
        let dispatch = match operation.state {
            WorkspaceOperationState::Pending => match self
                .operations
                .claim_effect_dispatch(
                    &command.operation,
                    command.request_digest,
                    candidate.clone(),
                )
                .await
            {
                Ok(EffectDispatchClaim::Installed(_)) => true,
                Ok(EffectDispatchClaim::Existing(record)) => {
                    if record.state.is_terminal() {
                        return Ok(BarrierMaterializeResult::AlreadyTerminal(record));
                    }
                    false
                }
                Err(WorkspaceOperationError::CommitOutcomeUnknown) => matches!(
                    self.operations
                        .lookup(&command.operation, command.request_digest)
                        .await?,
                    WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                        state: WorkspaceOperationState::EffectDispatched(ref existing),
                        ..
                    }) if existing == &candidate
                ),
                Err(WorkspaceOperationError::RequestConflict) => false,
                Err(error) => return Err(error.into()),
            },
            WorkspaceOperationState::EffectDispatched(_) => false,
            _ => return Ok(BarrierMaterializeResult::AlreadyTerminal(operation)),
        };
        if !dispatch {
            return self
                .lookup_materialized(command)
                .await?
                .map(|receipt| BarrierMaterializeResult::Materialized(Box::new(receipt)))
                .ok_or(BarrierError::CommitOutcomeUnknown);
        }
        #[cfg(test)]
        let after_claim = self.after_claim_hook.lock().unwrap().take();
        #[cfg(test)]
        if let Some(hook) = after_claim {
            hook(&candidate, &barrier_id).await?;
        }

        let request = WorkspaceBarrierRequest {
            command: command.clone(),
            effect_claim: candidate,
            barrier_id,
        };
        let guard = self
            .admission_locks
            .acquire(command.operation.workspace_id.clone())
            .await;
        match self
            .coordinator
            .materialize_workspace_barrier(request, guard)
            .await
        {
            Ok(receipt) => Ok(BarrierMaterializeResult::Materialized(Box::new(receipt))),
            Err(BarrierError::CommitOutcomeUnknown) => self
                .lookup_materialized(command)
                .await?
                .map(|receipt| BarrierMaterializeResult::Materialized(Box::new(receipt)))
                .ok_or(BarrierError::CommitOutcomeUnknown),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn complete(
        &self,
        verified: &VerifiedBarrierInput,
        terminal: VerifiedBarrierTerminal,
    ) -> Result<WorkspaceOperationLookup, BarrierError> {
        let command = verified.command();
        ensure_receipt_matches_command(&terminal.receipt, command)?;
        let durable = self
            .lookup_materialized(command)
            .await?
            .ok_or(BarrierError::CommitOutcomeUnknown)?;
        if durable != terminal.receipt {
            return Err(BarrierError::Conflict);
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

    pub(crate) async fn lookup_materialized(
        &self,
        command: &BarrierCommand,
    ) -> Result<Option<BarrierDurabilityReceipt>, BarrierError> {
        validate_command(command)?;
        let key = KeyCodec::new().workspace_barrier_record_key(
            &command.operation.workspace_id,
            &command.operation.request_id,
        );
        let Some(bytes) = self
            .db
            .get_bytes_durable(&key)
            .await
            .map_err(|_| BarrierError::Storage)?
        else {
            let genesis = read_durable_genesis(&self.db, &command.operation.workspace_id).await?;
            read_closed_head_graph(&self.db, &genesis, true).await?;
            return match self
                .operations
                .lookup(&command.operation, command.request_digest)
                .await?
            {
                WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                    state: WorkspaceOperationState::Succeeded(_),
                    ..
                }) => Err(BarrierError::Corrupt),
                _ => Ok(None),
            };
        };
        let receipt = decode_barrier_record(&key, &bytes)?;
        ensure_receipt_matches_command(&receipt, command)?;
        let genesis = read_durable_genesis(&self.db, &command.operation.workspace_id).await?;
        let current = read_closed_head_graph(&self.db, &genesis, true).await?;
        validate_receipt_in_head_graph(&self.db, &receipt, &current).await?;
        Ok(Some(receipt))
    }
}

async fn read_durable_genesis(
    db: &Db,
    workspace_id: &str,
) -> Result<GenesisDomainRecord, BarrierError> {
    let key = KeyCodec::new().workspace_genesis_key(workspace_id);
    let bytes = db
        .get_bytes_durable(&key)
        .await
        .map_err(|_| BarrierError::Storage)?
        .ok_or(BarrierError::Corrupt)?;
    crate::fs::workspace_genesis::decode_record(&key, &bytes).map_err(|_| BarrierError::Corrupt)
}

pub(crate) fn validate_command(command: &BarrierCommand) -> Result<(), BarrierError> {
    validate_id(&command.operation.workspace_id)?;
    validate_id(&command.operation.request_id)?;
    validate_id(&command.storage_shard_id)?;
    validate_token(&command.token)?;
    if command.operation.kind != CREATE_BARRIER_KIND
        || command.operation.workspace_id != command.token.workspace_id
        || command.storage_routing_revision == 0
        || command.expected_head_digest.0 == [0; 32]
    {
        return Err(BarrierError::Invalid);
    }
    Ok(())
}

fn validate_token(token: &MutationFenceToken) -> Result<(), BarrierError> {
    validate_id(&token.workspace_id)?;
    validate_id(&token.authority.actor)?;
    validate_id(&token.authority.home_cell)?;
    validate_id(&token.session_id)?;
    validate_id(&token.capability_id)?;
    validate_id(&token.node_incarnation_id)?;
    validate_id(&token.runtime_id)?;
    validate_id(&token.server_boot_id)?;
    if token.authority.actor_generation == 0
        || token.authority.home_revision == 0
        || token.authority.authority_epoch == 0
        || token.authority.placement_epoch == 0
        || token.authority.assignment_revision == 0
        || token.expires_at_unix_millis == 0
        || token.export.nbd_directory_inode == 0
        || token.export.inode == 0
        || token.export.name.is_empty()
        || token.export.advertised_size == 0
    {
        return Err(BarrierError::Invalid);
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), BarrierError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.as_bytes().contains(&0) {
        Err(BarrierError::Invalid)
    } else {
        Ok(())
    }
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

pub(crate) fn command_digest(command: &BarrierCommand) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(COMMAND_DOMAIN);
    field(&mut hash, command.operation.workspace_id.as_bytes());
    field(&mut hash, command.operation.request_id.as_bytes());
    hash.update(command.operation.kind.to_be_bytes());
    hash.update(command.request_digest.as_bytes());
    encode_token_hash(&mut hash, &command.token);
    hash.update(command.expected_head_digest.0);
    field(&mut hash, command.storage_shard_id.as_bytes());
    hash.update(command.storage_routing_revision.to_be_bytes());
    hash.finalize().into()
}

fn encode_token_hash(hash: &mut Sha256, token: &MutationFenceToken) {
    field(hash, token.workspace_id.as_bytes());
    field(hash, &token.export.name);
    hash.update(token.export.nbd_directory_inode.to_be_bytes());
    hash.update(token.export.inode.to_be_bytes());
    hash.update(token.export.advertised_size.to_be_bytes());
    encode_authority_hash(hash, &token.authority);
    field(hash, token.session_id.as_bytes());
    field(hash, token.capability_id.as_bytes());
    hash.update(token.expires_at_unix_millis.to_be_bytes());
    field(hash, token.node_incarnation_id.as_bytes());
    field(hash, token.runtime_id.as_bytes());
    field(hash, token.server_boot_id.as_bytes());
}

fn encode_authority_hash(hash: &mut Sha256, authority: &AuthorityVersion) {
    field(hash, authority.actor.as_bytes());
    hash.update(authority.actor_generation.to_be_bytes());
    field(hash, authority.home_cell.as_bytes());
    hash.update(authority.home_revision.to_be_bytes());
    hash.update(authority.authority_epoch.to_be_bytes());
    hash.update(authority.placement_epoch.to_be_bytes());
    hash.update(authority.assignment_revision.to_be_bytes());
}

fn effect_claim(command: &BarrierCommand, barrier_id: &str, installer_id: &str) -> Bytes {
    let mut bytes = Vec::with_capacity(CLAIM_DOMAIN.len() + 32 + 16 + 16);
    bytes.extend_from_slice(CLAIM_DOMAIN);
    bytes.extend_from_slice(&command_digest(command));
    field_bytes(&mut bytes, barrier_id.as_bytes());
    field_bytes(&mut bytes, installer_id.as_bytes());
    Bytes::from(bytes)
}

pub(crate) fn claim_matches(claim: &[u8], command: &BarrierCommand, barrier_id: &str) -> bool {
    let Some(mut rest) = claim.strip_prefix(CLAIM_DOMAIN) else {
        return false;
    };
    let Some(digest) = rest.get(..32) else {
        return false;
    };
    if digest != command_digest(command) {
        return false;
    }
    rest = &rest[32..];
    let Some((encoded_barrier, tail)) = take_claim_field(rest) else {
        return false;
    };
    let Some((installer, tail)) = take_claim_field(tail) else {
        return false;
    };
    tail.is_empty()
        && encoded_barrier == barrier_id.as_bytes()
        && uuid::Uuid::parse_str(barrier_id)
            .ok()
            .filter(|id| id.get_version_num() == 4 && id.to_string() == barrier_id)
            .is_some()
        && std::str::from_utf8(installer)
            .ok()
            .and_then(|value| uuid::Uuid::parse_str(value).ok().map(|id| (value, id)))
            .is_some_and(|(value, id)| id.get_version_num() == 4 && id.to_string() == value)
}

fn take_claim_field(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u64::from_be_bytes(input.get(..8)?.try_into().ok()?);
    let length = usize::try_from(length).ok()?;
    let end = 8usize.checked_add(length)?;
    Some((input.get(8..end)?, input.get(end..)?))
}

fn field_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn initial_head(genesis: &GenesisDomainRecord) -> WorkspaceHeadRecord {
    let mut hash = Sha256::new();
    hash.update(INITIAL_HEAD_DOMAIN);
    field(&mut hash, genesis.workspace_id.as_bytes());
    field(&mut hash, genesis.object_lineage.as_bytes());
    hash.update(genesis.root_digest.as_bytes());
    WorkspaceHeadRecord {
        head: WorkspaceHead {
            workspace_id: genesis.workspace_id.clone(),
            base_root_digest: *genesis.root_digest.as_bytes(),
            base_root_position: 0,
            committed_tail_position: 0,
            tail_chain_digest: hash.finalize().into(),
            workspace_version: 1,
            object_lineage: genesis.object_lineage.clone(),
        },
        last_barrier_request_id: None,
        last_barrier_request_digest: None,
    }
}

pub(crate) async fn read_closed_head_graph(
    db: &Db,
    genesis: &GenesisDomainRecord,
    allow_latest_effect_dispatched: bool,
) -> Result<WorkspaceHeadRecord, BarrierError> {
    let codec = KeyCodec::new();
    let current_key = codec.workspace_head_key(&genesis.workspace_id);
    let current_bytes = db
        .get_bytes_durable(&current_key)
        .await
        .map_err(|_| BarrierError::Storage)?
        .ok_or(BarrierError::Corrupt)?;
    let current = decode_head_record(&current_key, &current_bytes)?;
    let mut cursor = current.clone();
    loop {
        let version_key =
            codec.workspace_head_version_key(&genesis.workspace_id, cursor.head.workspace_version);
        let version_bytes = db
            .get_bytes_durable(&version_key)
            .await
            .map_err(|_| BarrierError::Storage)?
            .ok_or(BarrierError::Corrupt)?;
        if decode_head_record(&version_key, &version_bytes)? != cursor {
            return Err(BarrierError::Corrupt);
        }
        if cursor.head.workspace_version == 1 {
            if cursor != initial_head(genesis) {
                return Err(BarrierError::Corrupt);
            }
            break;
        }
        let (Some(request_id), Some(request_digest)) = (
            cursor.last_barrier_request_id.as_ref(),
            cursor.last_barrier_request_digest,
        ) else {
            return Err(BarrierError::Corrupt);
        };
        let receipt_key = codec.workspace_barrier_record_key(&genesis.workspace_id, request_id);
        let receipt_bytes = db
            .get_bytes_durable(&receipt_key)
            .await
            .map_err(|_| BarrierError::Storage)?
            .ok_or(BarrierError::Corrupt)?;
        let receipt = decode_barrier_record(&receipt_key, &receipt_bytes)?;
        if receipt.head != cursor.head
            || receipt.request_id != *request_id
            || receipt.request_digest != request_digest
        {
            return Err(BarrierError::Corrupt);
        }
        let operation = WorkspaceOperationKey::new(
            genesis.workspace_id.clone(),
            CREATE_BARRIER_KIND,
            request_id.clone(),
        );
        let outcome = crate::fs::workspace_operation::read_operation_durable(
            db,
            &operation,
            CanonicalRequestDigest::new(request_digest),
        )
        .await?;
        let is_latest = cursor.head.workspace_version == current.head.workspace_version;
        match outcome {
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                state: WorkspaceOperationState::Succeeded(_),
                ..
            }) => {}
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                state: WorkspaceOperationState::EffectDispatched(claim),
                ..
            }) if is_latest && allow_latest_effect_dispatched && claim == receipt.effect_claim => {}
            _ => return Err(BarrierError::Corrupt),
        }
        let previous_version = cursor
            .head
            .workspace_version
            .checked_sub(1)
            .ok_or(BarrierError::Corrupt)?;
        let previous_key =
            codec.workspace_head_version_key(&genesis.workspace_id, previous_version);
        let previous_bytes = db
            .get_bytes_durable(&previous_key)
            .await
            .map_err(|_| BarrierError::Storage)?
            .ok_or(BarrierError::Corrupt)?;
        let previous = decode_head_record(&previous_key, &previous_bytes)?;
        if head_digest(&previous.head) != receipt.expected_head_digest {
            return Err(BarrierError::Corrupt);
        }
        let command = command_from_receipt(&receipt);
        validate_command(&command).map_err(|_| BarrierError::Corrupt)?;
        genesis_matches(genesis, &command).map_err(|_| BarrierError::Corrupt)?;
        let recomputed = next_head(
            &previous,
            &command,
            receipt.included_write_sequence,
            receipt.zerofs_writer_epoch,
            receipt.zerofs_manifest_id,
            receipt.zerofs_durable_sequence,
        )?;
        if recomputed != cursor {
            return Err(BarrierError::Corrupt);
        }
        cursor = previous;
    }
    Ok(current)
}

pub(crate) async fn validate_receipt_in_head_graph(
    db: &Db,
    receipt: &BarrierDurabilityReceipt,
    current: &WorkspaceHeadRecord,
) -> Result<(), BarrierError> {
    if receipt.head.workspace_version == 0
        || receipt.head.workspace_version > current.head.workspace_version
        || receipt.workspace_id != current.head.workspace_id
    {
        return Err(BarrierError::Corrupt);
    }
    let codec = KeyCodec::new();
    let version_key =
        codec.workspace_head_version_key(&receipt.workspace_id, receipt.head.workspace_version);
    let version_bytes = db
        .get_bytes_durable(&version_key)
        .await
        .map_err(|_| BarrierError::Storage)?
        .ok_or(BarrierError::Corrupt)?;
    let version = decode_head_record(&version_key, &version_bytes)?;
    if version.head != receipt.head
        || version.last_barrier_request_id.as_deref() != Some(receipt.request_id.as_str())
        || version.last_barrier_request_digest != Some(receipt.request_digest)
    {
        return Err(BarrierError::Corrupt);
    }
    Ok(())
}

pub(crate) fn next_head(
    current: &WorkspaceHeadRecord,
    command: &BarrierCommand,
    included_write_sequence: u64,
    writer_epoch: u64,
    manifest_id: u64,
    durable_sequence: u64,
) -> Result<WorkspaceHeadRecord, BarrierError> {
    if included_write_sequence < current.head.committed_tail_position {
        return Err(BarrierError::Corrupt);
    }
    let version = current
        .head
        .workspace_version
        .checked_add(1)
        .ok_or(BarrierError::Corrupt)?;
    let mut hash = Sha256::new();
    hash.update(NEXT_HEAD_DOMAIN);
    hash.update(head_digest(&current.head).0);
    hash.update(command_digest(command));
    hash.update(included_write_sequence.to_be_bytes());
    hash.update(writer_epoch.to_be_bytes());
    hash.update(manifest_id.to_be_bytes());
    hash.update(durable_sequence.to_be_bytes());
    Ok(WorkspaceHeadRecord {
        head: WorkspaceHead {
            workspace_id: current.head.workspace_id.clone(),
            base_root_digest: current.head.base_root_digest,
            base_root_position: current.head.base_root_position,
            committed_tail_position: included_write_sequence,
            tail_chain_digest: hash.finalize().into(),
            workspace_version: version,
            object_lineage: current.head.object_lineage.clone(),
        },
        last_barrier_request_id: Some(command.operation.request_id.clone()),
        last_barrier_request_digest: Some(*command.request_digest.as_bytes()),
    })
}

pub(crate) fn head_digest(head: &WorkspaceHead) -> HeadDigest {
    let mut hash = Sha256::new();
    hash.update(HEAD_DIGEST_DOMAIN);
    field(&mut hash, head.workspace_id.as_bytes());
    hash.update(head.base_root_digest);
    hash.update(head.base_root_position.to_be_bytes());
    hash.update(head.committed_tail_position.to_be_bytes());
    hash.update(head.tail_chain_digest);
    hash.update(head.workspace_version.to_be_bytes());
    field(&mut hash, head.object_lineage.as_bytes());
    HeadDigest(hash.finalize().into())
}

pub(crate) fn receipt_digest(receipt: &BarrierDurabilityReceipt) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(RECEIPT_DIGEST_DOMAIN);
    field(&mut hash, receipt.workspace_id.as_bytes());
    field(&mut hash, receipt.request_id.as_bytes());
    hash.update(receipt.request_digest);
    field(&mut hash, &receipt.effect_claim);
    encode_token_hash(&mut hash, &receipt.token);
    hash.update(receipt.expected_head_digest.0);
    hash.update(head_digest(&receipt.head).0);
    field(&mut hash, receipt.barrier_id.as_bytes());
    hash.update(receipt.included_write_sequence.to_be_bytes());
    hash.update(receipt.zerofs_writer_epoch.to_be_bytes());
    hash.update(receipt.zerofs_manifest_id.to_be_bytes());
    hash.update(receipt.zerofs_durable_sequence.to_be_bytes());
    field(&mut hash, receipt.storage_shard_id.as_bytes());
    hash.update(receipt.storage_routing_revision.to_be_bytes());
    hash.update(receipt.committed_at_unix_seconds.to_be_bytes());
    hash.update(receipt.committed_at_nanos.to_be_bytes());
    hash.finalize().into()
}

pub(crate) fn validate_receipt(receipt: &BarrierDurabilityReceipt) -> Result<(), BarrierError> {
    validate_id(&receipt.workspace_id)?;
    validate_id(&receipt.request_id)?;
    validate_id(&receipt.barrier_id)?;
    validate_id(&receipt.storage_shard_id)?;
    validate_token(&receipt.token)?;
    if uuid::Uuid::parse_str(&receipt.barrier_id)
        .ok()
        .filter(|id| id.get_version_num() == 4 && id.to_string() == receipt.barrier_id)
        .is_none()
        || receipt.workspace_id != receipt.token.workspace_id
        || receipt.effect_claim.is_empty()
        || !claim_matches(
            &receipt.effect_claim,
            &BarrierCommand {
                operation: WorkspaceOperationKey::new(
                    receipt.workspace_id.clone(),
                    CREATE_BARRIER_KIND,
                    receipt.request_id.clone(),
                ),
                request_digest: CanonicalRequestDigest::new(receipt.request_digest),
                token: receipt.token.clone(),
                expected_head_digest: receipt.expected_head_digest,
                storage_shard_id: receipt.storage_shard_id.clone(),
                storage_routing_revision: receipt.storage_routing_revision,
            },
            &receipt.barrier_id,
        )
        || receipt.head.workspace_id != receipt.workspace_id
        || receipt.head.committed_tail_position != receipt.included_write_sequence
        || receipt.head.workspace_version < 2
        || receipt.zerofs_writer_epoch == 0
        || receipt.zerofs_manifest_id == 0
        || receipt.zerofs_durable_sequence == 0
        || receipt.storage_routing_revision == 0
        || receipt.committed_at_nanos >= 1_000_000_000
        || receipt.receipt_digest != receipt_digest(receipt)
    {
        return Err(BarrierError::Corrupt);
    }
    Ok(())
}

pub(crate) fn ensure_receipt_matches_command(
    receipt: &BarrierDurabilityReceipt,
    command: &BarrierCommand,
) -> Result<(), BarrierError> {
    validate_receipt(receipt)?;
    if receipt.workspace_id != command.operation.workspace_id
        || receipt.request_id != command.operation.request_id
        || receipt.request_digest != *command.request_digest.as_bytes()
        || receipt.token != command.token
        || receipt.expected_head_digest != command.expected_head_digest
        || receipt.storage_shard_id != command.storage_shard_id
        || receipt.storage_routing_revision != command.storage_routing_revision
    {
        return Err(BarrierError::Conflict);
    }
    Ok(())
}

fn command_from_receipt(receipt: &BarrierDurabilityReceipt) -> BarrierCommand {
    BarrierCommand {
        operation: WorkspaceOperationKey::new(
            receipt.workspace_id.clone(),
            CREATE_BARRIER_KIND,
            receipt.request_id.clone(),
        ),
        request_digest: CanonicalRequestDigest::new(receipt.request_digest),
        token: receipt.token.clone(),
        expected_head_digest: receipt.expected_head_digest,
        storage_shard_id: receipt.storage_shard_id.clone(),
        storage_routing_revision: receipt.storage_routing_revision,
    }
}

pub(crate) fn encode_head_record(
    key: &[u8],
    record: &WorkspaceHeadRecord,
) -> Result<Bytes, BarrierError> {
    validate_head_record(record)?;
    encode_bound(
        HEAD_MAGIC,
        key,
        &codec()
            .serialize(record)
            .map_err(|_| BarrierError::Corrupt)?,
    )
}

pub(crate) fn decode_head_record(
    key: &[u8],
    bytes: &[u8],
) -> Result<WorkspaceHeadRecord, BarrierError> {
    let payload = decode_bound(HEAD_MAGIC, key, bytes)?;
    let record = codec()
        .deserialize(payload)
        .map_err(|_| BarrierError::Corrupt)?;
    validate_head_record(&record)?;
    Ok(record)
}

fn validate_head_record(record: &WorkspaceHeadRecord) -> Result<(), BarrierError> {
    validate_id(&record.head.workspace_id)?;
    validate_id(&record.head.object_lineage)?;
    if record.head.workspace_version == 0
        || record.head.base_root_digest == [0; 32]
        || record.head.tail_chain_digest == [0; 32]
        || record.head.committed_tail_position < record.head.base_root_position
        || record.last_barrier_request_id.is_some() != record.last_barrier_request_digest.is_some()
    {
        return Err(BarrierError::Corrupt);
    }
    if let Some(request_id) = &record.last_barrier_request_id {
        validate_id(request_id)?;
    }
    Ok(())
}

pub(crate) fn encode_barrier_record(
    key: &[u8],
    receipt: &BarrierDurabilityReceipt,
) -> Result<Bytes, BarrierError> {
    validate_receipt(receipt)?;
    encode_bound(
        BARRIER_MAGIC,
        key,
        &codec()
            .serialize(receipt)
            .map_err(|_| BarrierError::Corrupt)?,
    )
}

pub(crate) fn decode_barrier_record(
    key: &[u8],
    bytes: &[u8],
) -> Result<BarrierDurabilityReceipt, BarrierError> {
    let payload = decode_bound(BARRIER_MAGIC, key, bytes)?;
    let receipt = codec()
        .deserialize(payload)
        .map_err(|_| BarrierError::Corrupt)?;
    validate_receipt(&receipt)?;
    Ok(receipt)
}

fn encode_bound(magic: &[u8; 4], key: &[u8], payload: &[u8]) -> Result<Bytes, BarrierError> {
    let length = u32::try_from(payload.len()).map_err(|_| BarrierError::Invalid)?;
    let mut out = Vec::with_capacity(4 + 1 + 32 + 4 + payload.len() + 32);
    out.extend_from_slice(magic);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&Sha256::digest(key));
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    let checksum: [u8; 32] = Sha256::new()
        .chain_update(ENVELOPE_DOMAIN)
        .chain_update(&out)
        .finalize()
        .into();
    out.extend_from_slice(&checksum);
    Ok(Bytes::from(out))
}

fn decode_bound<'a>(
    magic: &[u8; 4],
    key: &[u8],
    bytes: &'a [u8],
) -> Result<&'a [u8], BarrierError> {
    const HEADER: usize = 4 + 1 + 32 + 4;
    if bytes.len() < HEADER + 32 || &bytes[..4] != magic || bytes[4] != RECORD_VERSION {
        return Err(BarrierError::Corrupt);
    }
    if &bytes[5..37] != Sha256::digest(key).as_slice() {
        return Err(BarrierError::Corrupt);
    }
    let length = u32::from_be_bytes(bytes[37..41].try_into().unwrap()) as usize;
    let checksum_at = HEADER.checked_add(length).ok_or(BarrierError::Corrupt)?;
    if checksum_at + 32 != bytes.len() {
        return Err(BarrierError::Corrupt);
    }
    let checksum: [u8; 32] = Sha256::new()
        .chain_update(ENVELOPE_DOMAIN)
        .chain_update(&bytes[..checksum_at])
        .finalize()
        .into();
    if bytes[checksum_at..] != checksum {
        return Err(BarrierError::Corrupt);
    }
    Ok(&bytes[HEADER..checksum_at])
}

pub(crate) fn authority_matches(
    record: &crate::fs::export_authority::ExportAuthorityRecord,
    command: &BarrierCommand,
    server_boot_id: &str,
    now: u64,
) -> Result<u64, BarrierError> {
    if record.workspace_id != command.operation.workspace_id
        || record.export != command.token.export
        || record.authority != command.token.authority
    {
        return Err(BarrierError::Conflict);
    }
    let session = record
        .active_session
        .as_ref()
        .ok_or(BarrierError::Conflict)?;
    if session.session_id != command.token.session_id
        || session.capability_id != command.token.capability_id
        || session.expires_at_unix_millis != command.token.expires_at_unix_millis
        || session.node_incarnation_id != command.token.node_incarnation_id
        || session.runtime_id != command.token.runtime_id
        || session.server_boot_id != command.token.server_boot_id
        || session.server_boot_id != server_boot_id
        || session.expires_at_unix_millis <= now
    {
        return Err(BarrierError::Conflict);
    }
    Ok(session.committed_through_sequence)
}

pub(crate) fn genesis_matches(
    genesis: &GenesisDomainRecord,
    command: &BarrierCommand,
) -> Result<(), BarrierError> {
    if genesis.workspace_id != command.operation.workspace_id
        || genesis.actor != command.token.authority.actor
        || genesis.actor_generation != command.token.authority.actor_generation
        || genesis.home_cell != command.token.authority.home_cell
        || genesis.storage_shard_id != command.storage_shard_id
        || genesis.storage_routing_revision != command.storage_routing_revision
        || genesis.export != command.token.export
    {
        return Err(BarrierError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
static FOUNDATION_MANIFEST_CRASH_CONTEXT: std::sync::Mutex<
    Option<(BarrierCommand, u64, BarrierDurabilityReceipt)>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn arm_foundation_manifest_crash(receipt: &BarrierDurabilityReceipt) {
    let command = command_from_receipt(receipt);
    let mut context = FOUNDATION_MANIFEST_CRASH_CONTEXT.lock().unwrap();
    assert!(
        context
            .replace((command, receipt.included_write_sequence, receipt.clone(),))
            .is_none(),
        "Foundation manifest crash context already armed"
    );
}

#[cfg(test)]
pub(crate) async fn foundation_manifest_applied_before_response() {
    let (command, included_write_sequence, receipt) = FOUNDATION_MANIFEST_CRASH_CONTEXT
        .lock()
        .unwrap()
        .take()
        .expect("manifest blocker requires an exact barrier receipt context");
    foundation_process_crash_point(
        "manifest-applied-before-response",
        &command,
        included_write_sequence,
        Some(&receipt),
    )
    .await;
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) async fn foundation_process_crash_point(
    point: &str,
    command: &BarrierCommand,
    included_write_sequence: u64,
    receipt: Option<&BarrierDurabilityReceipt>,
) {
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    let Ok(configured) = std::env::var("RHIZOME_BARRIER_FAULT_CRASH_POINT") else {
        return;
    };
    if configured != point {
        return;
    }
    let run_id = std::env::var("RHIZOME_BARRIER_FAULT_RUN_ID")
        .expect("fault run id must accompany crash point");
    let uuid = uuid::Uuid::parse_str(&run_id).expect("fault run id must be a UUID");
    assert_eq!(uuid.get_version_num(), 4);
    assert_eq!(uuid.to_string(), run_id);
    let scenario = std::env::var("RHIZOME_BARRIER_FAULT_SCENARIO")
        .expect("fault scenario must accompany crash point");
    assert_eq!(scenario, point);
    let run_root = std::path::PathBuf::from(format!(
        "/opt/rhizome/validation/zerofs-barrier-fault/runs/{run_id}"
    ));
    let configured_root = std::path::PathBuf::from(
        std::env::var("RHIZOME_BARRIER_FAULT_RUN_ROOT")
            .expect("fault run root must accompany crash point"),
    );
    assert_eq!(configured_root, run_root);
    assert_eq!(
        std::fs::canonicalize(&configured_root).unwrap(),
        configured_root
    );
    let metadata = std::fs::symlink_metadata(&configured_root).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.gid(), 0);
    assert_eq!(metadata.mode() & 0o7777, 0o700);

    let claim_bytes = std::fs::read(configured_root.join(format!("{scenario}.claim"))).unwrap();
    let claim_text = std::str::from_utf8(&claim_bytes).unwrap();
    let claim_field = |name: &str| {
        claim_text
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .expect("claim record field is present")
    };
    let hex = |bytes: &[u8]| {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    };
    let receipt_digest = receipt
        .map(|value| hex(&value.receipt_digest))
        .unwrap_or_else(|| "none".into());
    let preflight_receipt_sha256 =
        std::env::var("RHIZOME_BARRIER_FAULT_PREFLIGHT_RECEIPT_SHA256").unwrap();
    assert!(
        preflight_receipt_sha256.len() == 64
            && preflight_receipt_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    let directory = std::fs::File::open(&configured_root).unwrap();
    let pending_name = format!("{scenario}.handshake.pending");
    let final_name = format!("{scenario}.handshake");
    let fd = rustix::fs::openat(
        &directory,
        pending_name.as_str(),
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    let mut file = std::fs::File::from(fd);
    file.write_all(
        format!(
            "schema=1\nrun_id={run_id}\nscenario={scenario}\npoint={point}\npid={}\npreflight_receipt_sha256={preflight_receipt_sha256}\nrequest_digest={}\nbarrier_id={}\neffect_claim_digest={}\nclaim_record_digest={}\nincluded_write_sequence={included_write_sequence}\nreceipt_digest={receipt_digest}\n",
            std::process::id(),
            hex(command.request_digest.as_bytes()),
            claim_field("barrier_id"),
            claim_field("effect_claim_digest"),
            hex(&Sha256::digest(&claim_bytes)),
        )
        .as_bytes(),
    )
    .unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).unwrap();
    file.sync_all().unwrap();
    rustix::fs::renameat_with(
        &directory,
        pending_name.as_str(),
        &directory,
        final_name.as_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .unwrap();
    directory.sync_all().unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock).unwrap();
    std::future::pending::<()>().await;
}

#[cfg(all(test, not(target_os = "linux")))]
pub(crate) async fn foundation_process_crash_point(
    _point: &str,
    _command: &BarrierCommand,
    _included_write_sequence: u64,
    _receipt: Option<&BarrierDurabilityReceipt>,
) {
}

/// Deterministic head/receipt codec model used by the repository DST binary.
/// It constructs no verified production command or signed receipt.
#[cfg(dst)]
#[doc(hidden)]
pub fn dst_workspace_barrier_codec_model(seed: u64) {
    use crate::fs::export_authority::ExportIdentity;
    use crate::fs::workspace_genesis::ContentDigest;

    let seed = seed.saturating_add(1);
    let workspace_id = format!("workspace-{seed}");
    let request_id = format!("barrier-{seed}");
    let digest: [u8; 32] = Sha256::digest(seed.to_be_bytes()).into();
    let export = ExportIdentity {
        nbd_directory_inode: seed.saturating_add(10),
        name: format!("disk-{seed}").into_bytes(),
        inode: seed.saturating_add(20),
        advertised_size: 4096,
    };
    let authority = AuthorityVersion {
        actor: format!("actor-{seed}"),
        actor_generation: seed,
        home_cell: "cells/dst".into(),
        home_revision: 1,
        authority_epoch: 1,
        placement_epoch: 1,
        assignment_revision: 1,
    };
    let genesis = GenesisDomainRecord {
        workspace_id: workspace_id.clone(),
        operation_kind: 10,
        request_id: format!("genesis-{seed}"),
        actor: authority.actor.clone(),
        actor_generation: authority.actor_generation,
        home_cell: authority.home_cell.clone(),
        home_revision: authority.home_revision,
        authority_epoch: authority.authority_epoch,
        tenant: "tenants/dst".into(),
        template: "templates/dst@sha256:01".into(),
        root_policy: "policies/dst@1".into(),
        source_create_actor_request_digest: ContentDigest::new(digest),
        object_lineage: format!("lineage-{seed}"),
        storage_shard_id: "shard-dst".into(),
        storage_routing_revision: 1,
        effect_claim: Bytes::from_static(b"genesis-claim"),
        request_digest: CanonicalRequestDigest::new(digest),
        root_digest: ContentDigest::new(digest),
        root_object_key: format!("root-{seed}"),
        export: export.clone(),
    };
    let initial = initial_head(&genesis);
    let token = MutationFenceToken {
        workspace_id: workspace_id.clone(),
        export,
        authority,
        session_id: format!("session-{seed}"),
        capability_id: format!("capability-{seed}"),
        expires_at_unix_millis: u64::MAX,
        node_incarnation_id: format!("node-{seed}"),
        runtime_id: format!("runtime-{seed}"),
        server_boot_id: "00000000-0000-4000-8000-000000000001".into(),
    };
    let command = BarrierCommand {
        operation: WorkspaceOperationKey::new(
            workspace_id.clone(),
            CREATE_BARRIER_KIND,
            request_id.clone(),
        ),
        request_digest: CanonicalRequestDigest::new(digest),
        token,
        expected_head_digest: head_digest(&initial.head),
        storage_shard_id: "shard-dst".into(),
        storage_routing_revision: 1,
    };
    let barrier_id = "00000000-0000-4000-8000-000000000002";
    let claim = effect_claim(&command, barrier_id, "00000000-0000-4000-8000-000000000003");
    let next = next_head(&initial, &command, 1, 1, 2, 3).unwrap();
    let mut receipt = BarrierDurabilityReceipt {
        workspace_id: workspace_id.clone(),
        request_id: request_id.clone(),
        request_digest: digest,
        effect_claim: claim,
        token: command.token.clone(),
        expected_head_digest: command.expected_head_digest,
        head: next.head.clone(),
        barrier_id: barrier_id.into(),
        included_write_sequence: 1,
        zerofs_writer_epoch: 1,
        zerofs_manifest_id: 2,
        zerofs_durable_sequence: 3,
        storage_shard_id: "shard-dst".into(),
        storage_routing_revision: 1,
        committed_at_unix_seconds: seed,
        committed_at_nanos: 0,
        receipt_digest: [0; 32],
    };
    receipt.receipt_digest = receipt_digest(&receipt);
    let codec = KeyCodec::new();
    let head_key = codec.workspace_head_version_key(&workspace_id, 2);
    let encoded_head = encode_head_record(&head_key, &next).unwrap();
    assert_eq!(decode_head_record(&head_key, &encoded_head).unwrap(), next);
    let receipt_key = codec.workspace_barrier_record_key(&workspace_id, &request_id);
    let encoded_receipt = encode_barrier_record(&receipt_key, &receipt).unwrap();
    assert_eq!(
        decode_barrier_record(&receipt_key, &encoded_receipt).unwrap(),
        receipt
    );
    let wrong_key = codec.workspace_barrier_record_key(&workspace_id, "other");
    assert_eq!(
        decode_barrier_record(&wrong_key, &encoded_receipt),
        Err(BarrierError::Corrupt)
    );
}

#[cfg(test)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod tests {
    use super::*;
    use crate::fs::ZeroFS;
    use crate::fs::export_authority::{
        ActivateExport, DeactivateExport, ExportMutationBuilder, ExportMutationCommand,
        ExportReverseBinding, ExportSessionState, ShardProcessGuard, reverse_binding_keys,
    };
    use crate::fs::workspace_genesis::{
        ContentDigest, GenesisCommand, GenesisMaterializationPlan, GenesisMaterializeResult,
        VerifiedGenesisInput, VerifiedGenesisTerminal,
    };
    use crate::{
        block_transformer::ZeroFsBlockTransformer, config::CompressionConfig, db::SlateDbHandle,
        frame_codec::FrameCodec,
    };
    use futures::TryStreamExt;
    use slatedb::object_store::{ObjectStore, ObjectStoreExt, path::Path};
    use slatedb::{BlockTransformer, DbBuilder, DbReaderMode};

    async fn active_workspace() -> (ZeroFS, MutationFenceToken, GenesisDomainRecord) {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        initialize_active(fs).await
    }

    async fn initialize_active(fs: ZeroFS) -> (ZeroFS, MutationFenceToken, GenesisDomainRecord) {
        fs.export_authority
            .install_process_guard(ShardProcessGuard::for_test())
            .unwrap();
        fs.mkdir(
            &crate::fs::test_util::test_creds(),
            0,
            b".nbd",
            &crate::fs::types::SetAttributes::default(),
        )
        .await
        .unwrap();
        let root_bytes = Bytes::from_static(b"barrier-root");
        let genesis_operation = WorkspaceOperationKey::new("workspace-a", 10, "genesis-request");
        let genesis_digest = CanonicalRequestDigest::new(Sha256::digest(b"genesis-request").into());
        let genesis_input = VerifiedGenesisInput::for_test(
            GenesisCommand {
                operation: genesis_operation.clone(),
                request_digest: genesis_digest,
                actor: "tenants/t/actors/a".into(),
                actor_generation: 7,
                home_cell: "cells/c".into(),
                home_revision: 1,
                authority_epoch: 1,
                tenant: "tenants/t".into(),
                template: "templates/base@sha256:01".into(),
                root_policy: "policies/root@1".into(),
                source_create_actor_request_digest: ContentDigest::new([9; 32]),
                object_lineage: "lineage-a".into(),
                storage_shard_id: "test-shard-a".into(),
                storage_routing_revision: 1,
                virtual_size_bytes: 4096,
            },
            GenesisMaterializationPlan {
                export_name: b"workspace-a.img".to_vec(),
                root_digest: ContentDigest::new(Sha256::digest(&root_bytes).into()),
                root_bytes,
            },
        )
        .unwrap();
        let genesis_receipt = match fs
            .workspace_genesis
            .materialize(genesis_input.clone())
            .await
            .unwrap()
        {
            GenesisMaterializeResult::Materialized(receipt) => *receipt,
            other => panic!("unexpected genesis result: {other:?}"),
        };
        fs.workspace_genesis
            .complete(
                &genesis_input,
                VerifiedGenesisTerminal::for_test(
                    genesis_operation,
                    genesis_digest,
                    genesis_receipt.clone(),
                    Bytes::from_static(b"signed-genesis-receipt"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        fs.export_authority
            .enable_standalone_profile()
            .await
            .unwrap();
        let authority = AuthorityVersion {
            actor: "tenants/t/actors/a".into(),
            actor_generation: 7,
            home_cell: "cells/c".into(),
            home_revision: 1,
            authority_epoch: 1,
            placement_epoch: 1,
            assignment_revision: 1,
        };
        let active = fs
            .export_authority
            .activate(ActivateExport {
                workspace_id: "workspace-a".into(),
                export: genesis_receipt.record.export.clone(),
                authority: authority.clone(),
                session: ExportSessionState {
                    session_id: "session-a".into(),
                    capability_id: "capability-a".into(),
                    expires_at_unix_millis: u64::MAX,
                    node_incarnation_id: "node-a".into(),
                    runtime_id: "runtime-a".into(),
                    server_boot_id: "ignored-input".into(),
                    committed_through_sequence: 0,
                },
            })
            .await
            .unwrap();
        let session = active.active_session.unwrap();
        let token = MutationFenceToken {
            workspace_id: active.workspace_id,
            export: active.export,
            authority,
            session_id: session.session_id,
            capability_id: session.capability_id,
            expires_at_unix_millis: session.expires_at_unix_millis,
            node_incarnation_id: session.node_incarnation_id,
            runtime_id: session.runtime_id,
            server_boot_id: session.server_boot_id,
        };
        (fs, token, genesis_receipt.record)
    }

    async fn open_persistent(object_store: Arc<dyn ObjectStore>) -> ZeroFS {
        let test_key = [0u8; 32];
        let transformer: Arc<dyn BlockTransformer> =
            ZeroFsBlockTransformer::try_new_arc(&test_key, CompressionConfig::default()).unwrap();
        let db_path = Path::from("workspace-barrier-reopen");
        let publication = crate::manifest_publication::ManifestPublication::new();
        let slatedb_store: Arc<dyn ObjectStore> =
            Arc::new(crate::manifest_publication::ManifestPublicationStore::new(
                object_store.clone(),
                db_path.clone(),
                publication.clone(),
            ));
        let settings = slatedb::config::Settings {
            wal_enabled: false,
            flush_interval: None,
            l0_sst_size_bytes: crate::manifest_publication::COORDINATED_L0_SST_SIZE_BYTES,
            max_unflushed_bytes: crate::manifest_publication::COORDINATED_MAX_UNFLUSHED_BYTES,
            l0_max_ssts: 256,
            l0_max_ssts_per_key: 256,
            compactor_options: None,
            garbage_collector_options: None,
            ..Default::default()
        };
        let db = Arc::new(
            DbBuilder::new(db_path, slatedb_store)
                .with_settings(settings)
                .with_block_transformer(transformer)
                .with_filter_policies(crate::fs::filter_policy::filter_policies())
                .with_segment_extractor(Arc::new(crate::segment_extractor::ZeroFsSegmentExtractor))
                .build()
                .await
                .unwrap(),
        );
        let segment_codec = FrameCodec::try_new(
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
            segment_codec,
        )
        .await
        .unwrap();
        fs.flush_coordinator.set_manifest_publication(publication);
        fs
    }

    async fn open_persistent_read_only(
        object_store: Arc<dyn ObjectStore>,
    ) -> (ZeroFS, Arc<slatedb::DbReader>) {
        let test_key = [0u8; 32];
        let transformer: Arc<dyn BlockTransformer> =
            ZeroFsBlockTransformer::try_new_arc(&test_key, CompressionConfig::default()).unwrap();
        let reader = Arc::new(
            slatedb::DbReader::builder(
                Path::from("workspace-barrier-reopen"),
                object_store.clone(),
            )
            // ManagedCheckpoint is SlateDB's default reader mode, but opening it
            // publishes a checkpoint manifest. Crash recovery is a strictly
            // read-only inspection after the old writer has been killed and
            // joined, so it must follow the latest already-durable manifest
            // without creating or refreshing a checkpoint.
            .with_reader_mode(DbReaderMode::FollowLatest)
            .with_block_transformer(transformer)
            .with_filter_policies(crate::fs::filter_policy::filter_policies())
            .with_segment_extractor(Arc::new(crate::segment_extractor::ZeroFsSegmentExtractor))
            .build()
            .await
            .unwrap(),
        );
        let segment_codec = FrameCodec::try_new(
            &test_key,
            crate::segment::SEGMENT_INFO,
            CompressionConfig::default(),
        )
        .unwrap();
        let fs = ZeroFS::new_with_slatedb(
            SlateDbHandle::ReadOnly(arc_swap::ArcSwap::new(reader.clone())),
            u64::MAX,
            None,
            false,
            object_store,
            segment_codec,
        )
        .await
        .unwrap();
        (fs, reader)
    }

    fn command(
        request_id: &str,
        token: &MutationFenceToken,
        expected_head_digest: HeadDigest,
    ) -> BarrierCommand {
        BarrierCommand {
            operation: WorkspaceOperationKey::new(
                token.workspace_id.clone(),
                CREATE_BARRIER_KIND,
                request_id,
            ),
            request_digest: CanonicalRequestDigest::new(Sha256::digest(request_id).into()),
            token: token.clone(),
            expected_head_digest,
            storage_shard_id: "test-shard-a".into(),
            storage_routing_revision: 1,
        }
    }

    async fn materialize(fs: &ZeroFS, command: BarrierCommand) -> BarrierDurabilityReceipt {
        match fs
            .workspace_barriers
            .materialize(VerifiedBarrierInput::for_test(command).unwrap())
            .await
            .unwrap()
        {
            BarrierMaterializeResult::Materialized(receipt) => *receipt,
            other => panic!("unexpected barrier result: {other:?}"),
        }
    }

    async fn complete_barrier(
        fs: &ZeroFS,
        command: BarrierCommand,
        receipt: BarrierDurabilityReceipt,
    ) {
        let verified = VerifiedBarrierInput::for_test(command).unwrap();
        fs.workspace_barriers
            .complete(
                &verified,
                VerifiedBarrierTerminal::for_test(
                    receipt,
                    Bytes::from_static(b"signed-barrier-receipt"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn publishes_exact_manifest_cut_and_advances_head() {
        let (fs, token, genesis) = active_workspace().await;
        let initial = initial_head(&genesis);
        let first_command = command("barrier-1", &token, head_digest(&initial.head));
        let first = materialize(&fs, first_command.clone()).await;
        assert_eq!(first.included_write_sequence, 0);
        assert!(first.zerofs_writer_epoch > 0);
        assert!(first.zerofs_manifest_id > 0);
        assert!(first.zerofs_durable_sequence > 0);
        assert_eq!(first.head.workspace_version, 2);
        assert_eq!(first.storage_shard_id, "test-shard-a");
        assert_eq!(first.storage_routing_revision, 1);

        let verified = VerifiedBarrierInput::for_test(first_command).unwrap();
        let terminal = VerifiedBarrierTerminal::for_test(
            first.clone(),
            Bytes::from_static(b"signed-barrier-receipt"),
        )
        .unwrap();
        assert!(matches!(
            fs.workspace_barriers
                .complete(&verified, terminal)
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                state: WorkspaceOperationState::Succeeded(_),
                ..
            })
        ));

        let second = materialize(&fs, command("barrier-2", &token, head_digest(&first.head))).await;
        assert_eq!(second.head.workspace_version, 3);
        assert_eq!(second.head.base_root_digest, first.head.base_root_digest);
        assert_eq!(second.expected_head_digest, head_digest(&first.head));
    }

    #[tokio::test]
    async fn lost_materialization_reply_converges_by_exact_durable_record() {
        let (fs, token, genesis) = active_workspace().await;
        let command = command(
            "barrier-lost",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        fs.write_coordinator.dst_drop_next_barrier_reply();
        let receipt = materialize(&fs, command.clone()).await;
        assert_eq!(
            fs.workspace_barriers
                .lookup_materialized(&command)
                .await
                .unwrap(),
            Some(receipt)
        );
    }

    #[tokio::test]
    async fn unknown_after_flush_never_dispatches_a_second_barrier() {
        let (fs, token, genesis) = active_workspace().await;
        let command = command(
            "barrier-unknown",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        fs.write_coordinator.dst_fail_next_barrier_before_publish();
        assert_eq!(
            fs.workspace_barriers
                .materialize(VerifiedBarrierInput::for_test(command.clone()).unwrap())
                .await,
            Err(BarrierError::CommitOutcomeUnknown)
        );
        let completed = fs.flush_coordinator.completed_flush_count();
        assert_eq!(
            fs.workspace_barriers
                .materialize(VerifiedBarrierInput::for_test(command).unwrap())
                .await,
            Err(BarrierError::CommitOutcomeUnknown)
        );
        assert_eq!(fs.flush_coordinator.completed_flush_count(), completed);
    }

    #[tokio::test]
    async fn record_checksum_and_key_binding_cover_every_byte() {
        let (fs, token, genesis) = active_workspace().await;
        let command = command(
            "barrier-codec",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        let receipt = materialize(&fs, command.clone()).await;
        let key = KeyCodec::new().workspace_barrier_record_key(
            &command.operation.workspace_id,
            &command.operation.request_id,
        );
        let encoded = encode_barrier_record(&key, &receipt).unwrap();
        for index in 0..encoded.len() {
            let mut corrupted = encoded.to_vec();
            corrupted[index] ^= 1;
            assert!(
                decode_barrier_record(&key, &corrupted).is_err(),
                "byte {index}"
            );
        }
        let wrong_key = KeyCodec::new().workspace_barrier_record_key("workspace-a", "other");
        assert_eq!(
            decode_barrier_record(&wrong_key, &encoded),
            Err(BarrierError::Corrupt)
        );
    }

    #[tokio::test]
    async fn exact_materialized_cut_survives_cold_reopen() {
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let fs = open_persistent(object_store.clone()).await;
        let (fs, token, genesis) = initialize_active(fs).await;
        let command = command(
            "barrier-reopen",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        let receipt = materialize(&fs, command.clone()).await;
        fs.flush_coordinator.close().await.unwrap();
        drop(fs);

        let reopened = open_persistent(object_store).await;
        assert_eq!(
            reopened
                .workspace_barriers
                .lookup_materialized(&command)
                .await
                .unwrap(),
            Some(receipt)
        );
    }

    #[tokio::test]
    async fn barrier_cut_includes_the_coordinator_assigned_export_sequence() {
        let (fs, token, genesis) = active_workspace().await;
        let outcome = fs
            .export_authority
            .commit_mutation(
                ExportMutationBuilder::build(
                    token.clone(),
                    [0x31; 32],
                    ExportMutationCommand::Flush,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outcome.mutation.sequence, 1);

        let receipt = materialize(
            &fs,
            command(
                "barrier-sequence",
                &token,
                head_digest(&initial_head(&genesis).head),
            ),
        )
        .await;
        assert_eq!(receipt.included_write_sequence, 1);
        assert_eq!(receipt.head.committed_tail_position, 1);
    }

    #[tokio::test]
    async fn after_claim_export_write_and_manifest_response_loss_converge() {
        let inner: Arc<dyn ObjectStore> = Arc::new(slatedb::object_store::memory::InMemory::new());
        let (fault_store, faults) = crate::fault_store::FaultStore::new(inner);
        let object_store: Arc<dyn ObjectStore> = fault_store;
        let fs = open_persistent(object_store.clone()).await;
        let (fs, token, genesis) = initialize_active(fs).await;
        let payload = Bytes::from_static(b"export-data-after-barrier-claim");
        let mutation_store = fs.export_authority.clone();
        let mutation_token = token.clone();
        let mutation_payload = payload.clone();
        fs.workspace_barriers
            .dst_set_after_claim_hook(Arc::new(move |_, _| {
                let store = mutation_store.clone();
                let token = mutation_token.clone();
                let payload = mutation_payload.clone();
                Box::pin(async move {
                    let outcome = store
                        .commit_mutation(
                            ExportMutationBuilder::build(
                                token,
                                [0x71; 32],
                                ExportMutationCommand::Write {
                                    offset: 0,
                                    data: payload,
                                    fua: false,
                                },
                            )
                            .map_err(|_| BarrierError::Invalid)?,
                        )
                        .await
                        .map_err(|_| BarrierError::Storage)?;
                    (outcome.mutation.sequence == 1)
                        .then_some(())
                        .ok_or(BarrierError::Corrupt)
                })
            }));
        let armed_faults = faults.clone();
        fs.write_coordinator
            .dst_set_barrier_after_apply_hook(Arc::new(move |_| {
                armed_faults.fail_manifest_puts_after_apply(1);
            }));
        let command = command(
            "barrier-manifest-response-loss",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        let receipt = materialize(&fs, command.clone()).await;
        assert_eq!(receipt.included_write_sequence, 1);
        assert_eq!(faults.manifest_response_loss_count(), 1);
        assert!(faults.manifest_put_count() >= 2);
        drop(fs);

        // Count only the recovery process's object-store calls. The inner fault
        // store above retains the writer-phase counters by design.
        let (read_only_store, recovery_io) = crate::fault_store::FaultStore::new(object_store);
        let (reopened, reader) = open_persistent_read_only(read_only_store).await;
        assert_eq!(
            reopened
                .workspace_barriers
                .lookup_materialized(&command)
                .await
                .unwrap(),
            Some(receipt)
        );
        assert_eq!(
            reopened
                .extent_store
                .read(genesis.export.inode, 0, payload.len() as u64)
                .await
                .unwrap(),
            payload
        );
        reader.close().await.unwrap();
        drop(reopened);
        assert_eq!(recovery_io.put_count(), 0);
        assert!(recovery_io.put_locations().is_empty());
    }

    #[tokio::test]
    async fn managed_checkpoint_reader_is_not_a_read_only_recovery_mode() {
        let inner: Arc<dyn ObjectStore> = Arc::new(slatedb::object_store::memory::InMemory::new());
        let db = slatedb::Db::open("managed-reader-negative-control", inner.clone())
            .await
            .unwrap();
        db.close().await.unwrap();

        let (counting_store, writes) = crate::fault_store::FaultStore::new(inner);
        let reader = slatedb::DbReader::builder(
            Path::from("managed-reader-negative-control"),
            counting_store,
        )
        .build()
        .await
        .unwrap();

        assert_eq!(writes.put_count(), 1);
        assert_eq!(
            writes.put_locations(),
            ["put_opts managed-reader-negative-control/manifest/00000000000000000005.manifest"],
            "the pinned SlateDB default reader must expose its exact checkpoint-manifest PUT"
        );
        reader.close().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn foundation_exit_receipt_primitives_bind_process_and_publish_atomically() {
        let process = read_linux_process_identity(std::process::id());
        assert_eq!(process.pid, std::process::id());
        assert!(process.start_time_ticks > 0);
        assert!(!process.boot_id.is_empty());
        assert!(process.cgroup.starts_with('/'));

        let directory = tempfile::tempdir().unwrap();
        let receipt = directory.path().join("scenario.exit");
        write_new_durable_atomic_no_replace(&receipt, b"schema=1\n");
        assert_eq!(std::fs::read(&receipt).unwrap(), b"schema=1\n");
        assert!(!directory.path().join("scenario.exit.pending").exists());
    }

    #[tokio::test]
    async fn stale_epoch_cannot_publish_a_barrier_record() {
        let (fs, mut token, genesis) = active_workspace().await;
        token.authority.placement_epoch += 1;
        let command = command(
            "barrier-stale",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        assert_eq!(
            fs.workspace_barriers
                .materialize(VerifiedBarrierInput::for_test(command.clone()).unwrap())
                .await,
            Err(BarrierError::Conflict)
        );
        assert_eq!(
            fs.workspace_barriers
                .lookup_materialized(&command)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn general_transaction_cannot_forge_workspace_head_or_barrier_rows() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        for key in [
            KeyCodec::new().workspace_head_key("workspace-a"),
            KeyCodec::new().workspace_barrier_record_key("workspace-a", "request-a"),
            KeyCodec::new().workspace_head_version_key("workspace-a", 1),
        ] {
            let mut transaction = crate::db::Transaction::new();
            transaction.put_bytes(&key, Bytes::from_static(b"forged"));
            assert_eq!(
                fs.write_coordinator.commit(transaction).await,
                Err(crate::fs::errors::FsError::OperationNotPermitted)
            );
        }
    }

    #[tokio::test]
    async fn missing_current_head_or_predecessor_receipt_is_corruption() {
        let (fs, token, genesis) = active_workspace().await;
        let first_command = command(
            "barrier-closed-head",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        let first = materialize(&fs, first_command.clone()).await;
        complete_barrier(&fs, first_command.clone(), first.clone()).await;
        fs.db
            .inject_reserved_authority_delete_for_test(
                KeyCodec::new().workspace_head_key(&token.workspace_id),
            )
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.workspace_barriers
                .lookup_materialized(&first_command)
                .await,
            Err(BarrierError::Corrupt)
        );

        let (fs, token, genesis) = active_workspace().await;
        let first_command = command(
            "barrier-missing-receipt",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        let first = materialize(&fs, first_command.clone()).await;
        complete_barrier(&fs, first_command.clone(), first.clone()).await;
        fs.db
            .inject_reserved_authority_delete_for_test(
                KeyCodec::new().workspace_barrier_record_key(
                    &first_command.operation.workspace_id,
                    &first_command.operation.request_id,
                ),
            )
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.workspace_barriers
                .lookup_materialized(&first_command)
                .await,
            Err(BarrierError::Corrupt)
        );
        assert_eq!(
            fs.workspace_barriers
                .materialize(
                    VerifiedBarrierInput::for_test(command(
                        "barrier-after-corrupt",
                        &token,
                        head_digest(&first.head),
                    ))
                    .unwrap(),
                )
                .await,
            Err(BarrierError::Corrupt)
        );

        let (fs, token, genesis) = active_workspace().await;
        let first_command = command(
            "barrier-missing-predecessor",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        let first = materialize(&fs, first_command.clone()).await;
        fs.db
            .inject_reserved_authority_delete_for_test(
                KeyCodec::new().workspace_head_version_key(&token.workspace_id, 1),
            )
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.workspace_barriers
                .lookup_materialized(&first_command)
                .await,
            Err(BarrierError::Corrupt)
        );
        assert_eq!(first.head.workspace_version, 2);
    }

    #[tokio::test]
    async fn final_permit_rejects_a_superseding_process_boot() {
        let (fs, token, genesis) = active_workspace().await;
        let command = command(
            "barrier-boot-race",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        fs.write_coordinator.dst_pause_next_barrier_after_cut();
        let worker_fs = fs.clone();
        let task = tokio::spawn(async move {
            worker_fs
                .workspace_barriers
                .materialize(VerifiedBarrierInput::for_test(command).unwrap())
                .await
        });
        fs.write_coordinator.dst_wait_barrier_after_cut().await;
        fs.db
            .inject_reserved_authority_value_for_test(
                KeyCodec::new().export_boot_key(),
                Bytes::from_static(b"superseding-process-boot"),
            )
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        fs.write_coordinator.dst_release_barrier_after_cut();
        assert_eq!(task.await.unwrap(), Err(BarrierError::Conflict));
    }

    #[tokio::test]
    async fn missing_reverse_binding_blocks_barrier_publication() {
        let (fs, token, genesis) = active_workspace().await;
        let binding = ExportReverseBinding {
            workspace_id: token.workspace_id.clone(),
            actor: token.authority.actor.clone(),
            actor_generation: token.authority.actor_generation,
            export: token.export.clone(),
        };
        let (name_key, _) = reverse_binding_keys(&binding);
        fs.db
            .inject_reserved_authority_delete_for_test(name_key)
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.workspace_barriers
                .materialize(
                    VerifiedBarrierInput::for_test(command(
                        "barrier-missing-reverse",
                        &token,
                        head_digest(&initial_head(&genesis).head),
                    ))
                    .unwrap(),
                )
                .await,
            Err(BarrierError::Corrupt)
        );
    }

    #[tokio::test]
    async fn checksummed_but_non_derivable_head_graph_is_corruption() {
        let (fs, token, genesis) = active_workspace().await;
        let command = command(
            "barrier-tampered-head",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        let mut receipt = materialize(&fs, command.clone()).await;
        receipt.head.base_root_digest = [0x7a; 32];
        receipt.receipt_digest = receipt_digest(&receipt);
        validate_receipt(&receipt).unwrap();
        let tampered_head = WorkspaceHeadRecord {
            head: receipt.head.clone(),
            last_barrier_request_id: Some(receipt.request_id.clone()),
            last_barrier_request_digest: Some(receipt.request_digest),
        };
        let codec = KeyCodec::new();
        let head_key = codec.workspace_head_key(&receipt.workspace_id);
        let version_key =
            codec.workspace_head_version_key(&receipt.workspace_id, receipt.head.workspace_version);
        let receipt_key =
            codec.workspace_barrier_record_key(&receipt.workspace_id, &receipt.request_id);
        fs.db
            .inject_reserved_authority_value_for_test(
                head_key.clone(),
                encode_head_record(&head_key, &tampered_head).unwrap(),
            )
            .await
            .unwrap();
        fs.db
            .inject_reserved_authority_value_for_test(
                version_key.clone(),
                encode_head_record(&version_key, &tampered_head).unwrap(),
            )
            .await
            .unwrap();
        fs.db
            .inject_reserved_authority_value_for_test(
                receipt_key.clone(),
                encode_barrier_record(&receipt_key, &receipt).unwrap(),
            )
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.workspace_barriers.lookup_materialized(&command).await,
            Err(BarrierError::Corrupt)
        );
    }

    fn validate_conformance_prefix(prefix: &str) {
        assert!(prefix.starts_with("rhizome/zerofs-barrier/"));
        assert!(!prefix.ends_with('/'));
        assert!(!prefix.contains(".."));
        assert!(prefix.len() <= 200);
        assert!(prefix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'/' | b'-')
        }));
    }

    async fn listed_objects(store: &Arc<dyn ObjectStore>) -> Vec<Path> {
        store
            .list(None)
            .map_ok(|meta| meta.location)
            .try_collect()
            .await
            .unwrap()
    }

    async fn assert_inventory_bound(
        store: &Arc<dyn ObjectStore>,
        maximum_objects: usize,
        maximum_bytes: u64,
    ) {
        let inventory = listed_objects(store).await;
        assert!(inventory.len() <= maximum_objects);
        let mut total = 0u64;
        for location in inventory {
            total = total
                .checked_add(store.head(&location).await.unwrap().size)
                .unwrap();
            assert!(total <= maximum_bytes);
        }
    }

    fn lower_hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }

    const FOUNDATION_FAULT_CHILD: &str = "RHIZOME_BARRIER_FAULT_CHILD";
    const FOUNDATION_FAULT_TEST: &str =
        "fs::workspace_barrier::tests::foundation_rustfs_process_fault_matrix";
    const FOUNDATION_FAULT_SCENARIOS: [&str; 4] = [
        "before-data-cut",
        "after-0x0d-apply",
        "manifest-applied-before-response",
        "after-manifest-publish",
    ];

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct FoundationFaultContext {
        request_id: String,
        request_digest: [u8; 32],
        token: MutationFenceToken,
        expected_head_digest: HeadDigest,
        storage_shard_id: String,
        storage_routing_revision: u64,
        export_inode: u64,
        payload: Vec<u8>,
        mutation_operation_id: [u8; 32],
    }

    impl FoundationFaultContext {
        fn command(&self) -> BarrierCommand {
            BarrierCommand {
                operation: WorkspaceOperationKey::new(
                    self.token.workspace_id.clone(),
                    CREATE_BARRIER_KIND,
                    self.request_id.clone(),
                ),
                request_digest: CanonicalRequestDigest::new(self.request_digest),
                token: self.token.clone(),
                expected_head_digest: self.expected_head_digest,
                storage_shard_id: self.storage_shard_id.clone(),
                storage_routing_revision: self.storage_routing_revision,
            }
        }
    }

    fn foundation_fault_run() -> (String, std::path::PathBuf, String) {
        use std::os::unix::fs::MetadataExt;

        let run_id = std::env::var("RHIZOME_BARRIER_FAULT_RUN_ID").unwrap();
        let parsed = uuid::Uuid::parse_str(&run_id).unwrap();
        assert_eq!(parsed.get_version_num(), 4);
        assert_eq!(parsed.to_string(), run_id);
        let expected_root = std::path::PathBuf::from(format!(
            "/opt/rhizome/validation/zerofs-barrier-fault/runs/{run_id}"
        ));
        let configured_root =
            std::path::PathBuf::from(std::env::var("RHIZOME_BARRIER_FAULT_RUN_ROOT").unwrap());
        assert_eq!(configured_root, expected_root);
        assert_eq!(
            std::fs::canonicalize(&configured_root).unwrap(),
            configured_root
        );
        let metadata = std::fs::symlink_metadata(&configured_root).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.gid(), 0);
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        let expected_prefix = format!("rhizome/zerofs-barrier-fault/{run_id}");
        assert_eq!(
            std::env::var("RHIZOME_BARRIER_S3_PREFIX").unwrap(),
            expected_prefix
        );
        assert_eq!(
            std::env::var("RHIZOME_BARRIER_FAULT_SUPERVISOR_UNIT").unwrap(),
            format!("zerofs-barrier-fault-{run_id}.service")
        );
        let supervisor_cgroup = std::env::var("RHIZOME_BARRIER_FAULT_SUPERVISOR_CGROUP").unwrap();
        assert!(supervisor_cgroup.starts_with('/') && !supervisor_cgroup.contains('\n'));
        let preflight_receipt_sha256 =
            std::env::var("RHIZOME_BARRIER_FAULT_PREFLIGHT_RECEIPT_SHA256").unwrap();
        assert!(
            preflight_receipt_sha256.len() == 64
                && preflight_receipt_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        (run_id, configured_root, expected_prefix)
    }

    fn foundation_fault_store(prefix: &str) -> Arc<dyn ObjectStore> {
        let bucket = std::env::var("RHIZOME_BARRIER_S3_BUCKET").unwrap();
        let raw = slatedb::object_store::aws::AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .with_virtual_hosted_style_request(false)
            .build()
            .unwrap();
        Arc::new(slatedb::object_store::prefix::PrefixStore::new(
            raw,
            Path::from(prefix),
        ))
    }

    fn scenario_prefix(base: &str, scenario: &str) -> String {
        assert!(FOUNDATION_FAULT_SCENARIOS.contains(&scenario));
        format!("{base}/{scenario}")
    }

    fn context_path(root: &std::path::Path, scenario: &str) -> std::path::PathBuf {
        root.join(format!("{scenario}.context"))
    }

    fn claim_path(root: &std::path::Path, scenario: &str) -> std::path::PathBuf {
        root.join(format!("{scenario}.claim"))
    }

    fn recovery_path(root: &std::path::Path, scenario: &str) -> std::path::PathBuf {
        root.join(format!("{scenario}.recovery"))
    }

    fn exit_path(root: &std::path::Path, scenario: &str) -> std::path::PathBuf {
        root.join(format!("{scenario}.exit"))
    }

    fn read_root_owned_scenario_file(root: &std::path::Path, name: &str) -> Vec<u8> {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;

        assert!(!name.is_empty() && !name.contains('/') && name != "." && name != "..");
        let directory = std::fs::File::open(root).unwrap();
        let fd = rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mut file = std::fs::File::from(fd);
        let metadata = file.metadata().unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.gid(), 0);
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn read_closed_scenario_record(
        root: &std::path::Path,
        name: &str,
        expected_fields: &[&str],
    ) -> std::collections::BTreeMap<String, String> {
        let bytes = read_root_owned_scenario_file(root, name);
        parse_closed_record(std::str::from_utf8(&bytes).unwrap(), expected_fields)
    }

    fn read_exit_record(
        root: &std::path::Path,
        scenario: &str,
    ) -> std::collections::BTreeMap<String, String> {
        read_closed_scenario_record(
            root,
            &format!("{scenario}.exit"),
            &[
                "schema",
                "run_id",
                "scenario",
                "pid",
                "pid_start_time_ticks",
                "linux_boot_id",
                "signal",
                "joined_at_unix_seconds",
                "joined_at_unix_nanos",
                "joined_at_boot_millis",
                "supervisor_unit",
                "supervisor_cgroup",
                "preflight_receipt_sha256",
                "request_digest",
                "barrier_id",
                "effect_claim_digest",
                "claim_record_digest",
                "handshake_digest",
                "included_write_sequence",
                "receipt_digest",
            ],
        )
    }

    fn read_handshake_record(
        root: &std::path::Path,
        scenario: &str,
    ) -> std::collections::BTreeMap<String, String> {
        read_closed_scenario_record(
            root,
            &format!("{scenario}.handshake"),
            &[
                "schema",
                "run_id",
                "scenario",
                "point",
                "pid",
                "preflight_receipt_sha256",
                "request_digest",
                "barrier_id",
                "effect_claim_digest",
                "claim_record_digest",
                "included_write_sequence",
                "receipt_digest",
            ],
        )
    }

    fn write_new_durable(path: &std::path::Path, bytes: &[u8]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        std::fs::File::open(path.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    fn write_new_durable_atomic_no_replace(path: &std::path::Path, bytes: &[u8]) {
        use std::io::Write;

        let parent = path.parent().unwrap();
        let final_name = path.file_name().unwrap().to_str().unwrap();
        let pending_name = format!("{final_name}.pending");
        let directory = std::fs::File::open(parent).unwrap();
        let fd = rustix::fs::openat(
            &directory,
            pending_name.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        rustix::fs::renameat_with(
            &directory,
            pending_name.as_str(),
            &directory,
            final_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .unwrap();
        directory.sync_all().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct LinuxProcessIdentity {
        pid: u32,
        start_time_ticks: u64,
        boot_id: String,
        cgroup: String,
    }

    #[cfg(target_os = "linux")]
    fn read_linux_process_identity(pid: u32) -> LinuxProcessIdentity {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let comm_end = stat.rfind(')').expect("proc stat command is closed");
        let fields = stat[comm_end + 2..].split_whitespace().collect::<Vec<_>>();
        let start_time_ticks = fields
            .get(19)
            .expect("proc stat contains start time")
            .parse()
            .unwrap();
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
            .to_owned();
        let parsed_boot = uuid::Uuid::parse_str(&boot_id).unwrap();
        assert_eq!(parsed_boot.to_string(), boot_id);
        let cgroups = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
        let cgroup = cgroups
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .expect("process belongs to one unified cgroup")
            .to_owned();
        assert!(cgroup.starts_with('/') && !cgroup.contains('\n'));
        LinuxProcessIdentity {
            pid,
            start_time_ticks,
            boot_id,
            cgroup,
        }
    }

    #[cfg(target_os = "linux")]
    fn persist_crash_exit_receipt(
        root: &std::path::Path,
        run_id: &str,
        scenario: &str,
        process: &LinuxProcessIdentity,
        status: &std::process::ExitStatus,
        handshake: &std::collections::BTreeMap<String, String>,
    ) {
        use std::os::unix::process::ExitStatusExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(!std::path::Path::new(&format!("/proc/{}", process.pid)).exists());
        let expected_unit = format!("zerofs-barrier-fault-{run_id}.service");
        assert_eq!(
            std::env::var("RHIZOME_BARRIER_FAULT_SUPERVISOR_UNIT").unwrap(),
            expected_unit
        );
        let expected_cgroup = std::env::var("RHIZOME_BARRIER_FAULT_SUPERVISOR_CGROUP").unwrap();
        assert_eq!(process.cgroup, expected_cgroup);
        let handshake_bytes = read_root_owned_scenario_file(root, &format!("{scenario}.handshake"));
        let claim_bytes = read_root_owned_scenario_file(root, &format!("{scenario}.claim"));
        let joined = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let uptime = std::fs::read_to_string("/proc/uptime").unwrap();
        let boot_seconds = uptime.split_whitespace().next().unwrap();
        let (whole, fractional) = boot_seconds.split_once('.').unwrap_or((boot_seconds, "0"));
        let mut millis = fractional
            .as_bytes()
            .iter()
            .take(3)
            .fold(0u64, |value, digit| value * 10 + u64::from(*digit - b'0'));
        for _ in fractional.len().min(3)..3 {
            millis *= 10;
        }
        let joined_at_boot_millis = whole.parse::<u64>().unwrap() * 1000 + millis;
        let bytes = format!(
            "schema=1\nrun_id={run_id}\nscenario={scenario}\npid={}\npid_start_time_ticks={}\nlinux_boot_id={}\nsignal={}\njoined_at_unix_seconds={}\njoined_at_unix_nanos={}\njoined_at_boot_millis={joined_at_boot_millis}\nsupervisor_unit={expected_unit}\nsupervisor_cgroup={}\npreflight_receipt_sha256={}\nrequest_digest={}\nbarrier_id={}\neffect_claim_digest={}\nclaim_record_digest={}\nhandshake_digest={}\nincluded_write_sequence={}\nreceipt_digest={}\n",
            process.pid,
            process.start_time_ticks,
            process.boot_id,
            libc::SIGKILL,
            joined.as_secs(),
            joined.subsec_nanos(),
            process.cgroup,
            handshake["preflight_receipt_sha256"],
            handshake["request_digest"],
            handshake["barrier_id"],
            handshake["effect_claim_digest"],
            lower_hex(&Sha256::digest(&claim_bytes)),
            lower_hex(&Sha256::digest(&handshake_bytes)),
            handshake["included_write_sequence"],
            handshake["receipt_digest"],
        );
        write_new_durable_atomic_no_replace(&exit_path(root, scenario), bytes.as_bytes());
        let record = read_exit_record(root, scenario);
        assert_eq!(record["pid"], process.pid.to_string());
        assert_eq!(record["signal"], libc::SIGKILL.to_string());
    }

    fn read_fault_context(root: &std::path::Path, scenario: &str) -> FoundationFaultContext {
        let bytes = read_root_owned_scenario_file(root, &format!("{scenario}.context"));
        codec().deserialize(&bytes).unwrap()
    }

    fn persist_fault_context(
        root: &std::path::Path,
        scenario: &str,
        context: &FoundationFaultContext,
    ) {
        write_new_durable(
            &context_path(root, scenario),
            &codec().serialize(context).unwrap(),
        );
    }

    fn parse_closed_record(
        contents: &str,
        expected_fields: &[&str],
    ) -> std::collections::BTreeMap<String, String> {
        assert!(contents.ends_with('\n'));
        let mut fields = std::collections::BTreeMap::new();
        for line in contents.lines() {
            let (key, value) = line.split_once('=').expect("record line has one separator");
            assert!(expected_fields.contains(&key));
            assert!(!value.is_empty() && !value.contains('='));
            assert!(fields.insert(key.to_owned(), value.to_owned()).is_none());
        }
        assert_eq!(fields.len(), expected_fields.len());
        for field in expected_fields {
            assert!(fields.contains_key(*field));
        }
        fields
    }

    fn assert_lower_hex_digest(value: &str) {
        assert_eq!(value.len(), 64);
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    fn assert_uuid_v4(value: &str) {
        let parsed = uuid::Uuid::parse_str(value).unwrap();
        assert_eq!(parsed.get_version_num(), 4);
        assert_eq!(parsed.to_string(), value);
    }

    fn persist_claim_record(
        root: &std::path::Path,
        scenario: &str,
        request_digest: [u8; 32],
        claim: &[u8],
        barrier_id: &str,
    ) {
        let parsed = uuid::Uuid::parse_str(barrier_id).unwrap();
        assert_eq!(parsed.get_version_num(), 4);
        assert_eq!(parsed.to_string(), barrier_id);
        write_new_durable(
            &claim_path(root, scenario),
            format!(
                "schema=1\nscenario={scenario}\nrequest_digest={}\nbarrier_id={barrier_id}\neffect_claim_digest={}\nincluded_write_sequence=1\n",
                lower_hex(&request_digest),
                lower_hex(&Sha256::digest(claim)),
            )
            .as_bytes(),
        );
    }

    fn read_claim_record(
        root: &std::path::Path,
        scenario: &str,
    ) -> std::collections::BTreeMap<String, String> {
        read_closed_scenario_record(
            root,
            &format!("{scenario}.claim"),
            &[
                "schema",
                "scenario",
                "request_digest",
                "barrier_id",
                "effect_claim_digest",
                "included_write_sequence",
            ],
        )
    }

    fn install_after_claim_write(
        fs: &ZeroFS,
        root: &std::path::Path,
        scenario: &str,
        context: &FoundationFaultContext,
    ) {
        let store = fs.export_authority.clone();
        let root = root.to_path_buf();
        let scenario = scenario.to_owned();
        let request_digest = context.request_digest;
        let token = context.token.clone();
        let payload = Bytes::copy_from_slice(&context.payload);
        let operation_id = context.mutation_operation_id;
        fs.workspace_barriers
            .dst_set_after_claim_hook(Arc::new(move |claim, barrier_id| {
                let store = store.clone();
                let token = token.clone();
                let payload = payload.clone();
                let claim = claim.clone();
                let barrier_id = barrier_id.to_owned();
                let root = root.clone();
                let scenario = scenario.clone();
                Box::pin(async move {
                    let outcome = store
                        .commit_mutation(
                            ExportMutationBuilder::build(
                                token,
                                operation_id,
                                ExportMutationCommand::Write {
                                    offset: 0,
                                    data: payload,
                                    fua: false,
                                },
                            )
                            .map_err(|_| BarrierError::Invalid)?,
                        )
                        .await
                        .map_err(|_| BarrierError::Storage)?;
                    if outcome.mutation.sequence != 1 {
                        return Err(BarrierError::Corrupt);
                    }
                    persist_claim_record(&root, &scenario, request_digest, &claim, &barrier_id);
                    Ok(())
                })
            }));
    }

    async fn foundation_fault_crash_child(scenario: &str) {
        let (_, root, base_prefix) = foundation_fault_run();
        assert_eq!(
            std::env::var("RHIZOME_BARRIER_FAULT_CRASH_POINT").unwrap(),
            scenario
        );
        let raw_store = foundation_fault_store(&scenario_prefix(&base_prefix, scenario));
        let (fault_store, faults) = crate::fault_store::FaultStore::new(raw_store);
        faults.set_put_limits(128, 16 * 1024 * 1024);
        let object_store: Arc<dyn ObjectStore> = fault_store;
        assert!(listed_objects(&object_store).await.is_empty());
        let fs = open_persistent(object_store).await;
        let (fs, token, genesis) = initialize_active(fs).await;
        let request_id = format!("barrier-{scenario}");
        let mut operation_id: [u8; 32] =
            Sha256::digest(format!("mutation-{scenario}").as_bytes()).into();
        operation_id[0] |= 1;
        let context = FoundationFaultContext {
            request_digest: Sha256::digest(request_id.as_bytes()).into(),
            request_id,
            token,
            expected_head_digest: head_digest(&initial_head(&genesis).head),
            storage_shard_id: "test-shard-a".into(),
            storage_routing_revision: 1,
            export_inode: genesis.export.inode,
            payload: b"rhizome-export-data-after-durable-barrier-claim".to_vec(),
            mutation_operation_id: operation_id,
        };
        persist_fault_context(&root, scenario, &context);
        install_after_claim_write(&fs, &root, scenario, &context);
        if scenario == "manifest-applied-before-response" {
            let armed_faults = faults.clone();
            fs.write_coordinator
                .dst_set_barrier_after_apply_hook(Arc::new(move |receipt| {
                    arm_foundation_manifest_crash(receipt);
                    armed_faults.block_manifest_after_apply();
                }));
        }
        let result = fs
            .workspace_barriers
            .materialize(VerifiedBarrierInput::for_test(context.command()).unwrap())
            .await;
        panic!("crash child returned before SIGKILL: {result:?}");
    }

    async fn foundation_fault_recovery_child(scenario: &str) {
        let (run_id, root, base_prefix) = foundation_fault_run();
        let context = read_fault_context(&root, scenario);
        let command = context.command();
        let claim_record = read_claim_record(&root, scenario);
        let exit_record = read_exit_record(&root, scenario);
        let handshake_record = read_handshake_record(&root, scenario);
        let claim_bytes = read_root_owned_scenario_file(&root, &format!("{scenario}.claim"));
        let handshake_bytes =
            read_root_owned_scenario_file(&root, &format!("{scenario}.handshake"));
        assert_eq!(claim_record["schema"], "1");
        assert_eq!(claim_record["scenario"], scenario);
        assert_eq!(
            claim_record["request_digest"],
            lower_hex(&context.request_digest)
        );
        assert_eq!(claim_record["included_write_sequence"], "1");
        assert_lower_hex_digest(&claim_record["request_digest"]);
        assert_lower_hex_digest(&claim_record["effect_claim_digest"]);
        assert_uuid_v4(&claim_record["barrier_id"]);

        assert_eq!(handshake_record["schema"], "1");
        assert_eq!(handshake_record["run_id"], run_id);
        assert_eq!(handshake_record["scenario"], scenario);
        assert_eq!(handshake_record["point"], scenario);
        assert_eq!(
            handshake_record["preflight_receipt_sha256"],
            std::env::var("RHIZOME_BARRIER_FAULT_PREFLIGHT_RECEIPT_SHA256").unwrap()
        );
        assert_eq!(
            handshake_record["request_digest"],
            claim_record["request_digest"]
        );
        assert_eq!(handshake_record["barrier_id"], claim_record["barrier_id"]);
        assert_eq!(
            handshake_record["effect_claim_digest"],
            claim_record["effect_claim_digest"]
        );
        assert_eq!(
            handshake_record["claim_record_digest"],
            lower_hex(&Sha256::digest(&claim_bytes))
        );
        assert_eq!(handshake_record["included_write_sequence"], "1");
        assert_lower_hex_digest(&handshake_record["preflight_receipt_sha256"]);
        assert_lower_hex_digest(&handshake_record["request_digest"]);
        assert_lower_hex_digest(&handshake_record["effect_claim_digest"]);
        assert_lower_hex_digest(&handshake_record["claim_record_digest"]);
        assert_uuid_v4(&handshake_record["barrier_id"]);

        assert_eq!(exit_record["schema"], "1");
        assert_eq!(exit_record["run_id"], run_id);
        assert_eq!(exit_record["scenario"], scenario);
        assert_eq!(exit_record["signal"], libc::SIGKILL.to_string());
        assert_eq!(exit_record["pid"], handshake_record["pid"]);
        assert_eq!(
            exit_record["request_digest"],
            handshake_record["request_digest"]
        );
        assert_eq!(exit_record["barrier_id"], handshake_record["barrier_id"]);
        assert_eq!(
            exit_record["effect_claim_digest"],
            handshake_record["effect_claim_digest"]
        );
        assert_eq!(
            exit_record["claim_record_digest"],
            handshake_record["claim_record_digest"]
        );
        assert_eq!(
            exit_record["handshake_digest"],
            lower_hex(&Sha256::digest(&handshake_bytes))
        );
        assert_eq!(exit_record["included_write_sequence"], "1");
        assert_eq!(
            exit_record["receipt_digest"],
            handshake_record["receipt_digest"]
        );
        assert_eq!(
            exit_record["preflight_receipt_sha256"],
            std::env::var("RHIZOME_BARRIER_FAULT_PREFLIGHT_RECEIPT_SHA256").unwrap()
        );
        assert_eq!(
            exit_record["supervisor_unit"],
            std::env::var("RHIZOME_BARRIER_FAULT_SUPERVISOR_UNIT").unwrap()
        );
        assert_eq!(
            exit_record["supervisor_cgroup"],
            std::env::var("RHIZOME_BARRIER_FAULT_SUPERVISOR_CGROUP").unwrap()
        );
        assert_eq!(
            exit_record["linux_boot_id"],
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim()
        );
        assert!(exit_record["pid_start_time_ticks"].parse::<u64>().unwrap() > 0);
        let child_start_ticks = exit_record["pid_start_time_ticks"].parse::<u64>().unwrap();
        assert!(
            exit_record["joined_at_unix_seconds"]
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert!(exit_record["joined_at_unix_nanos"].parse::<u32>().unwrap() < 1_000_000_000);
        assert!(exit_record["joined_at_boot_millis"].parse::<u64>().unwrap() > 0);
        let clock_ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        assert!(clock_ticks > 0);
        assert!(
            exit_record["joined_at_boot_millis"].parse::<u64>().unwrap()
                >= child_start_ticks.saturating_mul(1000) / clock_ticks as u64
        );
        assert!(!std::path::Path::new(&format!("/proc/{}", exit_record["pid"])).exists());
        assert_uuid_v4(&exit_record["run_id"]);
        assert_uuid_v4(&exit_record["barrier_id"]);
        for field in [
            "preflight_receipt_sha256",
            "request_digest",
            "effect_claim_digest",
            "claim_record_digest",
            "handshake_digest",
        ] {
            assert_lower_hex_digest(&exit_record[field]);
        }
        if exit_record["receipt_digest"] != "none" {
            assert_lower_hex_digest(&exit_record["receipt_digest"]);
        }

        // Only after the complete local crash provenance graph is closed may
        // recovery construct an object-store client and issue any S3 read.
        let raw_store = foundation_fault_store(&scenario_prefix(&base_prefix, scenario));
        let (fault_store, recovery_io) = crate::fault_store::FaultStore::new(raw_store);
        recovery_io.set_put_limits(128, 16 * 1024 * 1024);
        let object_store: Arc<dyn ObjectStore> = fault_store;
        let (fs, reader) = open_persistent_read_only(object_store).await;
        let lookup = fs
            .workspace_barriers
            .lookup_materialized(&command)
            .await
            .unwrap();
        let operation = fs
            .workspace_operations
            .lookup(&command.operation, command.request_digest)
            .await
            .unwrap();
        let WorkspaceOperationLookup::Known(operation) = operation else {
            panic!("durable barrier claim is absent");
        };
        let WorkspaceOperationState::EffectDispatched(effect_claim) = operation.state else {
            panic!("crash recovery must retain the exact effect-dispatch claim");
        };
        assert_eq!(
            claim_record["effect_claim_digest"],
            lower_hex(&Sha256::digest(&effect_claim))
        );
        assert!(claim_matches(
            &effect_claim,
            &command,
            &claim_record["barrier_id"]
        ));
        let bytes = fs
            .extent_store
            .read(context.export_inode, 0, context.payload.len() as u64)
            .await
            .unwrap();
        let (outcome, receipt_digest, included_sequence, payload_state) = match scenario {
            "before-data-cut" => {
                assert_eq!(exit_record["receipt_digest"], "none");
                assert!(lookup.is_none());
                assert_eq!(bytes, Bytes::from(vec![0; context.payload.len()]));
                ("unknown", "none".to_string(), 0, "absent")
            }
            "after-0x0d-apply" => {
                assert_ne!(exit_record["receipt_digest"], "none");
                assert!(lookup.is_none());
                assert_eq!(bytes.as_ref(), context.payload.as_slice());
                ("unknown", "none".to_string(), 0, "durable")
            }
            "manifest-applied-before-response" | "after-manifest-publish" => {
                let receipt = lookup.expect("published manifest must expose exact barrier");
                assert_eq!(receipt.included_write_sequence, 1);
                assert_eq!(receipt.effect_claim, effect_claim);
                assert_eq!(receipt.barrier_id, claim_record["barrier_id"]);
                assert_eq!(
                    exit_record["receipt_digest"],
                    lower_hex(&receipt.receipt_digest)
                );
                assert_eq!(bytes.as_ref(), context.payload.as_slice());
                (
                    "materialized",
                    lower_hex(&receipt.receipt_digest),
                    receipt.included_write_sequence,
                    "durable",
                )
            }
            _ => unreachable!(),
        };
        reader.close().await.unwrap();
        drop(fs);
        assert_eq!(recovery_io.put_count(), 0);
        assert!(recovery_io.put_locations().is_empty());
        write_new_durable(
            &recovery_path(&root, scenario),
            format!(
                "schema=1\nscenario={scenario}\noutcome={outcome}\nrequest_digest={}\nincluded_write_sequence={included_sequence}\nreceipt_digest={receipt_digest}\npayload={payload_state}\nrecovery_puts=0\n",
                lower_hex(&context.request_digest),
            )
            .as_bytes(),
        );
    }

    struct KillJoinChild(Option<std::process::Child>);

    impl KillJoinChild {
        fn child(&mut self) -> &mut std::process::Child {
            self.0.as_mut().unwrap()
        }

        fn terminate_until(&mut self, deadline: std::time::Instant) -> std::process::ExitStatus {
            self.0.as_mut().unwrap().kill().unwrap();
            self.wait_until(deadline)
        }

        fn wait_until(&mut self, deadline: std::time::Instant) -> std::process::ExitStatus {
            loop {
                if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                    self.0 = None;
                    return status;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "child process exceeded its join deadline"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }

    impl Drop for KillJoinChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            self.0 = None;
                            return;
                        }
                        Ok(None) if std::time::Instant::now() < deadline => {
                            std::thread::sleep(std::time::Duration::from_millis(20));
                        }
                        _ => std::process::abort(),
                    }
                }
            }
        }
    }

    fn spawn_fault_child(mode: &str, scenario: &str) -> KillJoinChild {
        use std::os::unix::fs::MetadataExt;

        let executable_fd = std::env::var("RHIZOME_BARRIER_FAULT_TEST_EXECUTABLE_FD").unwrap();
        let parsed_fd = executable_fd.parse::<u32>().unwrap();
        assert!(parsed_fd > 2 && parsed_fd.to_string() == executable_fd);
        let executable = format!("/proc/self/fd/{parsed_fd}");
        let executable_metadata = std::fs::metadata(&executable).unwrap();
        let process_metadata = std::fs::metadata("/proc/self/exe").unwrap();
        assert!(executable_metadata.is_file());
        assert_eq!(executable_metadata.dev(), process_metadata.dev());
        assert_eq!(executable_metadata.ino(), process_metadata.ino());
        assert_eq!(executable_metadata.size(), process_metadata.size());
        let child = std::process::Command::new(executable)
            .arg("--exact")
            .arg(FOUNDATION_FAULT_TEST)
            .arg("--ignored")
            .arg("--nocapture")
            .env(FOUNDATION_FAULT_CHILD, mode)
            .env("RHIZOME_BARRIER_FAULT_SCENARIO", scenario)
            .env("RHIZOME_BARRIER_FAULT_CRASH_POINT", scenario)
            .spawn()
            .unwrap();
        KillJoinChild(Some(child))
    }

    fn wait_for_fault_handshake(
        root: &std::path::Path,
        scenario: &str,
        child: &mut std::process::Child,
    ) -> std::collections::BTreeMap<String, String> {
        use std::io::Read;

        let child_pid = child.id();
        let marker = root.join(format!("{scenario}.handshake"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            match std::fs::File::open(&marker) {
                Ok(mut file) => {
                    let locked = match rustix::fs::flock(
                        &file,
                        rustix::fs::FlockOperation::NonBlockingLockShared,
                    ) {
                        Ok(()) => true,
                        Err(error) if error == rustix::io::Errno::WOULDBLOCK => false,
                        Err(error) => panic!("lock durable handshake: {error}"),
                    };
                    if locked {
                        let mut contents = String::new();
                        file.read_to_string(&mut contents).unwrap();
                        let fields = parse_closed_record(
                            &contents,
                            &[
                                "schema",
                                "run_id",
                                "scenario",
                                "point",
                                "pid",
                                "preflight_receipt_sha256",
                                "request_digest",
                                "barrier_id",
                                "effect_claim_digest",
                                "claim_record_digest",
                                "included_write_sequence",
                                "receipt_digest",
                            ],
                        );
                        assert_eq!(fields["schema"], "1");
                        assert_eq!(fields["scenario"], scenario);
                        assert_eq!(fields["point"], scenario);
                        assert_eq!(fields["pid"], child_pid.to_string());
                        assert_eq!(
                            fields["preflight_receipt_sha256"],
                            std::env::var("RHIZOME_BARRIER_FAULT_PREFLIGHT_RECEIPT_SHA256")
                                .unwrap()
                        );
                        assert_eq!(fields["included_write_sequence"], "1");
                        rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock).unwrap();
                        return fields;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("read handshake: {error}"),
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("fault child exited before handshake: {status}");
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for exact crash handshake"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(target_os = "linux")]
    #[ignore = "requires an explicitly configured isolated Foundation RustFS run"]
    #[tokio::test]
    async fn foundation_rustfs_process_fault_matrix() {
        use futures::FutureExt;
        use std::os::unix::process::ExitStatusExt;

        if let Ok(mode) = std::env::var(FOUNDATION_FAULT_CHILD) {
            let scenario = std::env::var("RHIZOME_BARRIER_FAULT_SCENARIO").unwrap();
            assert!(FOUNDATION_FAULT_SCENARIOS.contains(&scenario.as_str()));
            match mode.as_str() {
                "crash" => foundation_fault_crash_child(&scenario).await,
                "recover" => foundation_fault_recovery_child(&scenario).await,
                _ => panic!("unsupported Foundation fault child mode"),
            }
            return;
        }

        let (run_id, root, base_prefix) = foundation_fault_run();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let base_store = foundation_fault_store(&base_prefix);
        assert!(listed_objects(&base_store).await.is_empty());

        let run = std::panic::AssertUnwindSafe(async {
            for scenario in FOUNDATION_FAULT_SCENARIOS {
                assert_inventory_bound(&base_store, 512, 64 * 1024 * 1024).await;
                let mut crash = spawn_fault_child("crash", scenario);
                let handshake = wait_for_fault_handshake(&root, scenario, crash.child());
                let crash_process = read_linux_process_identity(crash.child().id());
                let context = read_fault_context(&root, scenario);
                let claim_record = read_claim_record(&root, scenario);
                assert_eq!(handshake["run_id"], run_id);
                assert_eq!(
                    handshake["request_digest"],
                    lower_hex(&context.request_digest)
                );
                assert_eq!(handshake["barrier_id"], claim_record["barrier_id"]);
                assert_eq!(
                    handshake["effect_claim_digest"],
                    claim_record["effect_claim_digest"]
                );
                assert_eq!(
                    handshake["claim_record_digest"],
                    lower_hex(&Sha256::digest(read_root_owned_scenario_file(
                        &root,
                        &format!("{scenario}.claim")
                    )))
                );
                match scenario {
                    "before-data-cut" => {
                        assert_eq!(handshake["receipt_digest"], "none");
                    }
                    _ => assert_ne!(handshake["receipt_digest"], "none"),
                }
                let status = crash.terminate_until(
                    std::time::Instant::now() + std::time::Duration::from_secs(120),
                );
                assert_eq!(status.signal(), Some(libc::SIGKILL));
                persist_crash_exit_receipt(
                    &root,
                    &run_id,
                    scenario,
                    &crash_process,
                    &status,
                    &handshake,
                );

                let mut recovery = spawn_fault_child("recover", scenario);
                let recovery_status = recovery
                    .wait_until(std::time::Instant::now() + std::time::Duration::from_secs(120));
                assert!(recovery_status.success());
                let recovery_result =
                    std::fs::read_to_string(recovery_path(&root, scenario)).unwrap();
                assert!(recovery_result.contains(&format!("scenario={scenario}\n")));
                assert!(recovery_result.contains("recovery_puts=0\n"));
                match scenario {
                    "before-data-cut" => {
                        assert!(recovery_result.contains("outcome=unknown\n"));
                        assert!(recovery_result.contains("payload=absent\n"));
                    }
                    "after-0x0d-apply" => {
                        assert!(recovery_result.contains("outcome=unknown\n"));
                        assert!(recovery_result.contains("payload=durable\n"));
                    }
                    "manifest-applied-before-response" | "after-manifest-publish" => {
                        assert!(recovery_result.contains("outcome=materialized\n"));
                        assert!(recovery_result.contains("included_write_sequence=1\n"));
                        assert!(recovery_result.contains("payload=durable\n"));
                        assert!(recovery_result.contains(&format!(
                            "receipt_digest={}\n",
                            handshake["receipt_digest"]
                        )));
                    }
                    _ => unreachable!(),
                }
            }
            assert_inventory_bound(&base_store, 512, 64 * 1024 * 1024).await;
        })
        .catch_unwind()
        .await;

        for object in listed_objects(&base_store).await {
            base_store.delete(&object).await.unwrap();
        }
        assert!(
            listed_objects(&base_store).await.is_empty(),
            "Foundation fault prefix must be empty after exact cleanup"
        );
        let mut names = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .into_string()
                    .expect("artifact names are UTF-8")
            })
            .collect::<Vec<_>>();
        names.sort();
        let mut expected = FOUNDATION_FAULT_SCENARIOS
            .iter()
            .flat_map(|scenario| {
                [
                    format!("{scenario}.context"),
                    format!("{scenario}.claim"),
                    format!("{scenario}.handshake"),
                    format!("{scenario}.exit"),
                    format!("{scenario}.recovery"),
                ]
            })
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(names, expected);
        if let Err(payload) = run {
            std::panic::resume_unwind(payload);
        }
    }

    /// Explicitly invoked against the retained Foundation RustFS endpoint.
    /// This is a clean-close/cold-reopen smoke, not a SIGKILL or response-loss
    /// qualification. Credentials remain in the object_store standard AWS
    /// environment chain and are never printed.
    #[ignore = "requires an explicitly configured isolated S3/RustFS prefix"]
    #[tokio::test]
    async fn foundation_rustfs_clean_reopen_smoke() {
        let bucket = std::env::var("RHIZOME_BARRIER_S3_BUCKET").unwrap();
        let prefix = std::env::var("RHIZOME_BARRIER_S3_PREFIX").unwrap();
        validate_conformance_prefix(&prefix);
        let raw = slatedb::object_store::aws::AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .with_virtual_hosted_style_request(false)
            .build()
            .unwrap();
        let prefixed: Arc<dyn ObjectStore> = Arc::new(
            slatedb::object_store::prefix::PrefixStore::new(raw, Path::from(prefix.clone())),
        );
        assert!(
            listed_objects(&prefixed).await.is_empty(),
            "conformance prefix must be empty before the run"
        );

        let fs = open_persistent(prefixed.clone()).await;
        let (fs, token, genesis) = initialize_active(fs).await;
        let payload = Bytes::from_static(b"rhizome-foundation-rustfs-export-data");
        let mutation_store = fs.export_authority.clone();
        let mutation_token = token.clone();
        let mutation_payload = payload.clone();
        fs.workspace_barriers
            .dst_set_after_claim_hook(Arc::new(move |_, _| {
                let store = mutation_store.clone();
                let token = mutation_token.clone();
                let payload = mutation_payload.clone();
                Box::pin(async move {
                    let mutation = store
                        .commit_mutation(
                            ExportMutationBuilder::build(
                                token,
                                [0x53; 32],
                                ExportMutationCommand::Write {
                                    offset: 0,
                                    data: payload,
                                    fua: false,
                                },
                            )
                            .map_err(|_| BarrierError::Invalid)?,
                        )
                        .await
                        .map_err(|_| BarrierError::Storage)?;
                    if mutation.mutation.sequence != 1 {
                        return Err(BarrierError::Corrupt);
                    }
                    Ok(())
                })
            }));
        let command = command(
            "barrier-foundation-rustfs",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        let receipt = materialize(&fs, command.clone()).await;
        assert_eq!(receipt.included_write_sequence, 1);
        complete_barrier(&fs, command.clone(), receipt.clone()).await;
        fs.flush_coordinator.close().await.unwrap();
        drop(fs);

        let reopened = open_persistent(prefixed.clone()).await;
        assert_eq!(
            reopened
                .workspace_barriers
                .lookup_materialized(&command)
                .await
                .unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            reopened
                .extent_store
                .read(genesis.export.inode, 0, payload.len() as u64)
                .await
                .unwrap(),
            payload
        );
        reopened.flush_coordinator.close().await.unwrap();
        drop(reopened);

        println!(
            "RHIZOME_BARRIER_SMOKE prefix={} writer_epoch={} manifest_id={} durable_sequence={} included_write_sequence={} workspace_version={} head_digest={} receipt_digest={}",
            prefix,
            receipt.zerofs_writer_epoch,
            receipt.zerofs_manifest_id,
            receipt.zerofs_durable_sequence,
            receipt.included_write_sequence,
            receipt.head.workspace_version,
            lower_hex(&head_digest(&receipt.head).0),
            lower_hex(&receipt.receipt_digest),
        );

        for object in listed_objects(&prefixed).await {
            prefixed.delete(&object).await.unwrap();
        }
        assert!(
            listed_objects(&prefixed).await.is_empty(),
            "conformance prefix must be empty after exact cleanup"
        );
    }

    #[tokio::test]
    async fn caller_cancellation_does_not_release_barrier_admission_early() {
        let (fs, token, genesis) = active_workspace().await;
        let command = command(
            "barrier-cancelled-caller",
            &token,
            head_digest(&initial_head(&genesis).head),
        );
        fs.write_coordinator.dst_pause_next_barrier_after_cut();
        let barrier_fs = fs.clone();
        let barrier = tokio::spawn(async move {
            barrier_fs
                .workspace_barriers
                .materialize(VerifiedBarrierInput::for_test(command).unwrap())
                .await
        });
        fs.write_coordinator.dst_wait_barrier_after_cut().await;
        barrier.abort();
        assert!(barrier.await.unwrap_err().is_cancelled());

        let deactivate_fs = fs.clone();
        let deactivate_token = token.clone();
        let mut deactivate = tokio::spawn(async move {
            deactivate_fs
                .export_authority
                .deactivate(DeactivateExport {
                    workspace_id: deactivate_token.workspace_id,
                    expected_export: deactivate_token.export,
                    expected_authority: deactivate_token.authority,
                    session_id: deactivate_token.session_id,
                })
                .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut deactivate)
                .await
                .is_err(),
            "deactivate must wait for the coordinator-owned barrier guard"
        );
        fs.write_coordinator.dst_release_barrier_after_cut();
        let deactivated = deactivate.await.unwrap().unwrap();
        assert!(deactivated.active_session.is_none());
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn failpoint_after_data_cut_never_reflushes_claimed_operation() {
        crate::test_helpers::isolated_failpoint::run(
            "fs::workspace_barrier::tests::failpoint_after_data_cut_never_reflushes_claimed_operation",
            crate::test_helpers::isolated_failpoint::Runtime::CurrentThread,
            || async {
                let (fs, token, genesis) = active_workspace().await;
                let command = command(
                    "barrier-fp-cut",
                    &token,
                    head_digest(&initial_head(&genesis).head),
                );
                let armed = crate::test_helpers::isolated_failpoint::arm(
                    crate::failpoints::WORKSPACE_BARRIER_AFTER_DATA_CUT_BEFORE_PUBLISH,
                    "return",
                );
                assert_eq!(
                    fs.workspace_barriers
                        .materialize(VerifiedBarrierInput::for_test(command.clone()).unwrap())
                        .await,
                    Err(BarrierError::CommitOutcomeUnknown)
                );
                drop(armed);
                let completed = fs.flush_coordinator.completed_flush_count();
                assert_eq!(
                    fs.workspace_barriers
                        .materialize(VerifiedBarrierInput::for_test(command).unwrap())
                        .await,
                    Err(BarrierError::CommitOutcomeUnknown)
                );
                assert_eq!(fs.flush_coordinator.completed_flush_count(), completed);
            },
        );
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn failpoint_after_publish_converges_by_exact_readback() {
        crate::test_helpers::isolated_failpoint::run(
            "fs::workspace_barrier::tests::failpoint_after_publish_converges_by_exact_readback",
            crate::test_helpers::isolated_failpoint::Runtime::CurrentThread,
            || async {
                let (fs, token, genesis) = active_workspace().await;
                let command = command(
                    "barrier-fp-publish",
                    &token,
                    head_digest(&initial_head(&genesis).head),
                );
                let armed = crate::test_helpers::isolated_failpoint::arm(
                    crate::failpoints::WORKSPACE_BARRIER_AFTER_PUBLISH_BEFORE_REPLY,
                    "return",
                );
                let receipt = materialize(&fs, command.clone()).await;
                drop(armed);
                assert_eq!(
                    fs.workspace_barriers
                        .lookup_materialized(&command)
                        .await
                        .unwrap(),
                    Some(receipt)
                );
            },
        );
    }
}
