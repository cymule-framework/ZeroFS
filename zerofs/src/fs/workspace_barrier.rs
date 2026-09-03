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
}

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
        }
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
    use slatedb::object_store::{ObjectStore, path::Path};
    use slatedb::{BlockTransformer, DbBuilder};

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
        let db = Arc::new(
            DbBuilder::new(Path::from("workspace-barrier-reopen"), object_store.clone())
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
        ZeroFS::new_with_slatedb(
            SlateDbHandle::ReadWrite(db),
            u64::MAX,
            None,
            false,
            object_store,
            segment_codec,
        )
        .await
        .unwrap()
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
