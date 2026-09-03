//! Non-default, protocol-neutral Workspace genesis mechanics.
//!
//! This module consumes only sealed, already-verified inputs. It deliberately
//! has no production constructor for that seal until Rhizome's canonical CDDL,
//! dual-language fixtures, capability verifier, and receipt signer are wired.
//! The durable operation lifecycle remains the existing 0x0A ledger; 0x0C is
//! only the immutable domain result of the genesis effect.

use crate::db::Db;
use crate::fs::export_authority::{
    ExportIdentity, ExportReverseBinding, encode_reverse_binding, reverse_binding_keys,
};
use crate::fs::key_codec::KeyCodec;
use crate::fs::workspace_operation::{
    CanonicalRequestDigest, WorkspaceOperationError, WorkspaceOperationKey,
    WorkspaceOperationLookup, WorkspaceOperationRecord, WorkspaceOperationState,
    WorkspaceTerminalOutcome,
};
use crate::fs::write_coordinator::WriteCoordinator;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use slatedb::object_store::{ObjectStore, PutMode, PutOptions, PutPayload, path::Path};
use std::sync::Arc;

const KEY_VERSION: u8 = 1;
const RECORD_MAGIC: &[u8; 4] = b"RWGN";
const RECORD_VERSION: u8 = 1;
const SHA256_SIZE: usize = 32;
const MAX_ID_BYTES: usize = 1024;
const MAX_OBJECT_KEY_BYTES: usize = 4096;
const RECORD_CHECKSUM_DOMAIN: &[u8] = b"rhizome.workspace-genesis-record.v1\0";
const ROOT_OBJECT_PREFIX: &str = "rhizome/workspace-genesis/sha256/";

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
    pub export_name: Vec<u8>,
    pub advertised_size: u64,
    pub root_digest: ContentDigest,
    pub root_bytes: Bytes,
}

/// Type-state proof that the caller passed the canonical command through the
/// external Rhizome verifier. Production construction intentionally does not
/// exist in this candidate.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedGenesisInput(GenesisCommand);

impl VerifiedGenesisInput {
    #[cfg(any(test, dst))]
    pub(crate) fn for_test(command: GenesisCommand) -> Result<Self, GenesisError> {
        validate_command(&command)?;
        Ok(Self(command))
    }

    fn command(&self) -> &GenesisCommand {
        &self.0
    }
}

/// Exact signed terminal bytes produced outside this crate. Like the command
/// seal, this has no production constructor until the normative signer exists.
pub(crate) struct VerifiedGenesisTerminal {
    bytes: Bytes,
}

impl VerifiedGenesisTerminal {
    #[cfg(any(test, dst))]
    pub(crate) fn for_test(bytes: Bytes) -> Result<Self, GenesisError> {
        if bytes.is_empty() {
            return Err(GenesisError::Invalid);
        }
        Ok(Self { bytes })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisDomainRecord {
    pub workspace_id: String,
    pub actor: String,
    pub actor_generation: u64,
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
    Materialized(GenesisDurabilityReceipt),
    AlreadyTerminal(WorkspaceOperationRecord),
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
    object_store: Arc<dyn ObjectStore>,
}

impl WorkspaceGenesisStore {
    pub(crate) fn new(
        db: Arc<Db>,
        coordinator: WriteCoordinator,
        operations: crate::fs::workspace_operation::WorkspaceOperationLedger,
        object_store: Arc<dyn ObjectStore>,
    ) -> Self {
        Self {
            db,
            coordinator,
            operations,
            object_store,
        }
    }

    pub(crate) async fn materialize(
        &self,
        verified: VerifiedGenesisInput,
    ) -> Result<GenesisMaterializeResult, GenesisError> {
        let command = verified.command();
        validate_command(command)?;
        let operation = self
            .operations
            .begin(&command.operation, command.request_digest)
            .await?;
        if operation.state.is_terminal() {
            return Ok(GenesisMaterializeResult::AlreadyTerminal(operation));
        }

        let object_key = content_object_key(command.root_digest);
        put_content_addressed_exact(
            &self.object_store,
            &object_key,
            command.root_digest,
            &command.root_bytes,
        )
        .await?;

        let record = GenesisDomainRecord {
            workspace_id: command.operation.workspace_id.clone(),
            actor: command.actor.clone(),
            actor_generation: command.actor_generation,
            request_digest: command.request_digest,
            root_digest: command.root_digest,
            root_object_key: object_key,
            export: ExportIdentity {
                nbd_directory_inode: 0,
                name: command.export_name.clone(),
                inode: 0,
                advertised_size: command.advertised_size,
            },
        };
        let receipt = self
            .coordinator
            .materialize_workspace_genesis(record)
            .await?;
        Ok(GenesisMaterializeResult::Materialized(receipt))
    }

    pub(crate) async fn complete(
        &self,
        verified: &VerifiedGenesisInput,
        terminal: VerifiedGenesisTerminal,
    ) -> Result<WorkspaceOperationLookup, GenesisError> {
        let command = verified.command();
        self.operations
            .complete(
                &command.operation,
                command.request_digest,
                WorkspaceTerminalOutcome::Succeeded(terminal.bytes),
            )
            .await
            .map_err(Into::into)
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
    actor: &str,
    actor_generation: u64,
    export: &ExportIdentity,
) -> Result<(), GenesisError> {
    if record.workspace_id == workspace_id
        && record.actor == actor
        && record.actor_generation == actor_generation
        && record.export == *export
    {
        Ok(())
    } else {
        Err(GenesisError::Conflict)
    }
}

pub(super) fn encode_record(
    key: &[u8],
    record: &GenesisDomainRecord,
) -> Result<Bytes, GenesisError> {
    validate_record(record)?;
    let mut payload = Vec::new();
    push_string(&mut payload, &record.workspace_id)?;
    push_string(&mut payload, &record.actor)?;
    payload.extend_from_slice(&record.actor_generation.to_be_bytes());
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
    let actor = take_string(&mut input, MAX_ID_BYTES)?;
    let actor_generation = take_u64(&mut input)?;
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
        actor,
        actor_generation,
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

fn validate_command(command: &GenesisCommand) -> Result<(), GenesisError> {
    validate_id(&command.operation.workspace_id)?;
    validate_id(&command.operation.request_id)?;
    validate_id(&command.actor)?;
    if command.operation.kind <= 0
        || command.actor_generation == 0
        || command.export_name.is_empty()
        || command.export_name.len() > crate::fs::NAME_MAX
        || command.export_name == b"."
        || command.export_name == b".."
        || command.advertised_size == 0
        || command.advertised_size % 512 != 0
        || command.root_bytes.is_empty()
        || Sha256::digest(&command.root_bytes).as_slice() != command.root_digest.as_bytes()
    {
        return Err(GenesisError::Invalid);
    }
    Ok(())
}

fn validate_record(record: &GenesisDomainRecord) -> Result<(), GenesisError> {
    validate_id(&record.workspace_id)?;
    validate_id(&record.actor)?;
    if record.actor_generation == 0
        || record.export.nbd_directory_inode == 0
        || record.export.inode == 0
        || record.export.name.is_empty()
        || record.export.name.len() > crate::fs::NAME_MAX
        || record.export.advertised_size == 0
        || record.export.advertised_size % 512 != 0
        || record.root_object_key != content_object_key(record.root_digest)
    {
        return Err(GenesisError::Invalid);
    }
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

async fn put_content_addressed_exact(
    store: &Arc<dyn ObjectStore>,
    object_key: &str,
    digest: ContentDigest,
    bytes: &Bytes,
) -> Result<(), GenesisError> {
    let path = Path::from(object_key);
    let put = store
        .put_opts(
            &path,
            PutPayload::from(bytes.clone()),
            PutOptions::from(PutMode::Create),
        )
        .await;
    match put {
        Ok(_) | Err(slatedb::object_store::Error::AlreadyExists { .. }) => {}
        Err(_) => {
            // Unknown create outcomes converge only through exact-key readback.
        }
    }
    let read = store
        .get(&path)
        .await
        .map_err(|_| GenesisError::ObjectOutcomeUnknown)?
        .bytes()
        .await
        .map_err(|_| GenesisError::ObjectOutcomeUnknown)?;
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

pub(super) fn encoded_reverse_bindings(
    record: &GenesisDomainRecord,
) -> Result<((Bytes, Bytes), (Bytes, Bytes)), GenesisError> {
    let binding = reverse_binding(record);
    let (name_key, inode_key) = reverse_binding_keys(&binding);
    let name_value =
        encode_reverse_binding(&binding, &name_key).map_err(|_| GenesisError::Corrupt)?;
    let inode_value =
        encode_reverse_binding(&binding, &inode_key).map_err(|_| GenesisError::Corrupt)?;
    Ok(((name_key, name_value), (inode_key, inode_value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::ZeroFS;
    use crate::fs::export_authority::{
        ActivateExport, AuthorityVersion, ExportSessionState, ShardProcessGuard,
    };

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

    fn verified(workspace: &str, request: &str, root: &'static [u8]) -> VerifiedGenesisInput {
        let root_bytes = Bytes::from_static(root);
        VerifiedGenesisInput::for_test(GenesisCommand {
            operation: WorkspaceOperationKey::new(workspace, 101, request),
            request_digest: CanonicalRequestDigest::new(Sha256::digest(request).into()),
            actor: format!("tenants/t/actors/{workspace}"),
            actor_generation: 7,
            export_name: format!("{workspace}.img").into_bytes(),
            advertised_size: 4096,
            root_digest: ContentDigest::new(Sha256::digest(&root_bytes).into()),
            root_bytes,
        })
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

        let terminal =
            VerifiedGenesisTerminal::for_test(Bytes::from_static(b"signed-receipt")).unwrap();
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
        fs.workspace_operations
            .begin(&input.command().operation, input.command().request_digest)
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
    async fn invalid_physical_precondition_leaves_no_genesis_domain_record() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let input = verified("workspace-a", "request-a", b"root-a");
        assert_eq!(
            fs.workspace_genesis.materialize(input).await,
            Err(GenesisError::Invalid)
        );
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
            object_store: fault,
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
    async fn unavailable_exact_get_keeps_physical_genesis_absent() {
        let fs = new_fs().await;
        let inner: Arc<dyn ObjectStore> = Arc::new(slatedb::object_store::memory::InMemory::new());
        let (fault, controls) = crate::fault_store::FaultStore::new(inner);
        controls.fail_gets(1);
        let store = WorkspaceGenesisStore {
            db: fs.workspace_genesis.db.clone(),
            coordinator: fs.workspace_genesis.coordinator.clone(),
            operations: fs.workspace_genesis.operations.clone(),
            object_store: fault,
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
    async fn activation_gate_requires_exact_genesis_binding() {
        let fs = new_fs().await;
        let input = verified("workspace-a", "request-a", b"root-a");
        let GenesisMaterializeResult::Materialized(receipt) =
            fs.workspace_genesis.materialize(input).await.unwrap()
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
            actor: "actor-a".into(),
            actor_generation: 1,
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
}
