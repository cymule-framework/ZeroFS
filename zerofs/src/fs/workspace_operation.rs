//! Durable idempotency ledger for Rhizome Workspace control operations.
//!
//! The ledger stores opaque, already-canonical request digests and exact signed
//! outcome bytes. It does not validate capabilities, sign receipts, or execute
//! Workspace effects. Every mutation is serialized with other ledger mutations
//! and committed through the filesystem's sole [`WriteCoordinator`].

use crate::db::{Db, Transaction};
#[cfg(feature = "failpoints")]
use crate::failpoints::{self as fp, fail_point};
use crate::fs::errors::FsError;
use crate::fs::key_codec::KeyCodec;
use crate::fs::write_coordinator::WriteCoordinator;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const KEY_VERSION: u8 = 1;
const VALUE_MAGIC: &[u8; 4] = b"RWOP";
const VALUE_VERSION: u8 = 1;
const DIGEST_SIZE: usize = 32;
const RECORD_CHECKSUM_DOMAIN: &[u8] = b"rhizome.workspace-operation-record.v1\0";
const VALUE_HEADER_SIZE: usize = VALUE_MAGIC.len() + 1 + DIGEST_SIZE + DIGEST_SIZE + 1 + 4;

/// Exact canonical SHA-256 request digest supplied by the Rhizome command codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalRequestDigest([u8; DIGEST_SIZE]);

impl CanonicalRequestDigest {
    pub const fn new(bytes: [u8; DIGEST_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_SIZE] {
        &self.0
    }
}

/// Durable scope for one operation ID. `kind` is the non-zero protobuf enum
/// number; keeping it numeric avoids coupling this storage primitive to tonic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceOperationKey {
    pub workspace_id: String,
    pub kind: i32,
    pub request_id: String,
}

impl WorkspaceOperationKey {
    pub fn new(workspace_id: impl Into<String>, kind: i32, request_id: impl Into<String>) -> Self {
        Self {
            workspace_id: workspace_id.into(),
            kind,
            request_id: request_id.into(),
        }
    }
}

/// Exact terminal bytes. The success payload is the response/receipt bytes;
/// negative payloads are the complete signed-negative receipt bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceTerminalOutcome {
    Succeeded(Bytes),
    Failed(Bytes),
    NotCommitted(Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceOperationState {
    Pending,
    /// One immutable, domain-specific effect-dispatch claim. The exact bytes
    /// identify the only mutation attempt authorized for this operation.
    EffectDispatched(Bytes),
    Succeeded(Bytes),
    Failed(Bytes),
    NotCommitted(Bytes),
}

impl WorkspaceOperationState {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending | Self::EffectDispatched(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EffectDispatchClaim {
    Installed(WorkspaceOperationRecord),
    Existing(WorkspaceOperationRecord),
}

impl From<WorkspaceTerminalOutcome> for WorkspaceOperationState {
    fn from(value: WorkspaceTerminalOutcome) -> Self {
        match value {
            WorkspaceTerminalOutcome::Succeeded(bytes) => Self::Succeeded(bytes),
            WorkspaceTerminalOutcome::Failed(bytes) => Self::Failed(bytes),
            WorkspaceTerminalOutcome::NotCommitted(bytes) => Self::NotCommitted(bytes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceOperationRecord {
    pub request_digest: CanonicalRequestDigest,
    pub state: WorkspaceOperationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceOperationLookup {
    /// No conclusive positive intent or terminal proof is durable.
    Unknown,
    Known(WorkspaceOperationRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceOperationError {
    #[error("workspace operation identity is invalid: {0}")]
    InvalidIdentity(&'static str),
    #[error("workspace operation request digest conflicts with the durable digest")]
    RequestConflict,
    #[error("workspace operation terminal outcome is immutable")]
    TerminalImmutable,
    #[error("workspace operation record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("workspace operation commit outcome is unknown; read the ledger")]
    CommitOutcomeUnknown,
    #[error("workspace operation storage failed: {0}")]
    Storage(FsError),
}

impl From<FsError> for WorkspaceOperationError {
    fn from(value: FsError) -> Self {
        match value {
            FsError::CommitOutcomeUnknown => Self::CommitOutcomeUnknown,
            other => Self::Storage(other),
        }
    }
}

#[derive(Clone)]
pub struct WorkspaceOperationLedger {
    db: Arc<Db>,
    key_codec: KeyCodec,
    write_coordinator: WriteCoordinator,
    #[cfg(any(test, dst))]
    lose_next_commit_reply: Arc<std::sync::atomic::AtomicBool>,
}

/// Unforgeable request carried by the coordinator's Workspace-ledger variant.
///
/// The fields and constructors are private to this module. Other crate modules
/// can pass the type through the commit worker, but cannot manufacture an
/// authorized raw transaction for the reserved keyspace.
pub(super) struct WorkspaceLedgerRequest {
    mutation: Option<(Bytes, Bytes)>,
}

impl WorkspaceLedgerRequest {
    fn put(key: &Bytes, value: Bytes) -> Self {
        debug_assert!(crate::fs::key_codec::is_reserved_mutation_key(key));
        Self {
            mutation: Some((key.clone(), value)),
        }
    }

    fn durability_barrier() -> Self {
        Self { mutation: None }
    }

    pub(super) fn into_transaction(self) -> Transaction {
        let mut txn = Transaction::new();
        if let Some((key, value)) = self.mutation {
            txn.put_bytes(&key, value);
        }
        txn
    }
}

impl WorkspaceOperationLedger {
    pub(crate) fn new(db: Arc<Db>, write_coordinator: WriteCoordinator) -> Self {
        Self {
            db,
            key_codec: KeyCodec::new(),
            write_coordinator,
            #[cfg(any(test, dst))]
            lose_next_commit_reply: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Arm one instance-local ambiguous-response hook for deterministic tests.
    #[cfg(any(test, dst))]
    #[doc(hidden)]
    pub fn dst_lose_next_commit_reply(&self) {
        self.lose_next_commit_reply
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Create a durable PENDING intent or replay the exact durable record.
    pub async fn begin(
        &self,
        key: &WorkspaceOperationKey,
        request_digest: CanonicalRequestDigest,
    ) -> Result<WorkspaceOperationRecord, WorkspaceOperationError> {
        let encoded_key = self.encode_key(key)?;
        let (existing, guard) = self.read_durable_current(&encoded_key).await?;

        if let Some(existing) = existing {
            ensure_digest(&existing, request_digest)?;
            return Ok(existing);
        }

        let record = WorkspaceOperationRecord {
            request_digest,
            state: WorkspaceOperationState::Pending,
        };
        self.commit_record(&encoded_key, &record, guard).await?;
        self.maybe_lose_commit_reply()?;
        Ok(record)
    }

    /// Atomically replace PENDING with one terminal outcome. A terminal record
    /// can only replay byte-for-byte; it can never be rewritten.
    pub async fn complete(
        &self,
        key: &WorkspaceOperationKey,
        request_digest: CanonicalRequestDigest,
        outcome: WorkspaceTerminalOutcome,
    ) -> Result<WorkspaceOperationLookup, WorkspaceOperationError> {
        let encoded_key = self.encode_key(key)?;
        let desired = WorkspaceOperationRecord {
            request_digest,
            state: outcome.into(),
        };
        validate_record(&desired)?;
        let (existing, guard) = self.read_durable_current(&encoded_key).await?;

        let Some(existing) = existing else {
            return Ok(WorkspaceOperationLookup::Unknown);
        };
        ensure_digest(&existing, request_digest)?;
        if matches!(existing.state, WorkspaceOperationState::EffectDispatched(_)) {
            return Err(WorkspaceOperationError::TerminalImmutable);
        }
        if existing.state.is_terminal() {
            return if existing == desired {
                Ok(WorkspaceOperationLookup::Known(existing))
            } else {
                Err(WorkspaceOperationError::TerminalImmutable)
            };
        }

        self.commit_record(&encoded_key, &desired, guard).await?;
        self.maybe_lose_commit_reply()?;
        Ok(WorkspaceOperationLookup::Known(desired))
    }

    /// Complete an externally claimed effect. The claim bytes are the durable
    /// handoff identity; only the typed domain owner may use this path after
    /// validating its effect receipt.
    pub(super) async fn complete_claimed_effect(
        &self,
        key: &WorkspaceOperationKey,
        request_digest: CanonicalRequestDigest,
        exact_claim: &Bytes,
        outcome: WorkspaceTerminalOutcome,
    ) -> Result<WorkspaceOperationLookup, WorkspaceOperationError> {
        let encoded_key = self.encode_key(key)?;
        let desired = WorkspaceOperationRecord {
            request_digest,
            state: outcome.into(),
        };
        validate_record(&desired)?;
        let (existing, guard) = self.read_durable_current(&encoded_key).await?;
        let Some(existing) = existing else {
            return Ok(WorkspaceOperationLookup::Unknown);
        };
        ensure_digest(&existing, request_digest)?;
        match &existing.state {
            WorkspaceOperationState::EffectDispatched(current) if current == exact_claim => {
                self.commit_record(&encoded_key, &desired, guard).await?;
                self.maybe_lose_commit_reply()?;
                Ok(WorkspaceOperationLookup::Known(desired))
            }
            WorkspaceOperationState::EffectDispatched(_) => {
                Err(WorkspaceOperationError::RequestConflict)
            }
            state if state.is_terminal() => {
                if existing == desired {
                    Ok(WorkspaceOperationLookup::Known(existing))
                } else {
                    Err(WorkspaceOperationError::TerminalImmutable)
                }
            }
            WorkspaceOperationState::Pending => Err(WorkspaceOperationError::TerminalImmutable),
            WorkspaceOperationState::Succeeded(_)
            | WorkspaceOperationState::Failed(_)
            | WorkspaceOperationState::NotCommitted(_) => unreachable!(),
        }
    }

    /// Durably authorize exactly one external mutation attempt. Only the call
    /// that installs the claim may dispatch; replay may perform readback only.
    pub(crate) async fn claim_effect_dispatch(
        &self,
        key: &WorkspaceOperationKey,
        request_digest: CanonicalRequestDigest,
        exact_claim: Bytes,
    ) -> Result<EffectDispatchClaim, WorkspaceOperationError> {
        if exact_claim.is_empty() {
            return Err(WorkspaceOperationError::CorruptRecord(
                "effect dispatch claim is empty",
            ));
        }
        let encoded_key = self.encode_key(key)?;
        let desired = WorkspaceOperationRecord {
            request_digest,
            state: WorkspaceOperationState::EffectDispatched(exact_claim),
        };
        validate_record(&desired)?;
        let (existing, guard) = self.read_durable_current(&encoded_key).await?;
        let Some(existing) = existing else {
            return Err(WorkspaceOperationError::CorruptRecord(
                "effect dispatch requires a pending operation",
            ));
        };
        ensure_digest(&existing, request_digest)?;
        match &existing.state {
            WorkspaceOperationState::Pending => {
                self.commit_record(&encoded_key, &desired, guard).await?;
                self.maybe_lose_commit_reply()?;
                Ok(EffectDispatchClaim::Installed(desired))
            }
            WorkspaceOperationState::EffectDispatched(bytes)
                if bytes
                    == match &desired.state {
                        WorkspaceOperationState::EffectDispatched(bytes) => bytes,
                        _ => unreachable!(),
                    } =>
            {
                Ok(EffectDispatchClaim::Existing(existing))
            }
            WorkspaceOperationState::EffectDispatched(_) => {
                Err(WorkspaceOperationError::RequestConflict)
            }
            _ => Ok(EffectDispatchClaim::Existing(existing)),
        }
    }

    /// Read only object-store-durable state. Absence is UNKNOWN; this primitive
    /// never manufactures a NOT_COMMITTED proof.
    pub async fn lookup(
        &self,
        key: &WorkspaceOperationKey,
        request_digest: CanonicalRequestDigest,
    ) -> Result<WorkspaceOperationLookup, WorkspaceOperationError> {
        let encoded_key = self.encode_key(key)?;
        match self.read_record_durable(&encoded_key).await? {
            Some(record) => {
                ensure_digest(&record, request_digest)?;
                Ok(WorkspaceOperationLookup::Known(record))
            }
            None => Ok(WorkspaceOperationLookup::Unknown),
        }
    }

    fn encode_key(&self, key: &WorkspaceOperationKey) -> Result<Bytes, WorkspaceOperationError> {
        validate_identity("workspace_id", &key.workspace_id)?;
        validate_identity("request_id", &key.request_id)?;
        if key.kind <= 0 {
            return Err(WorkspaceOperationError::InvalidIdentity(
                "operation kind must be positive",
            ));
        }
        Ok(self.key_codec.workspace_operation_key(
            KEY_VERSION,
            key.workspace_id.as_bytes(),
            key.kind,
            key.request_id.as_bytes(),
        ))
    }

    async fn read_record_current(
        &self,
        key: &Bytes,
    ) -> Result<Option<WorkspaceOperationRecord>, WorkspaceOperationError> {
        let raw = self
            .db
            .get_bytes(key)
            .await
            .map_err(|error| FsError::from_db_error(&error))?;
        raw.map(|bytes| decode_record(key, &bytes)).transpose()
    }

    async fn read_record_durable(
        &self,
        key: &Bytes,
    ) -> Result<Option<WorkspaceOperationRecord>, WorkspaceOperationError> {
        let raw = self
            .db
            .get_bytes_durable(key)
            .await
            .map_err(|error| FsError::from_db_error(&error))?;
        raw.map(|bytes| decode_record(key, &bytes)).transpose()
    }

    async fn commit_record(
        &self,
        key: &Bytes,
        record: &WorkspaceOperationRecord,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<(), WorkspaceOperationError> {
        let value = encode_record(key, record)?;
        self.write_coordinator
            .commit_workspace_durable(WorkspaceLedgerRequest::put(key, value), guard)
            .await?;
        Ok(())
    }

    async fn read_durable_current(
        &self,
        key: &Bytes,
    ) -> Result<
        (
            Option<WorkspaceOperationRecord>,
            tokio::sync::OwnedMutexGuard<()>,
        ),
        WorkspaceOperationError,
    > {
        loop {
            let guard = self.write_coordinator.lock_workspace_ledger().await;
            let current = self.read_record_current(key).await?;
            if current.is_none() || self.read_record_durable(key).await? == current {
                return Ok((current, guard));
            }
            self.write_coordinator
                .commit_workspace_durable(WorkspaceLedgerRequest::durability_barrier(), guard)
                .await?;
            // The queued request owned the guard through its durability barrier.
            // Reacquire and reread because another caller may have advanced the
            // record after that request completed.
        }
    }

    fn maybe_lose_commit_reply(&self) -> Result<(), WorkspaceOperationError> {
        #[cfg(feature = "failpoints")]
        fail_point!(fp::WORKSPACE_OPERATION_AFTER_COMMIT_BEFORE_REPLY, |_| {
            Err(WorkspaceOperationError::CommitOutcomeUnknown)
        });
        #[cfg(any(test, dst))]
        if self
            .lose_next_commit_reply
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(WorkspaceOperationError::CommitOutcomeUnknown);
        }
        Ok(())
    }
}

fn validate_identity(field: &'static str, value: &str) -> Result<(), WorkspaceOperationError> {
    if value.is_empty() {
        return Err(WorkspaceOperationError::InvalidIdentity(match field {
            "workspace_id" => "workspace_id must not be empty",
            _ => "request_id must not be empty",
        }));
    }
    if value.len() > u16::MAX as usize {
        return Err(WorkspaceOperationError::InvalidIdentity(match field {
            "workspace_id" => "workspace_id is too long",
            _ => "request_id is too long",
        }));
    }
    Ok(())
}

fn ensure_digest(
    record: &WorkspaceOperationRecord,
    expected: CanonicalRequestDigest,
) -> Result<(), WorkspaceOperationError> {
    if record.request_digest == expected {
        Ok(())
    } else {
        Err(WorkspaceOperationError::RequestConflict)
    }
}

fn validate_record(record: &WorkspaceOperationRecord) -> Result<(), WorkspaceOperationError> {
    match &record.state {
        WorkspaceOperationState::Pending => Ok(()),
        WorkspaceOperationState::EffectDispatched(bytes) if bytes.is_empty() => Err(
            WorkspaceOperationError::CorruptRecord("effect dispatch claim is empty"),
        ),
        WorkspaceOperationState::EffectDispatched(_) => Ok(()),
        WorkspaceOperationState::Succeeded(bytes)
        | WorkspaceOperationState::Failed(bytes)
        | WorkspaceOperationState::NotCommitted(bytes)
            if bytes.is_empty() =>
        {
            Err(WorkspaceOperationError::CorruptRecord(
                "terminal payload is empty",
            ))
        }
        WorkspaceOperationState::Succeeded(_)
        | WorkspaceOperationState::Failed(_)
        | WorkspaceOperationState::NotCommitted(_) => Ok(()),
    }
}

fn encode_record(
    key: &Bytes,
    record: &WorkspaceOperationRecord,
) -> Result<Bytes, WorkspaceOperationError> {
    validate_record(record)?;
    let (state, payload) = match &record.state {
        WorkspaceOperationState::Pending => (1, Bytes::new()),
        WorkspaceOperationState::Succeeded(bytes) => (2, bytes.clone()),
        WorkspaceOperationState::Failed(bytes) => (3, bytes.clone()),
        WorkspaceOperationState::NotCommitted(bytes) => (4, bytes.clone()),
        WorkspaceOperationState::EffectDispatched(bytes) => (5, bytes.clone()),
    };
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| WorkspaceOperationError::CorruptRecord("terminal payload is too large"))?;
    let mut encoded = Vec::with_capacity(VALUE_HEADER_SIZE + payload.len() + DIGEST_SIZE);
    encoded.extend_from_slice(VALUE_MAGIC);
    encoded.push(VALUE_VERSION);
    encoded.extend_from_slice(&Sha256::digest(key));
    encoded.extend_from_slice(record.request_digest.as_bytes());
    encoded.push(state);
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    encoded.extend_from_slice(&payload);
    let mut checksum = Sha256::new();
    checksum.update(RECORD_CHECKSUM_DOMAIN);
    checksum.update(&encoded);
    encoded.extend_from_slice(&checksum.finalize());
    Ok(Bytes::from(encoded))
}

fn decode_record(
    key: &Bytes,
    raw: &[u8],
) -> Result<WorkspaceOperationRecord, WorkspaceOperationError> {
    if raw.len() < VALUE_HEADER_SIZE + DIGEST_SIZE {
        return Err(WorkspaceOperationError::CorruptRecord(
            "record is shorter than its header",
        ));
    }
    if &raw[..VALUE_MAGIC.len()] != VALUE_MAGIC {
        return Err(WorkspaceOperationError::CorruptRecord(
            "record magic does not match",
        ));
    }
    if raw[VALUE_MAGIC.len()] != VALUE_VERSION {
        return Err(WorkspaceOperationError::CorruptRecord(
            "record version is unsupported",
        ));
    }
    let key_digest_start = VALUE_MAGIC.len() + 1;
    let key_digest_end = key_digest_start + DIGEST_SIZE;
    if raw[key_digest_start..key_digest_end] != Sha256::digest(key)[..] {
        return Err(WorkspaceOperationError::CorruptRecord(
            "record is bound to a different operation key",
        ));
    }
    let digest_start = key_digest_end;
    let digest_end = digest_start + DIGEST_SIZE;
    let digest = raw[digest_start..digest_end]
        .try_into()
        .expect("fixed-size digest slice");
    let state = raw[digest_end];
    let payload_len_start = digest_end + 1;
    let payload_len = u32::from_be_bytes(
        raw[payload_len_start..payload_len_start + 4]
            .try_into()
            .expect("fixed-size payload length slice"),
    ) as usize;
    let checksum_start = raw.len() - DIGEST_SIZE;
    let payload = &raw[VALUE_HEADER_SIZE..checksum_start];
    if payload.len() != payload_len {
        return Err(WorkspaceOperationError::CorruptRecord(
            "record payload length does not match",
        ));
    }
    let mut checksum = Sha256::new();
    checksum.update(RECORD_CHECKSUM_DOMAIN);
    checksum.update(&raw[..checksum_start]);
    if raw[checksum_start..] != checksum.finalize()[..] {
        return Err(WorkspaceOperationError::CorruptRecord(
            "record checksum does not match",
        ));
    }
    let state = match state {
        1 if payload.is_empty() => WorkspaceOperationState::Pending,
        1 => {
            return Err(WorkspaceOperationError::CorruptRecord(
                "pending record carries a terminal payload",
            ));
        }
        2 => WorkspaceOperationState::Succeeded(Bytes::copy_from_slice(payload)),
        3 => WorkspaceOperationState::Failed(Bytes::copy_from_slice(payload)),
        4 => WorkspaceOperationState::NotCommitted(Bytes::copy_from_slice(payload)),
        5 if !payload.is_empty() => {
            WorkspaceOperationState::EffectDispatched(Bytes::copy_from_slice(payload))
        }
        5 => {
            return Err(WorkspaceOperationError::CorruptRecord(
                "effect dispatch claim is empty",
            ));
        }
        _ => {
            return Err(WorkspaceOperationError::CorruptRecord(
                "record state is unsupported",
            ));
        }
    };
    let record = WorkspaceOperationRecord {
        request_digest: CanonicalRequestDigest::new(digest),
        state,
    };
    validate_record(&record)?;
    Ok(record)
}

pub(crate) async fn read_operation_durable(
    db: &Db,
    key: &WorkspaceOperationKey,
    request_digest: CanonicalRequestDigest,
) -> Result<WorkspaceOperationLookup, WorkspaceOperationError> {
    validate_identity("workspace_id", &key.workspace_id)?;
    validate_identity("request_id", &key.request_id)?;
    if key.kind <= 0 {
        return Err(WorkspaceOperationError::InvalidIdentity(
            "operation kind must be positive",
        ));
    }
    let encoded = KeyCodec::new().workspace_operation_key(
        KEY_VERSION,
        key.workspace_id.as_bytes(),
        key.kind,
        key.request_id.as_bytes(),
    );
    let Some(bytes) = db
        .get_bytes_durable(&encoded)
        .await
        .map_err(|error| FsError::from_db_error(&error))?
    else {
        return Ok(WorkspaceOperationLookup::Unknown);
    };
    let record = decode_record(&encoded, &bytes)?;
    ensure_digest(&record, request_digest)?;
    Ok(WorkspaceOperationLookup::Known(record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_transformer::ZeroFsBlockTransformer;
    use crate::config::CompressionConfig;
    use crate::db::SlateDbHandle;
    use crate::frame_codec::FrameCodec;
    use crate::fs::ZeroFS;
    use slatedb::BlockTransformer;
    use slatedb::DbBuilder;
    use slatedb::config::{PutOptions, WriteOptions};
    use slatedb::object_store::path::Path;

    async fn open_fs(
        object_store: Arc<dyn slatedb::object_store::ObjectStore>,
    ) -> anyhow::Result<ZeroFS> {
        let test_key = [0u8; 32];
        let block_transformer: Arc<dyn BlockTransformer> =
            ZeroFsBlockTransformer::try_new_arc(&test_key, CompressionConfig::default())?;
        let slatedb = Arc::new(
            DbBuilder::new(Path::from("workspace-ledger-reopen"), object_store.clone())
                .with_block_transformer(block_transformer)
                .with_filter_policies(crate::fs::filter_policy::filter_policies())
                .with_segment_extractor(Arc::new(crate::segment_extractor::ZeroFsSegmentExtractor))
                .build()
                .await?,
        );
        let segment_codec = FrameCodec::try_new(
            &test_key,
            crate::segment::SEGMENT_INFO,
            CompressionConfig::default(),
        )?;
        ZeroFS::new_with_slatedb(
            SlateDbHandle::ReadWrite(slatedb),
            u64::MAX,
            None,
            false,
            object_store,
            segment_codec,
        )
        .await
    }

    fn key() -> WorkspaceOperationKey {
        WorkspaceOperationKey::new("workspace-a", 10, "request-a")
    }

    fn digest(byte: u8) -> CanonicalRequestDigest {
        CanonicalRequestDigest::new([byte; DIGEST_SIZE])
    }

    #[tokio::test]
    async fn absence_is_unknown_and_complete_does_not_create_a_tombstone() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        assert_eq!(
            fs.workspace_operations
                .lookup(&key(), digest(1))
                .await
                .unwrap(),
            WorkspaceOperationLookup::Unknown
        );
        assert_eq!(
            fs.workspace_operations
                .complete(
                    &key(),
                    digest(1),
                    WorkspaceTerminalOutcome::NotCommitted(Bytes::from_static(b"signed")),
                )
                .await
                .unwrap(),
            WorkspaceOperationLookup::Unknown
        );
    }

    #[tokio::test]
    async fn concurrent_same_digest_replays_one_pending_record() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let flushes_before = fs.flush_coordinator.requested_flush_count();
        let ledger = fs.workspace_operations.clone();
        let first = tokio::spawn({
            let ledger = ledger.clone();
            async move { ledger.begin(&key(), digest(1)).await }
        });
        let second = tokio::spawn(async move { ledger.begin(&key(), digest(1)).await });
        let expected = WorkspaceOperationRecord {
            request_digest: digest(1),
            state: WorkspaceOperationState::Pending,
        };
        assert_eq!(first.await.unwrap().unwrap(), expected);
        assert_eq!(second.await.unwrap().unwrap(), expected);
        assert_eq!(
            fs.flush_coordinator.requested_flush_count(),
            flushes_before + 1,
            "the winning PENDING commit must be durable; replay must not flush again"
        );
    }

    #[tokio::test]
    async fn concurrent_different_digest_has_one_winner_and_one_conflict() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let ledger = fs.workspace_operations.clone();
        let first = tokio::spawn({
            let ledger = ledger.clone();
            async move { ledger.begin(&key(), digest(1)).await }
        });
        let second = tokio::spawn(async move { ledger.begin(&key(), digest(2)).await });
        let results = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(WorkspaceOperationError::RequestConflict))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn lost_commit_reply_converges_by_readback() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.workspace_operations.dst_lose_next_commit_reply();
        assert_eq!(
            fs.workspace_operations.begin(&key(), digest(1)).await,
            Err(WorkspaceOperationError::CommitOutcomeUnknown)
        );
        assert_eq!(
            fs.workspace_operations
                .lookup(&key(), digest(1))
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                request_digest: digest(1),
                state: WorkspaceOperationState::Pending,
            })
        );
    }

    #[tokio::test]
    async fn coordinator_reply_channel_close_is_an_unknown_outcome() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.write_coordinator.dst_drop_next_workspace_durable_reply();
        assert_eq!(
            fs.workspace_operations.begin(&key(), digest(1)).await,
            Err(WorkspaceOperationError::CommitOutcomeUnknown)
        );
        assert_eq!(
            fs.workspace_operations
                .lookup(&key(), digest(1))
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                request_digest: digest(1),
                state: WorkspaceOperationState::Pending,
            })
        );
    }

    #[tokio::test]
    async fn lost_terminal_reply_converges_to_the_exact_terminal_bytes() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.workspace_operations
            .begin(&key(), digest(1))
            .await
            .unwrap();
        fs.workspace_operations.dst_lose_next_commit_reply();
        assert_eq!(
            fs.workspace_operations
                .complete(
                    &key(),
                    digest(1),
                    WorkspaceTerminalOutcome::Failed(Bytes::from_static(b"signed-negative")),
                )
                .await,
            Err(WorkspaceOperationError::CommitOutcomeUnknown)
        );
        assert_eq!(
            fs.workspace_operations
                .lookup(&key(), digest(1))
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                request_digest: digest(1),
                state: WorkspaceOperationState::Failed(Bytes::from_static(b"signed-negative")),
            })
        );
    }

    #[tokio::test]
    async fn cancelled_caller_cannot_release_terminal_serialization_early() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.workspace_operations
            .begin(&key(), digest(1))
            .await
            .unwrap();
        fs.write_coordinator
            .dst_pause_next_workspace_durable_before_apply();
        let first = tokio::spawn({
            let ledger = fs.workspace_operations.clone();
            async move {
                ledger
                    .complete(
                        &key(),
                        digest(1),
                        WorkspaceTerminalOutcome::Succeeded(Bytes::from_static(b"receipt-a")),
                    )
                    .await
            }
        });
        fs.write_coordinator
            .dst_wait_workspace_durable_before_apply()
            .await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        let second = tokio::spawn({
            let ledger = fs.workspace_operations.clone();
            async move {
                ledger
                    .complete(
                        &key(),
                        digest(1),
                        WorkspaceTerminalOutcome::Failed(Bytes::from_static(b"receipt-b")),
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(
            !second.is_finished(),
            "the cancelled caller's guard must remain owned by the queued commit"
        );
        fs.write_coordinator
            .dst_release_workspace_durable_before_apply();
        assert_eq!(
            second.await.unwrap(),
            Err(WorkspaceOperationError::TerminalImmutable)
        );
        assert_eq!(
            fs.workspace_operations
                .lookup(&key(), digest(1))
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                request_digest: digest(1),
                state: WorkspaceOperationState::Succeeded(Bytes::from_static(b"receipt-a")),
            })
        );
    }

    #[tokio::test]
    async fn post_apply_flush_failure_is_unknown_and_preserves_terminal_choice() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.workspace_operations
            .begin(&key(), digest(1))
            .await
            .unwrap();
        fs.write_coordinator.dst_fail_next_workspace_durable_flush();
        let success = WorkspaceTerminalOutcome::Succeeded(Bytes::from_static(b"receipt-a"));
        assert_eq!(
            fs.workspace_operations
                .complete(&key(), digest(1), success.clone())
                .await,
            Err(WorkspaceOperationError::CommitOutcomeUnknown)
        );
        assert_eq!(
            fs.workspace_operations
                .complete(
                    &key(),
                    digest(1),
                    WorkspaceTerminalOutcome::Failed(Bytes::from_static(b"receipt-b")),
                )
                .await,
            Err(WorkspaceOperationError::TerminalImmutable)
        );
        assert_eq!(
            fs.workspace_operations
                .lookup(&key(), digest(1))
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                request_digest: digest(1),
                state: WorkspaceOperationState::Succeeded(Bytes::from_static(b"receipt-a")),
            }),
            "a deterministic immutable verdict requires the original terminal to be durable"
        );
        assert!(matches!(
            fs.workspace_operations
                .complete(&key(), digest(1), success)
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                state: WorkspaceOperationState::Succeeded(_),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn conflict_after_unknown_pending_first_makes_original_digest_durable() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.write_coordinator.dst_fail_next_workspace_durable_flush();
        assert_eq!(
            fs.workspace_operations.begin(&key(), digest(1)).await,
            Err(WorkspaceOperationError::CommitOutcomeUnknown)
        );
        assert_eq!(
            fs.workspace_operations.begin(&key(), digest(2)).await,
            Err(WorkspaceOperationError::RequestConflict)
        );
        assert_eq!(
            fs.workspace_operations
                .lookup(&key(), digest(1))
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                request_digest: digest(1),
                state: WorkspaceOperationState::Pending,
            }),
            "a deterministic digest conflict requires the original intent to be durable"
        );
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn failpoint_after_commit_requires_readback() {
        crate::test_helpers::isolated_failpoint::run(
            "fs::workspace_operation::tests::failpoint_after_commit_requires_readback",
            crate::test_helpers::isolated_failpoint::Runtime::CurrentThread,
            || async {
                let point = crate::failpoints::WORKSPACE_OPERATION_AFTER_COMMIT_BEFORE_REPLY;
                let armed = crate::test_helpers::isolated_failpoint::arm(point, "return");
                let fs = ZeroFS::new_in_memory().await.unwrap();
                assert_eq!(
                    fs.workspace_operations.begin(&key(), digest(1)).await,
                    Err(WorkspaceOperationError::CommitOutcomeUnknown)
                );
                drop(armed);
                assert!(matches!(
                    fs.workspace_operations
                        .lookup(&key(), digest(1))
                        .await
                        .unwrap(),
                    WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                        state: WorkspaceOperationState::Pending,
                        ..
                    })
                ));
            },
        );
    }

    #[tokio::test]
    async fn operation_kind_is_part_of_the_durable_scope() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let first = key();
        let mut second = key();
        second.kind += 1;
        fs.workspace_operations
            .begin(&first, digest(1))
            .await
            .unwrap();
        fs.workspace_operations
            .begin(&second, digest(2))
            .await
            .unwrap();
        assert!(matches!(
            fs.workspace_operations
                .lookup(&second, digest(2))
                .await
                .unwrap(),
            WorkspaceOperationLookup::Known(_)
        ));
    }

    #[tokio::test]
    async fn terminal_is_idempotent_but_immutable() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.workspace_operations
            .begin(&key(), digest(1))
            .await
            .unwrap();
        let terminal = WorkspaceTerminalOutcome::Succeeded(Bytes::from_static(b"receipt"));
        let expected = fs
            .workspace_operations
            .complete(&key(), digest(1), terminal.clone())
            .await
            .unwrap();
        assert_eq!(
            fs.workspace_operations
                .complete(&key(), digest(1), terminal)
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            fs.workspace_operations
                .complete(
                    &key(),
                    digest(1),
                    WorkspaceTerminalOutcome::Failed(Bytes::from_static(b"negative")),
                )
                .await,
            Err(WorkspaceOperationError::TerminalImmutable)
        );
    }

    #[tokio::test]
    async fn corrupt_record_fails_closed() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let encoded_key = fs.workspace_operations.encode_key(&key()).unwrap();
        let guard = fs.write_coordinator.lock_workspace_ledger().await;
        fs.write_coordinator
            .commit_workspace_durable(
                WorkspaceLedgerRequest::put(&encoded_key, Bytes::from_static(b"corrupt")),
                guard,
            )
            .await
            .unwrap();
        assert!(matches!(
            fs.workspace_operations.lookup(&key(), digest(1)).await,
            Err(WorkspaceOperationError::CorruptRecord(_))
        ));
    }

    #[tokio::test]
    async fn raw_copy_to_another_operation_key_is_rejected() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let source_key = fs.workspace_operations.encode_key(&key()).unwrap();
        let mut destination = key();
        destination.request_id = "request-b".to_string();
        let destination_key = fs.workspace_operations.encode_key(&destination).unwrap();
        let record = WorkspaceOperationRecord {
            request_digest: digest(1),
            state: WorkspaceOperationState::Pending,
        };
        let copied_value = encode_record(&source_key, &record).unwrap();
        let mut txn = Transaction::new();
        txn.put_bytes(&destination_key, copied_value);
        assert_eq!(
            fs.write_coordinator.commit(txn).await,
            Err(FsError::OperationNotPermitted)
        );
        assert_eq!(
            fs.workspace_operations
                .lookup(&destination, digest(1))
                .await,
            Ok(WorkspaceOperationLookup::Unknown)
        );
    }

    #[tokio::test]
    async fn typed_path_still_rejects_record_bytes_copied_across_keys_on_readback() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let source_key = fs.workspace_operations.encode_key(&key()).unwrap();
        let destination = WorkspaceOperationKey::new("workspace-b", 10, "request-a");
        let destination_key = fs.workspace_operations.encode_key(&destination).unwrap();
        let source_record = WorkspaceOperationRecord {
            request_digest: digest(1),
            state: WorkspaceOperationState::Pending,
        };
        let copied_source_bytes = encode_record(&source_key, &source_record).unwrap();
        let guard = fs.write_coordinator.lock_workspace_ledger().await;
        fs.write_coordinator
            .commit_workspace_durable(
                WorkspaceLedgerRequest::put(&destination_key, copied_source_bytes),
                guard,
            )
            .await
            .unwrap();

        assert!(matches!(
            fs.workspace_operations
                .lookup(&destination, digest(1))
                .await,
            Err(WorkspaceOperationError::CorruptRecord(_))
        ));
    }

    #[tokio::test]
    async fn raw_put_with_valid_current_key_checksum_cannot_advance_pending() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.workspace_operations
            .begin(&key(), digest(1))
            .await
            .unwrap();
        let encoded_key = fs.workspace_operations.encode_key(&key()).unwrap();
        let forged_terminal = WorkspaceOperationRecord {
            request_digest: digest(1),
            state: WorkspaceOperationState::Succeeded(Bytes::from_static(b"forged-receipt")),
        };
        let mut txn = Transaction::new();
        txn.put_bytes(
            &encoded_key,
            encode_record(&encoded_key, &forged_terminal).unwrap(),
        );

        assert_eq!(
            fs.write_coordinator.commit(txn).await,
            Err(FsError::OperationNotPermitted)
        );
        assert_eq!(
            fs.workspace_operations.lookup(&key(), digest(1)).await,
            Ok(WorkspaceOperationLookup::Known(WorkspaceOperationRecord {
                request_digest: digest(1),
                state: WorkspaceOperationState::Pending,
            }))
        );
    }

    #[tokio::test]
    async fn raw_delete_cannot_remove_current_record() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let expected = fs
            .workspace_operations
            .begin(&key(), digest(1))
            .await
            .unwrap();
        let encoded_key = fs.workspace_operations.encode_key(&key()).unwrap();
        let mut txn = Transaction::new();
        txn.delete_bytes(&encoded_key);

        assert_eq!(
            fs.write_coordinator.commit(txn).await,
            Err(FsError::OperationNotPermitted)
        );
        assert_eq!(
            fs.workspace_operations.lookup(&key(), digest(1)).await,
            Ok(WorkspaceOperationLookup::Known(expected))
        );
    }

    #[tokio::test]
    async fn raw_cross_workspace_put_with_valid_target_checksum_is_rejected() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let destination = WorkspaceOperationKey::new("workspace-b", 10, "request-a");
        let destination_key = fs.workspace_operations.encode_key(&destination).unwrap();
        let forged = WorkspaceOperationRecord {
            request_digest: digest(1),
            state: WorkspaceOperationState::Pending,
        };
        let mut txn = Transaction::new();
        txn.put_bytes(
            &destination_key,
            encode_record(&destination_key, &forged).unwrap(),
        );

        assert_eq!(
            fs.write_coordinator.commit(txn).await,
            Err(FsError::OperationNotPermitted)
        );
        assert_eq!(
            fs.workspace_operations
                .lookup(&destination, digest(1))
                .await,
            Ok(WorkspaceOperationLookup::Unknown)
        );
    }

    #[tokio::test]
    async fn raw_put_cannot_overwrite_terminal_record() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.workspace_operations
            .begin(&key(), digest(1))
            .await
            .unwrap();
        let expected = fs
            .workspace_operations
            .complete(
                &key(),
                digest(1),
                WorkspaceTerminalOutcome::Succeeded(Bytes::from_static(b"real-receipt")),
            )
            .await
            .unwrap();
        let encoded_key = fs.workspace_operations.encode_key(&key()).unwrap();
        let forged = WorkspaceOperationRecord {
            request_digest: digest(1),
            state: WorkspaceOperationState::Failed(Bytes::from_static(b"forged-negative")),
        };
        let mut txn = Transaction::new();
        txn.put_bytes(&encoded_key, encode_record(&encoded_key, &forged).unwrap());

        assert_eq!(
            fs.write_coordinator.commit(txn).await,
            Err(FsError::OperationNotPermitted)
        );
        assert_eq!(
            fs.workspace_operations.lookup(&key(), digest(1)).await,
            Ok(expected)
        );
    }

    #[tokio::test]
    async fn weak_general_commit_also_rejects_reserved_namespace() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let encoded_key = fs.workspace_operations.encode_key(&key()).unwrap();
        let mut txn = Transaction::new();
        txn.delete_bytes(&encoded_key);

        assert_eq!(
            fs.write_coordinator.downgrade().commit(txn).await,
            Err(FsError::OperationNotPermitted)
        );
    }

    #[tokio::test]
    async fn direct_database_put_rejects_reserved_namespace() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let encoded_key = fs.workspace_operations.encode_key(&key()).unwrap();
        let error = fs
            .db
            .put_with_options(
                &encoded_key,
                b"forged",
                &PutOptions::default(),
                &WriteOptions::default(),
            )
            .await
            .unwrap_err();

        assert_eq!(
            FsError::from_db_error(&error),
            FsError::OperationNotPermitted
        );
    }

    #[test]
    fn every_record_byte_is_covered_by_the_integrity_digest() {
        let encoded_key =
            KeyCodec::new().workspace_operation_key(KEY_VERSION, b"workspace-a", 10, b"request-a");
        let record = WorkspaceOperationRecord {
            request_digest: digest(1),
            state: WorkspaceOperationState::Succeeded(Bytes::from_static(b"exact-receipt")),
        };
        let encoded = encode_record(&encoded_key, &record).unwrap();
        for index in 0..encoded.len() {
            let mut mutated = encoded.to_vec();
            mutated[index] ^= 1;
            assert!(
                decode_record(&encoded_key, &mutated).is_err(),
                "byte {index} was not protected"
            );
        }
    }

    #[tokio::test]
    async fn terminal_record_survives_close_and_reopen() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let fs = open_fs(object_store.clone()).await.unwrap();
        fs.workspace_operations
            .begin(&key(), digest(1))
            .await
            .unwrap();
        let expected = fs
            .workspace_operations
            .complete(
                &key(),
                digest(1),
                WorkspaceTerminalOutcome::Succeeded(Bytes::from_static(b"exact-receipt")),
            )
            .await
            .unwrap();
        fs.flush_coordinator.close().await.unwrap();
        drop(fs);

        let reopened = open_fs(object_store).await.unwrap();
        assert_eq!(
            reopened
                .workspace_operations
                .lookup(&key(), digest(1))
                .await
                .unwrap(),
            expected
        );
    }
}
