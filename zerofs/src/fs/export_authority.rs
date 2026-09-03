//! Durable per-export Rhizome authority and session state.
//!
//! This module is an internal storage primitive. It accepts already-verified
//! authority inputs, does not parse capabilities, and never creates signed
//! receipts. Every transition and fenced mutation enters the filesystem's one
//! [`WriteCoordinator`], which is the only ordering authority.

use crate::db::{Db, Transaction};
use crate::fs::key_codec::{ExportMutationKey, KeyCodec};
use crate::fs::lock_manager::KeyedLockGuard;
use crate::fs::store::extent::TailUpdate;
use crate::fs::store::{ExtentStore, InodeStore};
use crate::fs::write_coordinator::WriteCoordinator;
use bincode::Options;
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

const RECORD_VERSION: u8 = 2;
const AUTHORITY_RECORD_MAGIC: &[u8; 4] = b"RAUT";
const MUTATION_OUTCOME_MAGIC: &[u8; 4] = b"RMUT";
const REVERSE_BINDING_MAGIC: &[u8; 4] = b"RBND";
const MAX_ID_BYTES: usize = 1024;
const SHA256_SIZE: usize = 32;
const MAX_RECORD_PAYLOAD_BYTES: usize = 64 * 1024;
const ENVELOPE_CHECKSUM_DOMAIN: &[u8] = b"rhizome.export-record-envelope.v1\0";
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
)]
const COMMAND_DIGEST_DOMAIN: &[u8] = b"rhizome.export-mutation-command.v2\0";
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
)]
const DATA_CHECKSUM_DOMAIN: &[u8] = b"rhizome.export-mutation-data.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExportIdentity {
    pub nbd_directory_inode: u64,
    pub name: Vec<u8>,
    pub inode: u64,
    pub advertised_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuthorityVersion {
    pub actor: String,
    pub actor_generation: u64,
    pub home_cell: String,
    pub home_revision: u64,
    pub authority_epoch: u64,
    pub placement_epoch: u64,
    pub assignment_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExportSessionState {
    pub session_id: String,
    pub capability_id: String,
    pub expires_at_unix_millis: u64,
    pub node_incarnation_id: String,
    pub runtime_id: String,
    pub server_boot_id: String,
    pub committed_through_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExportAuthorityRecord {
    pub workspace_id: String,
    pub export: ExportIdentity,
    pub authority: AuthorityVersion,
    pub rejected_through_placement_epoch: u64,
    pub binding_initialized: bool,
    pub active_session: Option<ExportSessionState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExportReverseBinding {
    pub workspace_id: String,
    pub actor: String,
    pub actor_generation: u64,
    pub export: ExportIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivateExport {
    pub workspace_id: String,
    pub export: ExportIdentity,
    pub authority: AuthorityVersion,
    pub session: ExportSessionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefreshExport {
    pub workspace_id: String,
    pub expected_export: ExportIdentity,
    pub expected_authority: AuthorityVersion,
    pub session_id: String,
    pub expected_capability_id: String,
    pub replacement_authority: AuthorityVersion,
    pub replacement_capability_id: String,
    pub replacement_expires_at_unix_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeactivateExport {
    pub workspace_id: String,
    pub expected_export: ExportIdentity,
    pub expected_authority: AuthorityVersion,
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdvanceFence {
    pub workspace_id: String,
    pub export: ExportIdentity,
    pub expected_authority: Option<AuthorityVersion>,
    pub new_non_writable_authority: AuthorityVersion,
    pub reject_through_placement_epoch: u64,
}

pub(super) struct FenceMutationConflict {
    committed: ExportMutationOutcome,
    attempted: ExportMutationExpectation,
}

impl FenceMutationConflict {
    fn new(
        committed: ExportMutationOutcome,
        attempted: ExportMutationExpectation,
    ) -> Result<Self, ExportAuthorityError> {
        if committed.workspace_id != attempted.workspace_id
            || committed.export != attempted.export
            || committed.authority.actor != attempted.authority.actor
            || committed.authority.actor_generation != attempted.authority.actor_generation
            || committed.authority.placement_epoch != attempted.authority.placement_epoch
            || committed.session_id != attempted.session_id
            || committed.server_boot_id != attempted.server_boot_id
            || committed.mutation.operation_id != attempted.mutation.operation_id
            || ensure_outcome(&committed, &attempted) != Err(ExportAuthorityError::Conflict)
        {
            return Err(ExportAuthorityError::Corrupt);
        }
        Ok(Self {
            committed,
            attempted,
        })
    }

    pub(super) async fn verify_current(&self, db: &Db) -> Result<(), ExportAuthorityError> {
        let key = mutation_outcome_key(&self.attempted);
        let current = read_outcome_current(db, &key, &self.attempted)
            .await?
            .ok_or(ExportAuthorityError::Corrupt)?;
        if current != self.committed
            || ensure_outcome(&current, &self.attempted) != Err(ExportAuthorityError::Conflict)
        {
            return Err(ExportAuthorityError::Corrupt);
        }
        Ok(())
    }

    pub(super) fn attempted(&self) -> &ExportMutationExpectation {
        &self.attempted
    }
}

pub(crate) type ExportAdmissionGuard = KeyedLockGuard<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShardLockIdentity {
    pub directory_device: u64,
    pub directory_inode: u64,
    pub lock_device: u64,
    pub lock_inode: u64,
}

pub(crate) struct ShardProcessGuard {
    _directory: std::fs::File,
    _lock: std::fs::File,
    _identity: ShardLockIdentity,
}

#[cfg(target_os = "linux")]
struct ShardGuardValidation {
    identity: ShardLockIdentity,
    directory_uid: u32,
    lock_uid: u32,
    gid: u32,
    directory_mode: u32,
    lock_mode: u32,
}

impl ShardProcessGuard {
    #[cfg(target_os = "linux")]
    #[cfg_attr(test, allow(dead_code))]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "wired by the supervised Rhizome profile")
    )]
    pub(crate) fn acquire_configured(
        lock_root: &std::path::Path,
        shard_id: &str,
        worker_uid: u32,
        worker_gid: u32,
        expected: ShardLockIdentity,
    ) -> Result<Self, ExportAuthorityError> {
        use std::os::unix::fs::OpenOptionsExt;

        if !lock_root.is_absolute()
            || worker_uid == 0
            || rustix::process::geteuid().as_raw() != worker_uid
            || (rustix::process::getegid().as_raw() != worker_gid
                && !rustix::process::getgroups()
                    .map_err(|_| ExportAuthorityError::Storage)?
                    .iter()
                    .any(|gid| gid.as_raw() == worker_gid))
        {
            return Err(ExportAuthorityError::Invalid);
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(lock_root)
            .map_err(|_| ExportAuthorityError::Storage)?;
        Self::acquire_at(
            directory,
            shard_id,
            ShardGuardValidation {
                identity: expected,
                directory_uid: 0,
                lock_uid: worker_uid,
                gid: worker_gid,
                directory_mode: 0o750,
                lock_mode: 0o600,
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn acquire_at(
        directory: std::fs::File,
        shard_id: &str,
        validation: ShardGuardValidation,
    ) -> Result<Self, ExportAuthorityError> {
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::MetadataExt;

        validate_id(shard_id)?;
        let directory_metadata = directory
            .metadata()
            .map_err(|_| ExportAuthorityError::Storage)?;
        if !directory_metadata.is_dir()
            || directory_metadata.uid() != validation.directory_uid
            || directory_metadata.gid() != validation.gid
            || directory_metadata.mode() & 0o7777 != validation.directory_mode
            || directory_metadata.dev() != validation.identity.directory_device
            || directory_metadata.ino() != validation.identity.directory_inode
        {
            return Err(ExportAuthorityError::Invalid);
        }
        let lock_fd: OwnedFd = rustix::fs::openat(
            &directory,
            shard_lock_name(shard_id),
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ExportAuthorityError::Storage)?;
        let lock = std::fs::File::from(lock_fd);
        let lock_metadata = lock.metadata().map_err(|_| ExportAuthorityError::Storage)?;
        if !lock_metadata.is_file()
            || lock_metadata.uid() != validation.lock_uid
            || lock_metadata.gid() != validation.gid
            || lock_metadata.mode() & 0o7777 != validation.lock_mode
            || lock_metadata.nlink() != 1
            || lock_metadata.dev() != validation.identity.lock_device
            || lock_metadata.ino() != validation.identity.lock_inode
        {
            return Err(ExportAuthorityError::Invalid);
        }
        lock.try_lock()
            .map_err(|_| ExportAuthorityError::Conflict)?;
        Ok(Self {
            _directory: directory,
            _lock: lock,
            _identity: validation.identity,
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn for_test() -> Self {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let shard_id = uuid::Uuid::new_v4().to_string();
        let lock_path = directory.join(shard_lock_name(&shard_id));
        let lock = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(lock_path)
            .unwrap();
        let directory_file = std::fs::File::open(directory).unwrap();
        let directory_metadata = directory_file.metadata().unwrap();
        let lock_metadata = lock.metadata().unwrap();
        let identity = ShardLockIdentity {
            directory_device: directory_metadata.dev(),
            directory_inode: directory_metadata.ino(),
            lock_device: lock_metadata.dev(),
            lock_inode: lock_metadata.ino(),
        };
        drop(lock);
        Self::acquire_at(
            directory_file,
            &shard_id,
            ShardGuardValidation {
                identity,
                directory_uid: directory_metadata.uid(),
                lock_uid: directory_metadata.uid(),
                gid: directory_metadata.gid(),
                directory_mode: 0o700,
                lock_mode: 0o600,
            },
        )
        .unwrap()
    }

    #[cfg(all(test, not(target_os = "linux")))]
    pub(super) fn for_test() -> Self {
        Self {
            _directory: tempfile::tempfile().unwrap(),
            _lock: tempfile::tempfile().unwrap(),
            _identity: ShardLockIdentity {
                directory_device: 0,
                directory_inode: 0,
                lock_device: 0,
                lock_inode: 0,
            },
        }
    }
}

#[cfg(target_os = "linux")]
fn shard_lock_name(shard_id: &str) -> String {
    let digest = Sha256::digest(shard_id.as_bytes());
    let mut name = String::with_capacity("rhizome-shard-".len() + digest.len() * 2 + 5);
    name.push_str("rhizome-shard-");
    for byte in digest {
        use std::fmt::Write;
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    name.push_str(".lock");
    name
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum MutationKind {
    Write { fua: bool },
    Flush,
    Trim { fua: bool },
    WriteZeroes { fua: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
)]
pub(crate) enum ExportMutationCommand {
    Write { offset: u64, data: Bytes, fua: bool },
    Flush,
    Trim { offset: u64, length: u32, fua: bool },
    WriteZeroes { offset: u64, length: u32, fua: bool },
}

impl ExportMutationCommand {
    fn kind(&self) -> MutationKind {
        match self {
            Self::Write { fua, .. } => MutationKind::Write { fua: *fua },
            Self::Flush => MutationKind::Flush,
            Self::Trim { fua, .. } => MutationKind::Trim { fua: *fua },
            Self::WriteZeroes { fua, .. } => MutationKind::WriteZeroes { fua: *fua },
        }
    }

    fn data_checksum(&self) -> DataChecksum {
        match self {
            Self::Write { data, .. } => {
                DataChecksum(domain_hash(DATA_CHECKSUM_DOMAIN, data.as_ref()))
            }
            _ => DataChecksum(domain_hash(DATA_CHECKSUM_DOMAIN, &[])),
        }
    }
}

impl MutationKind {
    pub(crate) fn requires_durability(self) -> bool {
        matches!(
            self,
            Self::Flush
                | Self::Write { fua: true }
                | Self::Trim { fua: true }
                | Self::WriteZeroes { fua: true }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MutationFenceToken {
    pub workspace_id: String,
    pub export: ExportIdentity,
    pub authority: AuthorityVersion,
    pub session_id: String,
    pub capability_id: String,
    pub expires_at_unix_millis: u64,
    pub node_incarnation_id: String,
    pub runtime_id: String,
    pub server_boot_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommandDigest([u8; SHA256_SIZE]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DataChecksum([u8; SHA256_SIZE]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OperationId(pub(crate) [u8; SHA256_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MutationRequestIdentity {
    pub operation_id: OperationId,
    pub command_digest: CommandDigest,
    pub data_checksum: DataChecksum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MutationIdentity {
    pub operation_id: OperationId,
    pub sequence: u64,
    pub command_digest: CommandDigest,
    pub data_checksum: DataChecksum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExportMutationOutcome {
    pub workspace_id: String,
    pub export: ExportIdentity,
    pub authority: AuthorityVersion,
    pub session_id: String,
    pub server_boot_id: String,
    pub mutation: MutationIdentity,
    pub kind: MutationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportMutationExpectation {
    pub workspace_id: String,
    pub export: ExportIdentity,
    pub authority: AuthorityVersion,
    pub session_id: String,
    pub server_boot_id: String,
    pub mutation: MutationRequestIdentity,
    pub kind: MutationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
)]
pub(crate) enum ExportMutationLookup {
    Unknown,
    Committed(Box<ExportMutationOutcome>),
}

pub(crate) struct ExportMutation {
    kind: MutationKind,
    token: MutationFenceToken,
    identity: MutationRequestIdentity,
    command: ExportMutationCommand,
    #[cfg(test)]
    test_transaction: Option<Transaction>,
}

struct PreparedExportMutation {
    transaction: Transaction,
    tail_update: Option<TailUpdate>,
    inode_guard: Option<KeyedLockGuard<u64>>,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
)]
pub(crate) struct ExportMutationBuilder;

impl ExportMutationBuilder {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
    )]
    pub(crate) fn build(
        token: MutationFenceToken,
        operation_id: [u8; SHA256_SIZE],
        command: ExportMutationCommand,
    ) -> Result<ExportMutation, ExportAuthorityError> {
        validate_id(&token.workspace_id)?;
        validate_export(&token.export)?;
        validate_authority(&token.authority)?;
        validate_id(&token.session_id)?;
        validate_id(&token.capability_id)?;
        validate_id(&token.node_incarnation_id)?;
        validate_id(&token.runtime_id)?;
        validate_id(&token.server_boot_id)?;
        if operation_id == [0; SHA256_SIZE] {
            return Err(ExportAuthorityError::Invalid);
        }
        let kind = command.kind();
        let data_checksum = command.data_checksum();
        Ok(ExportMutation {
            kind,
            token: token.clone(),
            identity: MutationRequestIdentity {
                operation_id: OperationId(operation_id),
                command_digest: CommandDigest(command_digest(
                    &token,
                    operation_id,
                    &command,
                    &data_checksum,
                )),
                data_checksum,
            },
            command,
            #[cfg(test)]
            test_transaction: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_transaction_for_test(
        token: MutationFenceToken,
        operation_id: [u8; SHA256_SIZE],
        command: ExportMutationCommand,
        transaction: Transaction,
    ) -> Result<ExportMutation, ExportAuthorityError> {
        validate_export(&token.export)?;
        if operation_id == [0; SHA256_SIZE] {
            return Err(ExportAuthorityError::Invalid);
        }
        transaction.validate_export_scope(token.export.inode)?;
        let kind = command.kind();
        let data_checksum = command.data_checksum();
        Ok(ExportMutation {
            kind,
            token: token.clone(),
            identity: MutationRequestIdentity {
                operation_id: OperationId(operation_id),
                command_digest: CommandDigest(command_digest(
                    &token,
                    operation_id,
                    &command,
                    &data_checksum,
                )),
                data_checksum,
            },
            command,
            test_transaction: Some(transaction),
        })
    }
}

impl ExportMutation {
    pub(crate) fn expectation(&self) -> ExportMutationExpectation {
        ExportMutationExpectation {
            workspace_id: self.token.workspace_id.clone(),
            export: self.token.export.clone(),
            authority: self.token.authority.clone(),
            session_id: self.token.session_id.clone(),
            server_boot_id: self.token.server_boot_id.clone(),
            mutation: self.identity.clone(),
            kind: self.kind,
        }
    }
}

pub(crate) struct ExportMutationContext {
    pub(crate) kind: MutationKind,
    pub(crate) token: MutationFenceToken,
    pub(crate) export: ExportIdentity,
    pub(crate) identity: MutationRequestIdentity,
    pub(crate) _guard: ExportAdmissionGuard,
    pub(crate) tail_update: Option<TailUpdate>,
    pub(crate) _inode_guard: Option<KeyedLockGuard<u64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ExportAuthorityError {
    #[error("invalid export authority input")]
    Invalid,
    #[error("export authority state is absent")]
    NotFound,
    #[error("export authority record is corrupt")]
    Corrupt,
    #[error("authority or session precondition failed")]
    Conflict,
    #[error("mutation fence is stale; close the presenting session")]
    StaleMutation,
    #[error("storage commit outcome is unknown; read back durable state")]
    CommitOutcomeUnknown,
    #[error("storage failure")]
    Storage,
    #[error("export authority profile is not durably enabled")]
    ProfileDisabled,
    #[error("legacy export authority state requires an explicit migration")]
    MigrationRequired,
}

impl ExportAuthorityError {
    /// A stale mutation invalidates the presenting transport session. This does
    /// not close or rewrite the currently authoritative session record.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
    )]
    pub(crate) fn close_session(self) -> bool {
        matches!(
            self,
            Self::Conflict | Self::StaleMutation | Self::CommitOutcomeUnknown
        )
    }
}

#[derive(Clone)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "feature-staged until verified adapter wiring")
)]
pub(crate) struct ExportAuthorityStore {
    db: Arc<Db>,
    coordinator: WriteCoordinator,
    inode_store: InodeStore,
    extent_store: ExtentStore,
    lock_manager: Arc<crate::fs::lock_manager::KeyedLockManager<u64>>,
    server_boot_id: String,
    admission_locks: Arc<crate::fs::lock_manager::KeyedLockManager<String>>,
    profile_enabled: Arc<std::sync::atomic::AtomicBool>,
    process_guard: Arc<std::sync::Mutex<Option<ShardProcessGuard>>>,
    enable_lock: Arc<tokio::sync::Mutex<()>>,
    #[cfg(test)]
    pause_after_admission: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    entered_after_admission: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    release_after_admission: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    prepared_mutations: Arc<std::sync::atomic::AtomicU64>,
}

impl ExportAuthorityStore {
    pub(crate) fn new(
        db: Arc<Db>,
        coordinator: WriteCoordinator,
        inode_store: InodeStore,
        extent_store: ExtentStore,
        lock_manager: Arc<crate::fs::lock_manager::KeyedLockManager<u64>>,
    ) -> Self {
        let server_boot_id = coordinator.export_server_boot_id().to_owned();
        Self {
            db,
            coordinator,
            inode_store,
            extent_store,
            lock_manager,
            server_boot_id,
            admission_locks: Arc::new(crate::fs::lock_manager::KeyedLockManager::new()),
            profile_enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            process_guard: Arc::new(std::sync::Mutex::new(None)),
            enable_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            pause_after_admission: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            entered_after_admission: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            release_after_admission: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            prepared_mutations: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified adapter wiring")
    )]
    pub(crate) async fn activate(
        &self,
        command: ActivateExport,
    ) -> Result<ExportAuthorityRecord, ExportAuthorityError> {
        self.ensure_current_schema().await?;
        self.require_enabled()?;
        let guard = self
            .admission_locks
            .acquire(command.workspace_id.clone())
            .await;
        self.coordinator
            .transition_export_authority(ExportAuthorityTransition::Activate(command), guard)
            .await
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified adapter wiring")
    )]
    pub(crate) async fn refresh(
        &self,
        command: RefreshExport,
    ) -> Result<ExportAuthorityRecord, ExportAuthorityError> {
        self.ensure_current_schema().await?;
        self.require_enabled()?;
        let guard = self
            .admission_locks
            .acquire(command.workspace_id.clone())
            .await;
        self.coordinator
            .transition_export_authority(ExportAuthorityTransition::Refresh(command), guard)
            .await
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified adapter wiring")
    )]
    pub(crate) async fn deactivate(
        &self,
        command: DeactivateExport,
    ) -> Result<ExportAuthorityRecord, ExportAuthorityError> {
        self.ensure_current_schema().await?;
        self.require_enabled()?;
        let guard = self
            .admission_locks
            .acquire(command.workspace_id.clone())
            .await;
        self.coordinator
            .transition_export_authority(ExportAuthorityTransition::Deactivate(command), guard)
            .await
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified adapter wiring")
    )]
    pub(crate) async fn advance_fence(
        &self,
        command: AdvanceFence,
    ) -> Result<ExportAuthorityRecord, ExportAuthorityError> {
        self.ensure_current_schema().await?;
        self.require_enabled()?;
        let guard = self
            .admission_locks
            .acquire(command.workspace_id.clone())
            .await;
        self.coordinator
            .transition_export_authority(ExportAuthorityTransition::AdvanceFence(command), guard)
            .await
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified adapter wiring")
    )]
    pub(crate) async fn commit_mutation(
        &self,
        mut mutation: ExportMutation,
    ) -> Result<ExportMutationOutcome, ExportAuthorityError> {
        self.ensure_current_schema().await?;
        self.require_enabled()?;
        let guard = self
            .admission_locks
            .acquire(mutation.token.workspace_id.clone())
            .await;
        let expected = mutation.expectation();
        let key = mutation_outcome_key(&expected);
        if let Some(current) = read_outcome_current(&self.db, &key, &expected).await? {
            if ensure_outcome(&current, &expected).is_err() {
                let conflict = FenceMutationConflict::new(current, expected)?;
                self.fence_mutation_conflict(conflict, guard).await?;
                return Err(ExportAuthorityError::Conflict);
            }
            if !expected.kind.requires_durability() {
                return Ok(current);
            }
            return self
                .make_outcome_durable(guard, &key, &expected, current)
                .await;
        }
        self.validate_admission(&mutation.token).await?;
        #[cfg(test)]
        if self
            .pause_after_admission
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.entered_after_admission.notify_one();
            self.release_after_admission.notified().await;
        }
        let prepared = self.prepare_mutation(&mut mutation).await?;
        self.coordinator
            .commit_export_mutation(
                prepared.transaction,
                ExportMutationContext {
                    kind: mutation.kind,
                    export: mutation.token.export.clone(),
                    token: mutation.token,
                    identity: mutation.identity,
                    _guard: guard,
                    tail_update: prepared.tail_update,
                    _inode_guard: prepared.inode_guard,
                },
            )
            .await?;
        let committed = read_outcome_current(&self.db, &key, &expected)
            .await?
            .ok_or(ExportAuthorityError::Corrupt)?;
        ensure_outcome(&committed, &expected)?;
        if expected.kind.requires_durability() {
            let durable = read_outcome_durable(&self.db, &key, &expected)
                .await?
                .ok_or(ExportAuthorityError::Corrupt)?;
            ensure_outcome(&durable, &expected)?;
            return Ok(durable);
        }
        Ok(committed)
    }

    async fn prepare_mutation(
        &self,
        mutation: &mut ExportMutation,
    ) -> Result<PreparedExportMutation, ExportAuthorityError> {
        #[cfg(test)]
        if let Some(transaction) = mutation.test_transaction.take() {
            return Ok(PreparedExportMutation {
                transaction,
                tail_update: None,
                inode_guard: None,
            });
        }

        let inode_guard = self.lock_manager.acquire(mutation.token.export.inode).await;
        let inode = self
            .inode_store
            .get(mutation.token.export.inode)
            .await
            .map_err(|_| ExportAuthorityError::Invalid)?;
        let file = match &inode {
            crate::fs::inode::Inode::File(file) => file,
            _ => return Err(ExportAuthorityError::Invalid),
        };
        if file.parent != Some(mutation.token.export.nbd_directory_inode)
            || file.name.as_deref() != Some(mutation.token.export.name.as_slice())
            || file.nlink != 1
            || file.size != mutation.token.export.advertised_size
        {
            return Err(ExportAuthorityError::Invalid);
        }
        // Re-read durable process/writer authority at the physical staging
        // boundary, after every potentially blocking local lock. The first
        // check reserves local transition order; this one catches a competing
        // process that superseded the boot in between.
        self.validate_admission(&mutation.token).await?;
        #[cfg(test)]
        self.prepared_mutations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut transaction = self
            .db
            .new_transaction()
            .map_err(|_| ExportAuthorityError::Storage)?;
        let tail_update = match &mutation.command {
            ExportMutationCommand::Write { offset, data, .. } => {
                let length =
                    u32::try_from(data.len()).map_err(|_| ExportAuthorityError::Invalid)?;
                let end = validate_extent_span(*offset, length)?;
                if end > file.size {
                    return Err(ExportAuthorityError::Invalid);
                }
                Some(
                    self.extent_store
                        .write(
                            &mut transaction,
                            mutation.token.export.inode,
                            *offset,
                            data,
                            file.size,
                        )
                        .await
                        .map_err(|_| ExportAuthorityError::Storage)?,
                )
            }
            ExportMutationCommand::Trim { offset, length, .. }
            | ExportMutationCommand::WriteZeroes { offset, length, .. } => {
                let end = validate_extent_span(*offset, *length)?;
                if end > file.size {
                    return Err(ExportAuthorityError::Invalid);
                }
                self.extent_store
                    .zero_range(
                        &mut transaction,
                        mutation.token.export.inode,
                        *offset,
                        u64::from(*length),
                        file.size,
                    )
                    .await
                    .map_err(|_| ExportAuthorityError::Storage)?;
                None
            }
            ExportMutationCommand::Flush => None,
        };
        transaction.validate_export_scope(mutation.token.export.inode)?;
        Ok(PreparedExportMutation {
            transaction,
            tail_update,
            inode_guard: Some(inode_guard),
        })
    }

    async fn validate_admission(
        &self,
        token: &MutationFenceToken,
    ) -> Result<(), ExportAuthorityError> {
        let codec = crate::fs::key_codec::KeyCodec::new();
        let boot = self
            .db
            .get_bytes(&codec.export_boot_key())
            .await
            .map_err(|_| ExportAuthorityError::Storage)?;
        if boot.as_deref() != Some(self.server_boot_id.as_bytes()) {
            return Err(ExportAuthorityError::StaleMutation);
        }
        let key = codec.export_authority_key(&token.workspace_id);
        let current = read_record_current(&self.db, &key, &token.workspace_id).await?;
        validate_mutation(
            current.as_ref(),
            token,
            self.coordinator.export_authority_now(),
            &self.server_boot_id,
        )
    }

    #[cfg(test)]
    fn dst_pause_next_after_admission(&self) {
        self.pause_after_admission
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    async fn dst_wait_after_admission(&self) {
        self.entered_after_admission.notified().await;
    }

    #[cfg(test)]
    fn dst_release_after_admission(&self) {
        self.release_after_admission.notify_one();
    }

    #[cfg(test)]
    fn dst_prepared_mutations(&self) -> u64 {
        self.prepared_mutations
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn fence_mutation_conflict(
        &self,
        conflict: FenceMutationConflict,
        guard: ExportAdmissionGuard,
    ) -> Result<(), ExportAuthorityError> {
        self.coordinator
            .fence_mutation_conflict(conflict, guard)
            .await
    }

    async fn make_outcome_durable(
        &self,
        guard: ExportAdmissionGuard,
        key: &Bytes,
        expected: &ExportMutationExpectation,
        current: ExportMutationOutcome,
    ) -> Result<ExportMutationOutcome, ExportAuthorityError> {
        if let Some(durable) = read_outcome_durable(&self.db, key, expected).await? {
            ensure_outcome(&durable, expected)?;
            return Ok(durable);
        }
        self.coordinator
            .flush_export_mutation_barrier(guard)
            .await?;
        let durable = read_outcome_durable(&self.db, key, expected)
            .await?
            .ok_or(ExportAuthorityError::Corrupt)?;
        ensure_outcome(&durable, expected)?;
        if durable != current {
            return Err(ExportAuthorityError::Corrupt);
        }
        Ok(durable)
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
    )]
    pub(crate) async fn lookup_mutation_current(
        &self,
        expected: &ExportMutationExpectation,
    ) -> Result<ExportMutationLookup, ExportAuthorityError> {
        self.ensure_current_schema().await?;
        validate_expectation(expected)?;
        let key = mutation_outcome_key(expected);
        match read_outcome_current(&self.db, &key, expected).await? {
            Some(outcome) => {
                ensure_outcome(&outcome, expected)?;
                Ok(ExportMutationLookup::Committed(Box::new(outcome)))
            }
            None => Ok(ExportMutationLookup::Unknown),
        }
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
    )]
    pub(crate) async fn lookup_mutation_durable(
        &self,
        expected: &ExportMutationExpectation,
    ) -> Result<ExportMutationLookup, ExportAuthorityError> {
        self.ensure_current_schema().await?;
        validate_expectation(expected)?;
        let key = mutation_outcome_key(expected);
        match read_outcome_durable(&self.db, &key, expected).await? {
            Some(outcome) => {
                ensure_outcome(&outcome, expected)?;
                Ok(ExportMutationLookup::Committed(Box::new(outcome)))
            }
            None => Ok(ExportMutationLookup::Unknown),
        }
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified adapter wiring")
    )]
    pub(crate) async fn get(
        &self,
        workspace_id: &str,
    ) -> Result<Option<ExportAuthorityRecord>, ExportAuthorityError> {
        self.ensure_current_schema().await?;
        validate_id(workspace_id)?;
        let codec = crate::fs::key_codec::KeyCodec::new();
        let key = codec.export_authority_key(workspace_id);
        let current_boot = self
            .db
            .get_bytes_durable(&codec.export_boot_key())
            .await
            .map_err(|_| ExportAuthorityError::Storage)?;
        let mut record = read_record_durable(&self.db, &key, workspace_id).await?;
        if let Some(current) = record.as_ref() {
            let binding = reverse_binding_for(current);
            let (name_key, inode_key) = reverse_binding_keys(&binding);
            let by_name = read_reverse_binding_durable(&self.db, &name_key).await?;
            let by_inode = read_reverse_binding_durable(&self.db, &inode_key).await?;
            match (current.binding_initialized, by_name, by_inode) {
                (true, Some(name), Some(inode)) if name == binding && inode == binding => {}
                (false, None, None) => {}
                _ => return Err(ExportAuthorityError::Corrupt),
            }
        }
        if let Some(record) = record.as_mut()
            && (current_boot.as_deref() != Some(self.server_boot_id.as_bytes())
                || record
                    .active_session
                    .as_ref()
                    .is_some_and(|session| session.server_boot_id != self.server_boot_id))
        {
            record.rejected_through_placement_epoch = record
                .rejected_through_placement_epoch
                .max(record.authority.placement_epoch);
            record.active_session = None;
        }
        Ok(record)
    }

    /// Explicitly enable the standalone Rhizome export-authority profile.
    /// Ordinary ZeroFS and HA construction never call this implicitly.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified adapter wiring")
    )]
    pub(crate) fn install_process_guard(
        &self,
        process_guard: ShardProcessGuard,
    ) -> Result<(), ExportAuthorityError> {
        let mut installed = self.process_guard.lock().unwrap();
        if installed.is_some() {
            return Err(ExportAuthorityError::Conflict);
        }
        *installed = Some(process_guard);
        Ok(())
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "feature-staged until verified adapter wiring")
    )]
    pub(crate) async fn enable_standalone_profile(&self) -> Result<(), ExportAuthorityError> {
        let _enable = self.enable_lock.lock().await;
        if self.process_guard.lock().unwrap().is_none() {
            return Err(ExportAuthorityError::ProfileDisabled);
        }
        if self
            .profile_enabled
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }
        self.ensure_current_schema().await?;
        self.coordinator.initialize_export_boot().await?;
        self.profile_enabled
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    async fn ensure_current_schema(&self) -> Result<(), ExportAuthorityError> {
        let mut legacy = self
            .db
            .scan_prefix(KeyCodec::new().legacy_export_v1_prefix(), None, 4 * 1024)
            .await
            .map_err(|_| ExportAuthorityError::Storage)?;
        if legacy
            .next()
            .await
            .transpose()
            .map_err(|_| ExportAuthorityError::Storage)?
            .is_some()
        {
            Err(ExportAuthorityError::MigrationRequired)
        } else {
            Ok(())
        }
    }

    fn require_enabled(&self) -> Result<(), ExportAuthorityError> {
        if self
            .profile_enabled
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Ok(())
        } else {
            Err(ExportAuthorityError::ProfileDisabled)
        }
    }
}

fn validate_extent_span(offset: u64, length: u32) -> Result<u64, ExportAuthorityError> {
    let end = offset
        .checked_add(u64::from(length))
        .ok_or(ExportAuthorityError::Invalid)?;
    if length == 0 {
        return Ok(end);
    }
    let extent_size = crate::fs::EXTENT_SIZE as u64;
    let last = end - 1;
    let extent_start = (last / extent_size) * extent_size;
    extent_start
        .checked_add(extent_size)
        .ok_or(ExportAuthorityError::Invalid)?;
    Ok(end)
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "feature-staged until verified NBD adapter wiring")
)]
fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; SHA256_SIZE] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

fn command_digest(
    token: &MutationFenceToken,
    operation_id: [u8; SHA256_SIZE],
    command: &ExportMutationCommand,
    data_checksum: &DataChecksum,
) -> [u8; SHA256_SIZE] {
    fn field(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }

    let mut hash = Sha256::new();
    hash.update(COMMAND_DIGEST_DOMAIN);
    field(&mut hash, token.workspace_id.as_bytes());
    field(&mut hash, &token.export.name);
    hash.update(token.export.inode.to_be_bytes());
    field(&mut hash, token.authority.actor.as_bytes());
    hash.update(token.authority.actor_generation.to_be_bytes());
    field(&mut hash, token.authority.home_cell.as_bytes());
    hash.update(token.authority.home_revision.to_be_bytes());
    hash.update(token.authority.authority_epoch.to_be_bytes());
    hash.update(token.authority.placement_epoch.to_be_bytes());
    hash.update(token.authority.assignment_revision.to_be_bytes());
    field(&mut hash, token.session_id.as_bytes());
    field(&mut hash, token.capability_id.as_bytes());
    hash.update(token.expires_at_unix_millis.to_be_bytes());
    field(&mut hash, token.node_incarnation_id.as_bytes());
    field(&mut hash, token.runtime_id.as_bytes());
    field(&mut hash, token.server_boot_id.as_bytes());
    hash.update(operation_id);
    match command {
        ExportMutationCommand::Write { offset, data, fua } => {
            hash.update([1, u8::from(*fua)]);
            hash.update(offset.to_be_bytes());
            hash.update((data.len() as u64).to_be_bytes());
        }
        ExportMutationCommand::Flush => hash.update([2, 0]),
        ExportMutationCommand::Trim {
            offset,
            length,
            fua,
        } => {
            hash.update([3, u8::from(*fua)]);
            hash.update(offset.to_be_bytes());
            hash.update(length.to_be_bytes());
        }
        ExportMutationCommand::WriteZeroes {
            offset,
            length,
            fua,
        } => {
            hash.update([4, u8::from(*fua)]);
            hash.update(offset.to_be_bytes());
            hash.update(length.to_be_bytes());
        }
    };
    hash.update(data_checksum.0);
    hash.finalize().into()
}

#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "feature-staged until verified adapter wiring")
)]
pub(crate) enum ExportAuthorityTransition {
    Activate(ActivateExport),
    Refresh(RefreshExport),
    Deactivate(DeactivateExport),
    AdvanceFence(AdvanceFence),
}

impl ExportAuthorityTransition {
    pub(crate) fn workspace_id(&self) -> &str {
        match self {
            Self::Activate(c) => &c.workspace_id,
            Self::Refresh(c) => &c.workspace_id,
            Self::Deactivate(c) => &c.workspace_id,
            Self::AdvanceFence(c) => &c.workspace_id,
        }
    }
}

pub(crate) async fn read_record_current(
    db: &Db,
    key: &Bytes,
    workspace_id: &str,
) -> Result<Option<ExportAuthorityRecord>, ExportAuthorityError> {
    let Some(bytes) = db
        .get_bytes(key)
        .await
        .map_err(|_| ExportAuthorityError::Storage)?
    else {
        return Ok(None);
    };
    decode_record(&bytes, workspace_id).map(Some)
}

async fn read_record_durable(
    db: &Db,
    key: &Bytes,
    workspace_id: &str,
) -> Result<Option<ExportAuthorityRecord>, ExportAuthorityError> {
    let Some(bytes) = db
        .get_bytes_durable(key)
        .await
        .map_err(|_| ExportAuthorityError::Storage)?
    else {
        return Ok(None);
    };
    decode_record(&bytes, workspace_id).map(Some)
}

pub(crate) async fn read_outcome_current(
    db: &Db,
    key: &Bytes,
    expected: &ExportMutationExpectation,
) -> Result<Option<ExportMutationOutcome>, ExportAuthorityError> {
    let Some(bytes) = db
        .get_bytes(key)
        .await
        .map_err(|_| ExportAuthorityError::Storage)?
    else {
        return Ok(None);
    };
    decode_outcome(&bytes, expected).map(Some)
}

pub(crate) async fn read_reverse_binding_current(
    db: &Db,
    key: &Bytes,
) -> Result<Option<ExportReverseBinding>, ExportAuthorityError> {
    let Some(bytes) = db
        .get_bytes(key)
        .await
        .map_err(|_| ExportAuthorityError::Storage)?
    else {
        return Ok(None);
    };
    decode_reverse_binding(&bytes, key).map(Some)
}

async fn read_reverse_binding_durable(
    db: &Db,
    key: &Bytes,
) -> Result<Option<ExportReverseBinding>, ExportAuthorityError> {
    let Some(bytes) = db
        .get_bytes_durable(key)
        .await
        .map_err(|_| ExportAuthorityError::Storage)?
    else {
        return Ok(None);
    };
    decode_reverse_binding(&bytes, key).map(Some)
}

pub(crate) fn reverse_binding_for(record: &ExportAuthorityRecord) -> ExportReverseBinding {
    ExportReverseBinding {
        workspace_id: record.workspace_id.clone(),
        actor: record.authority.actor.clone(),
        actor_generation: record.authority.actor_generation,
        export: record.export.clone(),
    }
}

pub(crate) fn reverse_binding_keys(binding: &ExportReverseBinding) -> (Bytes, Bytes) {
    let codec = KeyCodec::new();
    (
        codec.export_reverse_name_key(
            binding.export.nbd_directory_inode,
            binding.export.name.as_slice(),
        ),
        codec.export_reverse_inode_key(binding.export.inode),
    )
}

pub(crate) fn mutation_outcome_key(expected: &ExportMutationExpectation) -> Bytes {
    KeyCodec::new().export_mutation_outcome_key(&ExportMutationKey {
        workspace_id: &expected.workspace_id,
        actor: &expected.authority.actor,
        actor_generation: expected.authority.actor_generation,
        placement_epoch: expected.authority.placement_epoch,
        session_id: &expected.session_id,
        server_boot_id: &expected.server_boot_id,
        operation_id: expected.mutation.operation_id.0,
    })
}

async fn read_outcome_durable(
    db: &Db,
    key: &Bytes,
    expected: &ExportMutationExpectation,
) -> Result<Option<ExportMutationOutcome>, ExportAuthorityError> {
    let Some(bytes) = db
        .get_bytes_durable(key)
        .await
        .map_err(|_| ExportAuthorityError::Storage)?
    else {
        return Ok(None);
    };
    decode_outcome(&bytes, expected).map(Some)
}

pub(crate) fn apply_transition(
    existing: Option<ExportAuthorityRecord>,
    transition: ExportAuthorityTransition,
    now: u64,
    server_boot_id: &str,
) -> Result<ExportAuthorityRecord, ExportAuthorityError> {
    validate_id(transition.workspace_id())?;
    match transition {
        ExportAuthorityTransition::Activate(mut command) => {
            command.session.server_boot_id = server_boot_id.to_owned();
            command.session.committed_through_sequence = 0;
            validate_authority(&command.authority)?;
            validate_session(&command.session, now)?;
            let desired = ExportAuthorityRecord {
                workspace_id: command.workspace_id,
                export: command.export,
                authority: command.authority,
                rejected_through_placement_epoch: existing
                    .as_ref()
                    .map_or(0, |r| r.rejected_through_placement_epoch),
                binding_initialized: true,
                active_session: Some(command.session),
            };
            if let Some(current) = existing {
                validate_record(&current)?;
                if current == desired {
                    return Ok(current);
                }
                if current.workspace_id != desired.workspace_id
                    || current.export != desired.export
                    || !monotonic_authority(&current.authority, &desired.authority)
                    || current.active_session.is_some()
                    || desired.authority.placement_epoch <= current.rejected_through_placement_epoch
                {
                    return Err(ExportAuthorityError::Conflict);
                }
            }
            Ok(desired)
        }
        ExportAuthorityTransition::Refresh(command) => {
            validate_authority(&command.expected_authority)?;
            validate_id(&command.session_id)?;
            validate_id(&command.expected_capability_id)?;
            validate_id(&command.replacement_capability_id)?;
            validate_authority(&command.replacement_authority)?;
            let mut current = existing.ok_or(ExportAuthorityError::NotFound)?;
            validate_record(&current)?;
            let session = current
                .active_session
                .as_mut()
                .ok_or(ExportAuthorityError::Conflict)?;
            if current.workspace_id != command.workspace_id
                || current.export != command.expected_export
                || current.authority != command.expected_authority
                || session.session_id != command.session_id
                || session.capability_id != command.expected_capability_id
                || command.replacement_capability_id == command.expected_capability_id
                || session.server_boot_id != server_boot_id
                || session.expires_at_unix_millis <= now
                || !same_placement_renewal(&current.authority, &command.replacement_authority)
                || command.replacement_expires_at_unix_millis <= session.expires_at_unix_millis
                || command.replacement_expires_at_unix_millis <= now
            {
                return Err(ExportAuthorityError::Conflict);
            }
            session.capability_id = command.replacement_capability_id;
            session.expires_at_unix_millis = command.replacement_expires_at_unix_millis;
            current.authority = command.replacement_authority;
            Ok(current)
        }
        ExportAuthorityTransition::Deactivate(command) => {
            validate_authority(&command.expected_authority)?;
            validate_id(&command.session_id)?;
            let mut current = existing.ok_or(ExportAuthorityError::NotFound)?;
            validate_record(&current)?;
            let session = current
                .active_session
                .as_ref()
                .ok_or(ExportAuthorityError::Conflict)?;
            if current.workspace_id != command.workspace_id
                || current.export != command.expected_export
                || current.authority != command.expected_authority
                || session.session_id != command.session_id
            {
                return Err(ExportAuthorityError::Conflict);
            }
            current.rejected_through_placement_epoch = current
                .rejected_through_placement_epoch
                .max(current.authority.placement_epoch);
            current.active_session = None;
            Ok(current)
        }
        ExportAuthorityTransition::AdvanceFence(command) => {
            validate_authority(&command.new_non_writable_authority)?;
            if command.reject_through_placement_epoch == 0
                || command.reject_through_placement_epoch
                    < command.new_non_writable_authority.placement_epoch
            {
                return Err(ExportAuthorityError::Invalid);
            }
            match existing {
                None if command.expected_authority.is_none() => Ok(ExportAuthorityRecord {
                    workspace_id: command.workspace_id,
                    export: command.export,
                    authority: command.new_non_writable_authority,
                    rejected_through_placement_epoch: command.reject_through_placement_epoch,
                    binding_initialized: false,
                    active_session: None,
                }),
                Some(mut current) => {
                    validate_record(&current)?;
                    let valid_authority = command.new_non_writable_authority == current.authority
                        || monotonic_authority(
                            &current.authority,
                            &command.new_non_writable_authority,
                        );
                    if command.expected_authority.as_ref() != Some(&current.authority)
                        || current.workspace_id != command.workspace_id
                        || current.export != command.export
                        || !valid_authority
                        || command.reject_through_placement_epoch
                            < current.rejected_through_placement_epoch
                    {
                        return Err(ExportAuthorityError::Conflict);
                    }
                    current.authority = command.new_non_writable_authority;
                    current.rejected_through_placement_epoch =
                        command.reject_through_placement_epoch;
                    current.active_session = None;
                    Ok(current)
                }
                _ => Err(ExportAuthorityError::Conflict),
            }
        }
    }
}

pub(crate) fn validate_mutation(
    current: Option<&ExportAuthorityRecord>,
    token: &MutationFenceToken,
    now: u64,
    server_boot_id: &str,
) -> Result<(), ExportAuthorityError> {
    validate_id(&token.workspace_id).map_err(|_| ExportAuthorityError::StaleMutation)?;
    validate_export(&token.export).map_err(|_| ExportAuthorityError::StaleMutation)?;
    validate_authority(&token.authority).map_err(|_| ExportAuthorityError::StaleMutation)?;
    validate_id(&token.session_id).map_err(|_| ExportAuthorityError::StaleMutation)?;
    validate_id(&token.capability_id).map_err(|_| ExportAuthorityError::StaleMutation)?;
    validate_id(&token.node_incarnation_id).map_err(|_| ExportAuthorityError::StaleMutation)?;
    validate_id(&token.runtime_id).map_err(|_| ExportAuthorityError::StaleMutation)?;
    let Some(current) = current else {
        return Err(ExportAuthorityError::StaleMutation);
    };
    validate_record(current)?;
    let Some(session) = current.active_session.as_ref() else {
        return Err(ExportAuthorityError::StaleMutation);
    };
    if token.expires_at_unix_millis <= now
        || token.workspace_id != current.workspace_id
        || token.export != current.export
        || token.authority != current.authority
        || token.authority.placement_epoch <= current.rejected_through_placement_epoch
        || token.session_id != session.session_id
        || token.capability_id != session.capability_id
        || token.expires_at_unix_millis != session.expires_at_unix_millis
        || token.node_incarnation_id != session.node_incarnation_id
        || token.runtime_id != session.runtime_id
        || token.server_boot_id != session.server_boot_id
        || session.server_boot_id != server_boot_id
    {
        return Err(ExportAuthorityError::StaleMutation);
    }
    Ok(())
}

pub(crate) fn trusted_now_unix_millis() -> u64 {
    let (seconds, nanos) = crate::fs::get_current_time();
    seconds
        .saturating_mul(1_000)
        .saturating_add(u64::from(nanos / 1_000_000))
}

pub(crate) fn encode_record(record: &ExportAuthorityRecord) -> Result<Bytes, ExportAuthorityError> {
    validate_record(record)?;
    let payload = codec()
        .serialize(record)
        .map_err(|_| ExportAuthorityError::Corrupt)?;
    let key = crate::fs::key_codec::KeyCodec::new().export_authority_key(&record.workspace_id);
    encode_bound_record(AUTHORITY_RECORD_MAGIC, &key, &payload)
}

pub(crate) fn encode_outcome(
    outcome: &ExportMutationOutcome,
) -> Result<Bytes, ExportAuthorityError> {
    validate_outcome(outcome)?;
    let payload = codec()
        .serialize(outcome)
        .map_err(|_| ExportAuthorityError::Corrupt)?;
    let key = KeyCodec::new().export_mutation_outcome_key(&ExportMutationKey {
        workspace_id: &outcome.workspace_id,
        actor: &outcome.authority.actor,
        actor_generation: outcome.authority.actor_generation,
        placement_epoch: outcome.authority.placement_epoch,
        session_id: &outcome.session_id,
        server_boot_id: &outcome.server_boot_id,
        operation_id: outcome.mutation.operation_id.0,
    });
    encode_bound_record(MUTATION_OUTCOME_MAGIC, &key, &payload)
}

pub(crate) fn encode_reverse_binding(
    binding: &ExportReverseBinding,
    key: &Bytes,
) -> Result<Bytes, ExportAuthorityError> {
    validate_reverse_binding(binding)?;
    let (name_key, inode_key) = reverse_binding_keys(binding);
    if key != &name_key && key != &inode_key {
        return Err(ExportAuthorityError::Corrupt);
    }
    let payload = codec()
        .serialize(binding)
        .map_err(|_| ExportAuthorityError::Corrupt)?;
    encode_bound_record(REVERSE_BINDING_MAGIC, key, &payload)
}

pub(crate) fn decode_record(
    bytes: &[u8],
    expected_workspace_id: &str,
) -> Result<ExportAuthorityRecord, ExportAuthorityError> {
    let key = crate::fs::key_codec::KeyCodec::new().export_authority_key(expected_workspace_id);
    let payload = decode_bound_record(AUTHORITY_RECORD_MAGIC, &key, bytes)?;
    let record: ExportAuthorityRecord = codec()
        .deserialize(payload)
        .map_err(|_| ExportAuthorityError::Corrupt)?;
    validate_record(&record)?;
    if record.workspace_id != expected_workspace_id {
        return Err(ExportAuthorityError::Corrupt);
    }
    Ok(record)
}

fn decode_outcome(
    bytes: &[u8],
    expected: &ExportMutationExpectation,
) -> Result<ExportMutationOutcome, ExportAuthorityError> {
    let key = mutation_outcome_key(expected);
    let payload = decode_bound_record(MUTATION_OUTCOME_MAGIC, &key, bytes)?;
    let outcome: ExportMutationOutcome = codec()
        .deserialize(payload)
        .map_err(|_| ExportAuthorityError::Corrupt)?;
    validate_outcome(&outcome)?;
    if outcome.workspace_id != expected.workspace_id
        || outcome.session_id != expected.session_id
        || outcome.mutation.operation_id != expected.mutation.operation_id
    {
        return Err(ExportAuthorityError::Corrupt);
    }
    Ok(outcome)
}

pub(crate) fn decode_reverse_binding(
    bytes: &[u8],
    key: &Bytes,
) -> Result<ExportReverseBinding, ExportAuthorityError> {
    let payload = decode_bound_record(REVERSE_BINDING_MAGIC, key, bytes)?;
    let binding: ExportReverseBinding = codec()
        .deserialize(payload)
        .map_err(|_| ExportAuthorityError::Corrupt)?;
    validate_reverse_binding(&binding)?;
    let (name_key, inode_key) = reverse_binding_keys(&binding);
    if key != &name_key && key != &inode_key {
        return Err(ExportAuthorityError::Corrupt);
    }
    Ok(binding)
}

fn encode_bound_record(
    magic: &[u8; 4],
    key: &[u8],
    payload: &[u8],
) -> Result<Bytes, ExportAuthorityError> {
    if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(ExportAuthorityError::Corrupt);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| ExportAuthorityError::Corrupt)?;
    let key_digest: [u8; SHA256_SIZE] = Sha256::digest(key).into();
    let mut encoded =
        Vec::with_capacity(magic.len() + 1 + key_digest.len() + 4 + payload.len() + SHA256_SIZE);
    encoded.extend_from_slice(magic);
    encoded.push(RECORD_VERSION);
    encoded.extend_from_slice(&key_digest);
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    encoded.extend_from_slice(payload);
    let checksum = envelope_checksum(&encoded);
    encoded.extend_from_slice(&checksum);
    Ok(Bytes::from(encoded))
}

fn decode_bound_record<'a>(
    magic: &[u8; 4],
    key: &[u8],
    bytes: &'a [u8],
) -> Result<&'a [u8], ExportAuthorityError> {
    let header_len = magic.len() + 1 + SHA256_SIZE + 4;
    if bytes.len() < header_len + SHA256_SIZE
        || !bytes.starts_with(magic)
        || bytes.get(magic.len()).copied() != Some(RECORD_VERSION)
    {
        return Err(ExportAuthorityError::Corrupt);
    }
    let key_digest_start = magic.len() + 1;
    let key_digest_end = key_digest_start + SHA256_SIZE;
    let expected_key_digest: [u8; SHA256_SIZE] = Sha256::digest(key).into();
    if bytes[key_digest_start..key_digest_end] != expected_key_digest {
        return Err(ExportAuthorityError::Corrupt);
    }
    let payload_len = u32::from_be_bytes(
        bytes[key_digest_end..header_len]
            .try_into()
            .map_err(|_| ExportAuthorityError::Corrupt)?,
    ) as usize;
    if payload_len > MAX_RECORD_PAYLOAD_BYTES
        || bytes.len() != header_len + payload_len + SHA256_SIZE
    {
        return Err(ExportAuthorityError::Corrupt);
    }
    let checksum_start = header_len + payload_len;
    if bytes[checksum_start..] != envelope_checksum(&bytes[..checksum_start]) {
        return Err(ExportAuthorityError::Corrupt);
    }
    Ok(&bytes[header_len..checksum_start])
}

fn envelope_checksum(envelope_without_checksum: &[u8]) -> [u8; SHA256_SIZE] {
    let mut hash = Sha256::new();
    hash.update(ENVELOPE_CHECKSUM_DOMAIN);
    hash.update(envelope_without_checksum);
    hash.finalize().into()
}

fn validate_expectation(expected: &ExportMutationExpectation) -> Result<(), ExportAuthorityError> {
    validate_id(&expected.workspace_id)?;
    validate_export(&expected.export)?;
    validate_authority(&expected.authority)?;
    validate_id(&expected.session_id)?;
    validate_id(&expected.server_boot_id)?;
    if expected.mutation.operation_id.0 == [0; SHA256_SIZE] {
        return Err(ExportAuthorityError::Invalid);
    }
    Ok(())
}

fn validate_outcome(outcome: &ExportMutationOutcome) -> Result<(), ExportAuthorityError> {
    validate_id(&outcome.workspace_id)?;
    validate_export(&outcome.export)?;
    validate_authority(&outcome.authority)?;
    validate_id(&outcome.session_id)?;
    validate_id(&outcome.server_boot_id)?;
    if outcome.mutation.operation_id.0 == [0; SHA256_SIZE] || outcome.mutation.sequence == 0 {
        return Err(ExportAuthorityError::Corrupt);
    }
    Ok(())
}

pub(crate) fn ensure_outcome(
    outcome: &ExportMutationOutcome,
    expected: &ExportMutationExpectation,
) -> Result<(), ExportAuthorityError> {
    validate_expectation(expected)?;
    if outcome.workspace_id == expected.workspace_id
        && outcome.export == expected.export
        && outcome.authority == expected.authority
        && outcome.session_id == expected.session_id
        && outcome.server_boot_id == expected.server_boot_id
        && outcome.mutation.operation_id == expected.mutation.operation_id
        && outcome.mutation.command_digest == expected.mutation.command_digest
        && outcome.mutation.data_checksum == expected.mutation.data_checksum
        && outcome.kind == expected.kind
    {
        Ok(())
    } else {
        Err(ExportAuthorityError::Conflict)
    }
}

fn validate_record(record: &ExportAuthorityRecord) -> Result<(), ExportAuthorityError> {
    validate_id(&record.workspace_id)?;
    validate_export(&record.export)?;
    validate_authority(&record.authority)?;
    if record.rejected_through_placement_epoch > record.authority.placement_epoch
        && record.active_session.is_some()
    {
        return Err(ExportAuthorityError::Corrupt);
    }
    if let Some(session) = &record.active_session {
        if !record.binding_initialized {
            return Err(ExportAuthorityError::Corrupt);
        }
        validate_session(session, 0)?;
        if record.authority.placement_epoch <= record.rejected_through_placement_epoch {
            return Err(ExportAuthorityError::Corrupt);
        }
    }
    Ok(())
}

fn validate_export(export: &ExportIdentity) -> Result<(), ExportAuthorityError> {
    if export.name.is_empty()
        || export.name.len() > MAX_ID_BYTES
        || export.name.contains(&0)
        || export.nbd_directory_inode == 0
        || export.inode == 0
    {
        return Err(ExportAuthorityError::Invalid);
    }
    Ok(())
}

fn validate_reverse_binding(binding: &ExportReverseBinding) -> Result<(), ExportAuthorityError> {
    validate_id(&binding.workspace_id)?;
    validate_id(&binding.actor)?;
    validate_export(&binding.export)?;
    if binding.actor_generation == 0 {
        return Err(ExportAuthorityError::Invalid);
    }
    Ok(())
}

fn validate_authority(authority: &AuthorityVersion) -> Result<(), ExportAuthorityError> {
    validate_id(&authority.actor)?;
    validate_id(&authority.home_cell)?;
    if authority.actor_generation == 0
        || authority.home_revision == 0
        || authority.authority_epoch == 0
        || authority.placement_epoch == 0
        || authority.assignment_revision == 0
    {
        return Err(ExportAuthorityError::Invalid);
    }
    Ok(())
}

fn validate_session(session: &ExportSessionState, now: u64) -> Result<(), ExportAuthorityError> {
    validate_id(&session.session_id)?;
    validate_id(&session.capability_id)?;
    validate_id(&session.node_incarnation_id)?;
    validate_id(&session.runtime_id)?;
    validate_id(&session.server_boot_id)?;
    if session.expires_at_unix_millis <= now {
        return Err(ExportAuthorityError::Invalid);
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), ExportAuthorityError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.as_bytes().contains(&0) {
        return Err(ExportAuthorityError::Invalid);
    }
    Ok(())
}

fn monotonic_authority(current: &AuthorityVersion, next: &AuthorityVersion) -> bool {
    non_regressing_authority(current, next)
        && next.placement_epoch > current.placement_epoch
        && next.assignment_revision > current.assignment_revision
}

fn non_regressing_authority(current: &AuthorityVersion, next: &AuthorityVersion) -> bool {
    current.actor == next.actor
        && current.actor_generation == next.actor_generation
        && current.home_cell == next.home_cell
        && next.home_revision >= current.home_revision
        && next.authority_epoch >= current.authority_epoch
        && next.placement_epoch >= current.placement_epoch
        && next.assignment_revision >= current.assignment_revision
}

fn same_placement_renewal(current: &AuthorityVersion, next: &AuthorityVersion) -> bool {
    current.actor == next.actor
        && current.actor_generation == next.actor_generation
        && current.home_cell == next.home_cell
        && current.home_revision == next.home_revision
        && current.authority_epoch == next.authority_epoch
        && current.placement_epoch == next.placement_epoch
        && next.assignment_revision > current.assignment_revision
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

/// Deterministic transition-model sweep used by the repository DST binary.
#[cfg(dst)]
#[doc(hidden)]
pub fn dst_export_authority_model(seed: u64) {
    let base = seed % 10_000 + 1;
    let version = AuthorityVersion {
        actor: format!("tenants/t/actors/{seed}"),
        actor_generation: base,
        home_cell: "cells/dst".into(),
        home_revision: base,
        authority_epoch: base,
        placement_epoch: base,
        assignment_revision: base,
    };
    let active = apply_transition(
        None,
        ExportAuthorityTransition::Activate(ActivateExport {
            workspace_id: format!("workspace-{seed}"),
            export: ExportIdentity {
                nbd_directory_inode: base.saturating_add(1),
                name: format!("export-{seed}").into_bytes(),
                inode: base,
                advertised_size: base,
            },
            authority: version.clone(),
            session: ExportSessionState {
                session_id: format!("session-{seed}"),
                capability_id: format!("capability-{seed}"),
                expires_at_unix_millis: u64::MAX,
                node_incarnation_id: format!("node-{seed}"),
                runtime_id: format!("runtime-{seed}"),
                server_boot_id: "caller-overwritten".into(),
                committed_through_sequence: 0,
            },
        }),
        base,
        "dst-boot",
    )
    .expect("DST activation");
    let session = active.active_session.as_ref().unwrap();
    let mut token = MutationFenceToken {
        workspace_id: active.workspace_id.clone(),
        export: active.export.clone(),
        authority: active.authority.clone(),
        session_id: session.session_id.clone(),
        capability_id: session.capability_id.clone(),
        expires_at_unix_millis: session.expires_at_unix_millis,
        node_incarnation_id: session.node_incarnation_id.clone(),
        runtime_id: session.runtime_id.clone(),
        server_boot_id: session.server_boot_id.clone(),
    };
    validate_mutation(Some(&active), &token, base, "dst-boot").expect("DST live token");
    token.authority.assignment_revision += 1;
    assert_eq!(
        validate_mutation(Some(&active), &token, base, "dst-boot"),
        Err(ExportAuthorityError::StaleMutation)
    );
    let fenced = apply_transition(
        Some(active.clone()),
        ExportAuthorityTransition::AdvanceFence(AdvanceFence {
            workspace_id: active.workspace_id.clone(),
            export: active.export.clone(),
            expected_authority: Some(active.authority.clone()),
            new_non_writable_authority: active.authority,
            reject_through_placement_epoch: base,
        }),
        base,
        "dst-boot",
    )
    .expect("DST fence");
    assert!(fenced.active_session.is_none());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_transformer::ZeroFsBlockTransformer;
    use crate::config::CompressionConfig;
    use crate::db::SlateDbHandle;
    use crate::db::Transaction;
    use crate::frame_codec::FrameCodec;
    use crate::fs::ZeroFS;
    use crate::fs::inode::test_file_inode;
    use bytes::Bytes;
    use futures::TryStreamExt;
    use proptest::prelude::*;
    use slatedb::object_store::ObjectStoreExt;
    use slatedb::object_store::path::Path;
    use slatedb::{BlockTransformer, DbBuilder};

    const NOW: u64 = 1_000;
    const BOOT: &str = "server-boot-a";

    fn export(inode: u64) -> ExportIdentity {
        ExportIdentity {
            nbd_directory_inode: 1,
            name: b"disk-a".to_vec(),
            inode,
            advertised_size: 4096,
        }
    }

    fn export_with_size(directory_inode: u64, inode: u64, size: u64) -> ExportIdentity {
        ExportIdentity {
            nbd_directory_inode: directory_inode,
            name: b"disk-a".to_vec(),
            inode,
            advertised_size: size,
        }
    }

    fn authority(placement_epoch: u64, assignment_revision: u64) -> AuthorityVersion {
        AuthorityVersion {
            actor: "tenants/t/actors/a".into(),
            actor_generation: 7,
            home_cell: "cells/c".into(),
            home_revision: 11,
            authority_epoch: 13,
            placement_epoch,
            assignment_revision,
        }
    }

    fn session(id: &str, capability: &str, expires: u64) -> ExportSessionState {
        ExportSessionState {
            session_id: id.into(),
            capability_id: capability.into(),
            expires_at_unix_millis: expires,
            node_incarnation_id: "node-incarnation-a".into(),
            runtime_id: "runtime-a".into(),
            server_boot_id: "caller-value-is-replaced".into(),
            committed_through_sequence: 0,
        }
    }

    fn activate_command(version: AuthorityVersion) -> ActivateExport {
        activate_command_for(version, export(2))
    }

    fn activate_command_for(version: AuthorityVersion, export: ExportIdentity) -> ActivateExport {
        ActivateExport {
            workspace_id: "workspace-a".into(),
            export,
            authority: version,
            session: session("session-a", "capability-a", u64::MAX - 1),
        }
    }

    fn token(record: &ExportAuthorityRecord) -> MutationFenceToken {
        let session = record.active_session.as_ref().unwrap();
        MutationFenceToken {
            workspace_id: record.workspace_id.clone(),
            export: record.export.clone(),
            authority: record.authority.clone(),
            session_id: session.session_id.clone(),
            capability_id: session.capability_id.clone(),
            expires_at_unix_millis: session.expires_at_unix_millis,
            node_incarnation_id: session.node_incarnation_id.clone(),
            runtime_id: session.runtime_id.clone(),
            server_boot_id: session.server_boot_id.clone(),
        }
    }

    fn mutation_for(
        record: &ExportAuthorityRecord,
        transaction: Transaction,
        kind: MutationKind,
        ordinal: u8,
    ) -> ExportMutation {
        let command = match kind {
            MutationKind::Write { fua } => ExportMutationCommand::Write {
                offset: u64::from(ordinal),
                data: Bytes::from(vec![b'd', ordinal]),
                fua,
            },
            MutationKind::Flush => ExportMutationCommand::Flush,
            MutationKind::Trim { fua } => ExportMutationCommand::Trim {
                offset: u64::from(ordinal),
                length: 1,
                fua,
            },
            MutationKind::WriteZeroes { fua } => ExportMutationCommand::WriteZeroes {
                offset: u64::from(ordinal),
                length: 1,
                fua,
            },
        };
        ExportMutationBuilder::from_transaction_for_test(
            token(record),
            [ordinal; SHA256_SIZE],
            command,
            transaction,
        )
        .unwrap()
    }

    async fn open_fs(
        object_store: Arc<dyn slatedb::object_store::ObjectStore>,
    ) -> anyhow::Result<ZeroFS> {
        let test_key = [0u8; 32];
        let transformer: Arc<dyn BlockTransformer> =
            ZeroFsBlockTransformer::try_new_arc(&test_key, CompressionConfig::default())?;
        let db = Arc::new(
            DbBuilder::new(Path::from("export-authority-reopen"), object_store.clone())
                .with_block_transformer(transformer)
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
        let fs = ZeroFS::new_with_slatedb(
            SlateDbHandle::ReadWrite(db),
            u64::MAX,
            None,
            false,
            object_store,
            segment_codec,
        )
        .await?;
        fs.export_authority
            .install_process_guard(ShardProcessGuard::for_test())?;
        fs.export_authority.enable_standalone_profile().await?;
        ensure_test_export(&fs, 4096).await?;
        Ok(fs)
    }

    async fn new_export_fs() -> ZeroFS {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.export_authority
            .install_process_guard(ShardProcessGuard::for_test())
            .unwrap();
        fs.export_authority
            .enable_standalone_profile()
            .await
            .unwrap();
        ensure_test_export(&fs, 4096).await.unwrap();
        fs
    }

    async fn ensure_test_export(
        fs: &ZeroFS,
        size: u64,
    ) -> Result<ExportIdentity, crate::fs::errors::FsError> {
        let creds = crate::fs::test_util::test_creds();
        let directory_inode = match fs.lookup(&creds, 0, b".nbd").await {
            Ok(inode) => inode,
            Err(crate::fs::errors::FsError::NotFound) => {
                fs.mkdir(
                    &creds,
                    0,
                    b".nbd",
                    &crate::fs::types::SetAttributes::default(),
                )
                .await?
                .0
            }
            Err(error) => return Err(error),
        };
        let inode = match fs.lookup(&creds, directory_inode, b"disk-a").await {
            Ok(inode) => inode,
            Err(crate::fs::errors::FsError::NotFound) => {
                let inode = fs
                    .create(
                        &creds,
                        directory_inode,
                        b"disk-a",
                        &crate::fs::types::SetAttributes::default(),
                    )
                    .await?
                    .0;
                if size != 0 {
                    fs.write(
                        &crate::fs::types::AuthContext::default(),
                        inode,
                        size - 1,
                        &Bytes::from_static(&[0]),
                    )
                    .await?;
                }
                inode
            }
            Err(error) => return Err(error),
        };
        let current = fs.inode_store.get(inode).await?;
        Ok(export_with_size(directory_inode, inode, current.size()))
    }

    async fn snapshot_object_store(
        source: &Arc<dyn slatedb::object_store::ObjectStore>,
    ) -> Arc<dyn slatedb::object_store::ObjectStore> {
        let snapshot = Arc::new(slatedb::object_store::memory::InMemory::new());
        let objects = source.list(None).try_collect::<Vec<_>>().await.unwrap();
        for object in objects {
            let bytes = source
                .get(&object.location)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            snapshot.put(&object.location, bytes.into()).await.unwrap();
        }
        snapshot
    }

    #[test]
    fn deterministic_state_model_rejects_regressions_and_future_mutations() {
        let active = apply_transition(
            None,
            ExportAuthorityTransition::Activate(activate_command(authority(3, 5))),
            NOW,
            BOOT,
        )
        .unwrap();

        let mut future = token(&active);
        future.authority.placement_epoch = 4;
        assert_eq!(
            validate_mutation(Some(&active), &future, NOW, BOOT),
            Err(ExportAuthorityError::StaleMutation)
        );

        let fenced = apply_transition(
            Some(active.clone()),
            ExportAuthorityTransition::AdvanceFence(AdvanceFence {
                workspace_id: active.workspace_id.clone(),
                export: active.export.clone(),
                expected_authority: Some(active.authority.clone()),
                new_non_writable_authority: authority(3, 5),
                reject_through_placement_epoch: 3,
            }),
            NOW,
            BOOT,
        )
        .unwrap();
        assert!(fenced.active_session.is_none());
        assert_eq!(
            validate_mutation(Some(&fenced), &token(&active), NOW, BOOT),
            Err(ExportAuthorityError::StaleMutation)
        );

        assert_eq!(
            apply_transition(
                Some(fenced.clone()),
                ExportAuthorityTransition::AdvanceFence(AdvanceFence {
                    workspace_id: fenced.workspace_id.clone(),
                    export: fenced.export.clone(),
                    expected_authority: Some(fenced.authority.clone()),
                    new_non_writable_authority: authority(2, 4),
                    reject_through_placement_epoch: 3,
                }),
                NOW,
                BOOT,
            ),
            Err(ExportAuthorityError::Conflict)
        );

        assert_eq!(
            apply_transition(
                Some(fenced.clone()),
                ExportAuthorityTransition::AdvanceFence(AdvanceFence {
                    workspace_id: fenced.workspace_id.clone(),
                    export: fenced.export.clone(),
                    expected_authority: Some(fenced.authority.clone()),
                    new_non_writable_authority: authority(4, 5),
                    reject_through_placement_epoch: 4,
                }),
                NOW,
                BOOT,
            ),
            Err(ExportAuthorityError::Conflict)
        );

        assert_eq!(
            apply_transition(
                Some(fenced.clone()),
                ExportAuthorityTransition::Activate(activate_command(authority(4, 5))),
                NOW,
                BOOT,
            ),
            Err(ExportAuthorityError::Conflict)
        );

        let next = apply_transition(
            Some(fenced),
            ExportAuthorityTransition::Activate(activate_command(authority(4, 6))),
            NOW,
            BOOT,
        )
        .unwrap();
        validate_mutation(Some(&next), &token(&next), NOW, BOOT).unwrap();
    }

    proptest! {
        #[test]
        fn authority_action_traces_preserve_binding_and_reject_stale_tokens(
            actions in prop::collection::vec(0u8..10, 1..128)
        ) {
            let mut boot = BOOT.to_owned();
            let mut record = apply_transition(
                None,
                ExportAuthorityTransition::Activate(activate_command(authority(3, 5))),
                NOW,
                &boot,
            ).unwrap();
            let binding = record.export.clone();
            let mut next_assignment = 6u64;
            let mut next_placement = 4u64;

            for action in actions {
                let previous_reject = record.rejected_through_placement_epoch;
                match action {
                    0 if record
                        .active_session
                        .as_ref()
                        .is_some_and(|session| {
                            session.server_boot_id == boot
                                && session.expires_at_unix_millis < u64::MAX
                        }) => {
                        let session = record.active_session.as_ref().unwrap().clone();
                        let replacement = AuthorityVersion {
                            assignment_revision: next_assignment,
                            ..record.authority.clone()
                        };
                        next_assignment += 1;
                        record = apply_transition(
                            Some(record.clone()),
                            ExportAuthorityTransition::Refresh(RefreshExport {
                                workspace_id: record.workspace_id.clone(),
                                expected_export: binding.clone(),
                                expected_authority: record.authority.clone(),
                                session_id: session.session_id,
                                expected_capability_id: session.capability_id,
                                replacement_authority: replacement,
                                replacement_capability_id: format!("capability-{next_assignment}"),
                                replacement_expires_at_unix_millis: u64::MAX,
                            }),
                            NOW,
                            &boot,
                        ).unwrap();
                    }
                    1 if record
                        .active_session
                        .as_ref()
                        .is_some_and(|session| session.server_boot_id == boot) => {
                        let live = token(&record);
                        prop_assert_eq!(
                            validate_mutation(Some(&record), &live, NOW, &boot),
                            Ok(())
                        );
                        prop_assert_eq!(
                            validate_mutation(Some(&record), &live, NOW, &boot),
                            Ok(())
                        );
                    }
                    2 if record.active_session.is_some() => {
                        let mut conflicting = token(&record);
                        conflicting.capability_id.push_str("-conflict");
                        prop_assert_eq!(
                            validate_mutation(Some(&record), &conflicting, NOW, &boot),
                            Err(ExportAuthorityError::StaleMutation)
                        );
                    }
                    3 if record.active_session.is_some() => {
                        let live = token(&record);
                        prop_assert_eq!(
                            validate_mutation(Some(&record), &live, u64::MAX, &boot),
                            Err(ExportAuthorityError::StaleMutation)
                        );
                    }
                    4 => {
                        record = apply_transition(
                            Some(record.clone()),
                            ExportAuthorityTransition::AdvanceFence(AdvanceFence {
                                workspace_id: record.workspace_id.clone(),
                                export: binding.clone(),
                                expected_authority: Some(record.authority.clone()),
                                new_non_writable_authority: record.authority.clone(),
                                reject_through_placement_epoch: record.authority.placement_epoch,
                            }),
                            NOW,
                            &boot,
                        ).unwrap();
                    }
                    5 => {
                        boot = format!("boot-{next_assignment}-{next_placement}");
                        if record.active_session.is_some() {
                            prop_assert_eq!(
                                validate_mutation(Some(&record), &token(&record), NOW, &boot),
                                Err(ExportAuthorityError::StaleMutation)
                            );
                        }
                    }
                    6 if record.active_session.is_none() => {
                        let next = AuthorityVersion {
                            placement_epoch: next_placement.max(
                                record.rejected_through_placement_epoch.saturating_add(1)
                            ),
                            assignment_revision: next_assignment,
                            ..record.authority.clone()
                        };
                        next_placement = next.placement_epoch.saturating_add(1);
                        next_assignment = next_assignment.saturating_add(1);
                        record = apply_transition(
                            Some(record.clone()),
                            ExportAuthorityTransition::Activate(ActivateExport {
                                workspace_id: record.workspace_id.clone(),
                                export: binding.clone(),
                                authority: next,
                                session: session(
                                    &format!("session-{next_assignment}"),
                                    &format!("capability-{next_assignment}"),
                                    u64::MAX - 1,
                                ),
                            }),
                            NOW,
                            &boot,
                        ).unwrap();
                    }
                    7 if record.active_session.is_some() => {
                        let session_id = record.active_session.as_ref().unwrap().session_id.clone();
                        record = apply_transition(
                            Some(record.clone()),
                            ExportAuthorityTransition::Deactivate(DeactivateExport {
                                workspace_id: record.workspace_id.clone(),
                                expected_export: binding.clone(),
                                expected_authority: record.authority.clone(),
                                session_id,
                            }),
                            NOW,
                            &boot,
                        ).unwrap();
                    }
                    8 => {
                        let mut wrong = binding.clone();
                        wrong.inode = wrong.inode.saturating_add(1);
                        prop_assert_eq!(
                            apply_transition(
                                Some(record.clone()),
                                ExportAuthorityTransition::AdvanceFence(AdvanceFence {
                                    workspace_id: record.workspace_id.clone(),
                                    export: wrong,
                                    expected_authority: Some(record.authority.clone()),
                                    new_non_writable_authority: record.authority.clone(),
                                    reject_through_placement_epoch: record.authority.placement_epoch,
                                }),
                                NOW,
                                &boot,
                            ),
                            Err(ExportAuthorityError::Conflict)
                        );
                    }
                    _ => {
                        let encoded = encode_record(&record).unwrap();
                        prop_assert_eq!(
                            decode_record(&encoded, &record.workspace_id).unwrap(),
                            record.clone()
                        );
                    }
                }
                prop_assert_eq!(&record.export, &binding);
                prop_assert!(record.rejected_through_placement_epoch >= previous_reject);
                if let Some(active) = record.active_session.as_ref() {
                    prop_assert!(record.authority.placement_epoch > record.rejected_through_placement_epoch);
                    if active.server_boot_id == boot {
                        prop_assert_eq!(
                            validate_mutation(Some(&record), &token(&record), NOW, &boot),
                            Ok(())
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn ordinary_zerofs_requires_explicit_export_profile_enablement() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        assert_eq!(
            fs.export_authority
                .activate(activate_command(authority(3, 5)))
                .await,
            Err(ExportAuthorityError::ProfileDisabled)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn configured_shard_guard_locks_exact_identity_and_rejects_replacement_inode() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let shard_id = "shards/test-a";
        let lock_path = directory.path().join(shard_lock_name(shard_id));
        let lock = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        let directory_file = std::fs::File::open(directory.path()).unwrap();
        let directory_metadata = directory_file.metadata().unwrap();
        let lock_metadata = lock.metadata().unwrap();
        let identity = ShardLockIdentity {
            directory_device: directory_metadata.dev(),
            directory_inode: directory_metadata.ino(),
            lock_device: lock_metadata.dev(),
            lock_inode: lock_metadata.ino(),
        };
        drop(lock);
        let validation = || ShardGuardValidation {
            identity,
            directory_uid: directory_metadata.uid(),
            lock_uid: directory_metadata.uid(),
            gid: directory_metadata.gid(),
            directory_mode: 0o700,
            lock_mode: 0o600,
        };
        let acquire = || {
            ShardProcessGuard::acquire_at(
                std::fs::File::open(directory.path()).unwrap(),
                shard_id,
                validation(),
            )
        };
        let first_store_guard = acquire().unwrap();
        assert!(matches!(acquire(), Err(ExportAuthorityError::Conflict)));

        let retired = directory.path().join("retired.lock");
        std::fs::rename(&lock_path, retired).unwrap();
        std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        assert!(matches!(acquire(), Err(ExportAuthorityError::Invalid)));
        drop(first_store_guard);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn configured_shard_guard_rejects_root_or_a_mismatched_worker_identity() {
        let impossible = ShardLockIdentity {
            directory_device: 0,
            directory_inode: 0,
            lock_device: 0,
            lock_inode: 0,
        };
        assert!(matches!(
            ShardProcessGuard::acquire_configured(
                std::path::Path::new("/does/not/matter"),
                "shard-a",
                0,
                0,
                impossible,
            ),
            Err(ExportAuthorityError::Invalid)
        ));
        let mismatched_uid = rustix::process::geteuid().as_raw().wrapping_add(1).max(1);
        assert!(matches!(
            ShardProcessGuard::acquire_configured(
                std::path::Path::new("/does/not/matter"),
                "shard-a",
                mismatched_uid,
                rustix::process::getegid().as_raw(),
                impossible,
            ),
            Err(ExportAuthorityError::Invalid)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn configured_shard_guard_accepts_supervisor_provisioned_dedicated_uid() {
        use std::os::unix::fs::MetadataExt;

        let Ok(root) = std::env::var("RHIZOME_TEST_SHARD_GUARD_ROOT") else {
            return;
        };
        let root = std::path::Path::new(&root);
        let shard_id = "foundation-dedicated-worker";
        let directory = std::fs::File::open(root).unwrap();
        let directory_metadata = directory.metadata().unwrap();
        let lock_metadata = std::fs::metadata(root.join(shard_lock_name(shard_id))).unwrap();
        let guard = ShardProcessGuard::acquire_configured(
            root,
            shard_id,
            rustix::process::geteuid().as_raw(),
            directory_metadata.gid(),
            ShardLockIdentity {
                directory_device: directory_metadata.dev(),
                directory_inode: directory_metadata.ino(),
                lock_device: lock_metadata.dev(),
                lock_inode: lock_metadata.ino(),
            },
        )
        .unwrap();
        assert!(matches!(
            ShardProcessGuard::acquire_configured(
                root,
                shard_id,
                rustix::process::geteuid().as_raw(),
                directory_metadata.gid(),
                ShardLockIdentity {
                    directory_device: directory_metadata.dev(),
                    directory_inode: directory_metadata.ino(),
                    lock_device: lock_metadata.dev(),
                    lock_inode: lock_metadata.ino(),
                },
            ),
            Err(ExportAuthorityError::Conflict)
        ));
        drop(guard);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shard_guard_conflicts_with_subprocess_until_holder_is_killed_and_joined() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let shard_id = "subprocess-shard";
        let lock_path = directory.path().join(shard_lock_name(shard_id));
        let lock = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        let directory_file = std::fs::File::open(directory.path()).unwrap();
        let directory_metadata = directory_file.metadata().unwrap();
        let lock_metadata = lock.metadata().unwrap();
        let validation = || ShardGuardValidation {
            identity: ShardLockIdentity {
                directory_device: directory_metadata.dev(),
                directory_inode: directory_metadata.ino(),
                lock_device: lock_metadata.dev(),
                lock_inode: lock_metadata.ino(),
            },
            directory_uid: directory_metadata.uid(),
            lock_uid: lock_metadata.uid(),
            gid: directory_metadata.gid(),
            directory_mode: 0o700,
            lock_mode: 0o600,
        };
        drop(lock);
        let mut holder = Command::new("sh")
            .args([
                "-c",
                "exec 9<>\"$1\"; flock -x 9; exec sleep 30",
                "shard-guard-holder",
                lock_path.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match ShardProcessGuard::acquire_at(
                std::fs::File::open(directory.path()).unwrap(),
                shard_id,
                validation(),
            ) {
                Err(ExportAuthorityError::Conflict) => break,
                Ok(guard) => drop(guard),
                Err(error) => panic!("unexpected guard error: {error:?}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "subprocess never acquired lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        holder.kill().unwrap();
        holder.wait().unwrap();
        ShardProcessGuard::acquire_at(
            std::fs::File::open(directory.path()).unwrap(),
            shard_id,
            validation(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn boot_flush_unknown_keeps_the_profile_disabled_until_durable_retry() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        fs.export_authority
            .install_process_guard(ShardProcessGuard::for_test())
            .unwrap();
        fs.write_coordinator.dst_fail_next_workspace_durable_flush();
        assert_eq!(
            fs.export_authority.enable_standalone_profile().await,
            Err(ExportAuthorityError::CommitOutcomeUnknown)
        );
        assert_eq!(
            fs.export_authority
                .install_process_guard(ShardProcessGuard::for_test()),
            Err(ExportAuthorityError::Conflict)
        );
        assert_eq!(
            fs.export_authority
                .activate(activate_command(authority(3, 5)))
                .await,
            Err(ExportAuthorityError::ProfileDisabled)
        );
        assert!(
            fs.db
                .get_bytes_durable(&crate::fs::key_codec::KeyCodec::new().export_boot_key())
                .await
                .unwrap()
                .is_none()
        );

        fs.export_authority
            .enable_standalone_profile()
            .await
            .unwrap();
        ensure_test_export(&fs, 4096).await.unwrap();
        fs.export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enabled_profile_cannot_replace_its_guard_or_reinitialize_boot() {
        let fs = new_export_fs().await;
        let boot_key = crate::fs::key_codec::KeyCodec::new().export_boot_key();
        let boot = fs.db.get_bytes_durable(&boot_key).await.unwrap().unwrap();
        assert_eq!(
            fs.export_authority
                .install_process_guard(ShardProcessGuard::for_test()),
            Err(ExportAuthorityError::Conflict)
        );
        assert_eq!(
            fs.db.get_bytes_durable(&boot_key).await.unwrap(),
            Some(boot)
        );
    }

    #[tokio::test]
    async fn cancelled_enable_retains_the_installed_guard_and_retry_converges() {
        let fs = Arc::new(ZeroFS::new_in_memory().await.unwrap());
        fs.export_authority
            .install_process_guard(ShardProcessGuard::for_test())
            .unwrap();
        let enable = tokio::spawn({
            let fs = fs.clone();
            async move { fs.export_authority.enable_standalone_profile().await }
        });
        enable.abort();
        assert!(enable.await.unwrap_err().is_cancelled());
        assert_eq!(
            fs.export_authority
                .install_process_guard(ShardProcessGuard::for_test()),
            Err(ExportAuthorityError::Conflict)
        );
        fs.export_authority
            .enable_standalone_profile()
            .await
            .unwrap();
        ensure_test_export(&fs, 4096).await.unwrap();
        fs.export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn superseded_boot_rejects_authority_transitions() {
        let fs = Arc::new(new_export_fs().await);
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        fs.write_coordinator.dst_pause_next_authority_after_permit();
        let transition = {
            let fs = fs.clone();
            let active = active.clone();
            tokio::spawn(async move {
                fs.export_authority
                    .advance_fence(AdvanceFence {
                        workspace_id: active.workspace_id.clone(),
                        export: active.export.clone(),
                        expected_authority: Some(active.authority.clone()),
                        new_non_writable_authority: active.authority.clone(),
                        reject_through_placement_epoch: active.authority.placement_epoch,
                    })
                    .await
            })
        };
        fs.write_coordinator.dst_wait_authority_after_permit().await;
        let boot_key = crate::fs::key_codec::KeyCodec::new().export_boot_key();
        fs.db
            .inject_reserved_authority_value_for_test(
                boot_key,
                Bytes::from_static(b"another-process-boot"),
            )
            .await
            .unwrap();
        fs.write_coordinator.dst_release_authority_after_permit();
        assert_eq!(
            transition.await.unwrap(),
            Err(ExportAuthorityError::Conflict)
        );
    }

    #[test]
    fn expired_session_cannot_be_revived_by_refresh() {
        let expired = ExportAuthorityRecord {
            workspace_id: "workspace-a".into(),
            export: export(77),
            authority: authority(3, 5),
            rejected_through_placement_epoch: 0,
            binding_initialized: true,
            active_session: Some(session("session-a", "capability-a", NOW)),
        };
        assert_eq!(
            apply_transition(
                Some(expired),
                ExportAuthorityTransition::Refresh(RefreshExport {
                    workspace_id: "workspace-a".into(),
                    expected_export: export(77),
                    expected_authority: authority(3, 5),
                    session_id: "session-a".into(),
                    expected_capability_id: "capability-a".into(),
                    replacement_authority: authority(3, 6),
                    replacement_capability_id: "capability-b".into(),
                    replacement_expires_at_unix_millis: NOW + 100,
                }),
                NOW,
                BOOT,
            ),
            Err(ExportAuthorityError::Conflict)
        );

        let active = apply_transition(
            None,
            ExportAuthorityTransition::Activate(activate_command(authority(3, 5))),
            NOW,
            BOOT,
        )
        .unwrap();
        for replacement in [authority(3, 5), authority(4, 6)] {
            assert_eq!(
                apply_transition(
                    Some(active.clone()),
                    ExportAuthorityTransition::Refresh(RefreshExport {
                        workspace_id: "workspace-a".into(),
                        expected_export: export(77),
                        expected_authority: authority(3, 5),
                        session_id: "session-a".into(),
                        expected_capability_id: "capability-a".into(),
                        replacement_authority: replacement,
                        replacement_capability_id: "capability-b".into(),
                        replacement_expires_at_unix_millis: u64::MAX,
                    }),
                    NOW,
                    BOOT,
                ),
                Err(ExportAuthorityError::Conflict)
            );
        }
        assert_eq!(
            apply_transition(
                Some(active.clone()),
                ExportAuthorityTransition::Refresh(RefreshExport {
                    workspace_id: "workspace-a".into(),
                    expected_export: export(77),
                    expected_authority: authority(3, 5),
                    session_id: "session-a".into(),
                    expected_capability_id: "capability-a".into(),
                    replacement_authority: authority(3, 6),
                    replacement_capability_id: "capability-a".into(),
                    replacement_expires_at_unix_millis: u64::MAX,
                }),
                NOW,
                BOOT,
            ),
            Err(ExportAuthorityError::Conflict)
        );
    }

    #[tokio::test]
    async fn all_core_mutation_kinds_are_fenced_and_close_stale_session() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();

        for (index, kind) in [
            MutationKind::Write { fua: false },
            MutationKind::Write { fua: true },
            MutationKind::Flush,
            MutationKind::Trim { fua: false },
            MutationKind::Trim { fua: true },
            MutationKind::WriteZeroes { fua: false },
            MutationKind::WriteZeroes { fua: true },
        ]
        .into_iter()
        .enumerate()
        {
            let key =
                crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, index as u64);
            let mut transaction = Transaction::new();
            transaction.put_bytes(&key, Bytes::from_static(b"accepted"));
            fs.export_authority
                .commit_mutation(mutation_for(&active, transaction, kind, index as u8 + 1))
                .await
                .unwrap();
            assert_eq!(
                fs.db.get_bytes(&key).await.unwrap().as_deref(),
                Some(&b"accepted"[..])
            );
        }

        fs.export_authority
            .advance_fence(AdvanceFence {
                workspace_id: active.workspace_id.clone(),
                export: active.export.clone(),
                expected_authority: Some(active.authority.clone()),
                new_non_writable_authority: active.authority.clone(),
                reject_through_placement_epoch: active.authority.placement_epoch,
            })
            .await
            .unwrap();

        for (index, kind) in [
            MutationKind::Write { fua: false },
            MutationKind::Write { fua: true },
            MutationKind::Flush,
            MutationKind::Trim { fua: false },
            MutationKind::Trim { fua: true },
            MutationKind::WriteZeroes { fua: false },
            MutationKind::WriteZeroes { fua: true },
        ]
        .into_iter()
        .enumerate()
        {
            let key = crate::fs::key_codec::KeyCodec::new()
                .extent_key(active.export.inode, index as u64 + 100);
            let mut transaction = Transaction::new();
            transaction.put_bytes(&key, Bytes::from_static(b"must-not-commit"));
            let error = fs
                .export_authority
                .commit_mutation(mutation_for(&active, transaction, kind, index as u8 + 20))
                .await
                .unwrap_err();
            assert_eq!(error, ExportAuthorityError::StaleMutation);
            assert!(error.close_session());
            assert!(fs.db.get_bytes(&key).await.unwrap().is_none());
        }

        let empty_flush = fs
            .export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Flush,
                40,
            ))
            .await
            .unwrap_err();
        assert_eq!(empty_flush, ExportAuthorityError::StaleMutation);
        assert!(empty_flush.close_session());
    }

    #[tokio::test]
    async fn refresh_deactivate_and_expiry_preserve_complete_binding() {
        let fs = new_export_fs().await;
        let first = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let binding = reverse_binding_for(&first);
        let (name_key, inode_key) = reverse_binding_keys(&binding);
        let original_name = fs.db.get_bytes(&name_key).await.unwrap().unwrap();
        let original_inode = fs.db.get_bytes(&inode_key).await.unwrap().unwrap();
        let refreshed = fs
            .export_authority
            .refresh(RefreshExport {
                workspace_id: first.workspace_id.clone(),
                expected_export: first.export.clone(),
                expected_authority: first.authority.clone(),
                session_id: "session-a".into(),
                expected_capability_id: "capability-a".into(),
                replacement_authority: authority(3, 6),
                replacement_capability_id: "capability-b".into(),
                replacement_expires_at_unix_millis: u64::MAX,
            })
            .await
            .unwrap();
        assert_eq!(
            validate_mutation(Some(&refreshed), &token(&first), NOW, BOOT),
            Err(ExportAuthorityError::StaleMutation)
        );
        assert_eq!(
            validate_mutation(Some(&refreshed), &token(&refreshed), u64::MAX, BOOT),
            Err(ExportAuthorityError::StaleMutation)
        );

        let deactivated = fs
            .export_authority
            .deactivate(DeactivateExport {
                workspace_id: refreshed.workspace_id.clone(),
                expected_export: refreshed.export.clone(),
                expected_authority: refreshed.authority.clone(),
                session_id: "session-a".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            fs.db.get_bytes(&name_key).await.unwrap(),
            Some(original_name.clone())
        );
        assert_eq!(
            fs.db.get_bytes(&inode_key).await.unwrap(),
            Some(original_inode.clone())
        );
        assert!(deactivated.active_session.is_none());
        assert_eq!(
            deactivated.rejected_through_placement_epoch,
            refreshed.authority.placement_epoch
        );
        fs.export_authority
            .advance_fence(AdvanceFence {
                workspace_id: deactivated.workspace_id.clone(),
                export: deactivated.export.clone(),
                expected_authority: Some(deactivated.authority.clone()),
                new_non_writable_authority: deactivated.authority,
                reject_through_placement_epoch: deactivated.rejected_through_placement_epoch,
            })
            .await
            .unwrap();
        assert_eq!(
            fs.db.get_bytes(&name_key).await.unwrap(),
            Some(original_name)
        );
        assert_eq!(
            fs.db.get_bytes(&inode_key).await.unwrap(),
            Some(original_inode)
        );
    }

    #[tokio::test]
    async fn final_gate_observes_expiry_after_write_permit_wait() {
        let fs = Arc::new(new_export_fs().await);
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        fs.write_coordinator.dst_pause_next_export_after_permit();
        let mutation = {
            let fs = fs.clone();
            tokio::spawn(async move {
                fs.export_authority
                    .commit_mutation(mutation_for(
                        &active,
                        Transaction::new(),
                        MutationKind::Flush,
                        41,
                    ))
                    .await
            })
        };
        fs.write_coordinator.dst_wait_export_after_permit().await;
        fs.write_coordinator
            .dst_advance_authority_time_floor(u64::MAX - 1);
        fs.write_coordinator.dst_release_export_after_permit();
        let error = mutation.await.unwrap().unwrap_err();
        assert_eq!(error, ExportAuthorityError::StaleMutation);
    }

    #[tokio::test]
    async fn final_gate_observes_boot_supersession_without_applying_data() {
        let fs = Arc::new(new_export_fs().await);
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let data_key = crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, 600);
        let mut transaction = Transaction::new();
        transaction.put_bytes(&data_key, Bytes::from_static(b"must-not-apply"));
        let mutation = mutation_for(&active, transaction, MutationKind::Write { fua: false }, 59);
        let expected = mutation.expectation();
        fs.write_coordinator.dst_pause_next_export_after_permit();
        let pending = tokio::spawn({
            let fs = fs.clone();
            async move { fs.export_authority.commit_mutation(mutation).await }
        });
        fs.write_coordinator.dst_wait_export_after_permit().await;
        fs.db
            .inject_reserved_authority_value_for_test(
                crate::fs::key_codec::KeyCodec::new().export_boot_key(),
                Bytes::from_static(b"superseding-process"),
            )
            .await
            .unwrap();
        fs.write_coordinator.dst_release_export_after_permit();
        assert_eq!(
            pending.await.unwrap(),
            Err(ExportAuthorityError::StaleMutation)
        );
        assert!(fs.db.get_bytes(&data_key).await.unwrap().is_none());
        assert_eq!(
            fs.export_authority
                .lookup_mutation_current(&expected)
                .await
                .unwrap(),
            ExportMutationLookup::Unknown
        );
    }

    #[tokio::test]
    async fn durable_reply_loss_is_unknown_and_closes_the_session() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let mutation = mutation_for(&active, Transaction::new(), MutationKind::Flush, 42);
        let expected = mutation.expectation();
        fs.write_coordinator.dst_drop_next_workspace_durable_reply();
        let error = fs
            .export_authority
            .commit_mutation(mutation)
            .await
            .unwrap_err();
        assert_eq!(error, ExportAuthorityError::CommitOutcomeUnknown);
        assert!(error.close_session());
        assert!(matches!(
            fs.export_authority
                .lookup_mutation_durable(&expected)
                .await
                .unwrap(),
            ExportMutationLookup::Committed(_)
        ));
    }

    #[tokio::test]
    async fn only_fua_and_flush_require_the_durability_barrier() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        fs.write_coordinator.dst_fail_next_workspace_durable_flush();
        fs.export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Write { fua: false },
                43,
            ))
            .await
            .expect("buffered write must not force the armed durability failure");
        let error = fs
            .export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Write { fua: true },
                44,
            ))
            .await
            .unwrap_err();
        assert_eq!(error, ExportAuthorityError::CommitOutcomeUnknown);
        assert!(error.close_session());
    }

    #[tokio::test]
    async fn transition_reply_loss_requires_durable_readback() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        fs.write_coordinator.dst_drop_next_workspace_durable_reply();
        let error = fs
            .export_authority
            .advance_fence(AdvanceFence {
                workspace_id: active.workspace_id.clone(),
                export: active.export.clone(),
                expected_authority: Some(active.authority.clone()),
                new_non_writable_authority: active.authority.clone(),
                reject_through_placement_epoch: active.authority.placement_epoch,
            })
            .await
            .unwrap_err();
        assert_eq!(error, ExportAuthorityError::CommitOutcomeUnknown);
        let readback = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(readback.active_session.is_none());
        assert_eq!(readback.rejected_through_placement_epoch, 3);
    }

    #[tokio::test]
    async fn transition_flush_failure_is_not_a_durable_receipt_after_crash_reopen() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let fs = open_fs(object_store.clone()).await.unwrap();
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let crash_snapshot = snapshot_object_store(&object_store).await;

        fs.write_coordinator.dst_fail_next_workspace_durable_flush();
        assert_eq!(
            fs.export_authority
                .refresh(RefreshExport {
                    workspace_id: active.workspace_id.clone(),
                    expected_export: active.export.clone(),
                    expected_authority: active.authority.clone(),
                    session_id: "session-a".into(),
                    expected_capability_id: "capability-a".into(),
                    replacement_authority: authority(3, 6),
                    replacement_capability_id: "capability-b".into(),
                    replacement_expires_at_unix_millis: u64::MAX,
                })
                .await,
            Err(ExportAuthorityError::CommitOutcomeUnknown)
        );
        let durable = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(durable.authority, authority(3, 5));
        assert_eq!(
            durable.active_session.as_ref().unwrap().capability_id,
            "capability-a"
        );

        let reopened = open_fs(crash_snapshot).await.unwrap();
        let recovered = reopened
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.authority, authority(3, 5));
        assert!(recovered.active_session.is_none());
    }

    #[tokio::test]
    async fn unknown_transition_converges_after_reopen_and_new_boot() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let first = open_fs(object_store.clone()).await.unwrap();
        let active = first
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        first
            .write_coordinator
            .dst_drop_next_workspace_durable_reply();
        assert_eq!(
            first
                .export_authority
                .advance_fence(AdvanceFence {
                    workspace_id: active.workspace_id.clone(),
                    export: active.export.clone(),
                    expected_authority: Some(active.authority.clone()),
                    new_non_writable_authority: active.authority.clone(),
                    reject_through_placement_epoch: active.authority.placement_epoch,
                })
                .await,
            Err(ExportAuthorityError::CommitOutcomeUnknown)
        );
        first.db.close().await.unwrap();
        drop(first);

        let reopened = open_fs(object_store).await.unwrap();
        let readback = reopened
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(readback.active_session.is_none());
        assert_eq!(readback.authority, authority(3, 5));
        assert_eq!(readback.rejected_through_placement_epoch, 3);
        let advanced = reopened
            .export_authority
            .advance_fence(AdvanceFence {
                workspace_id: readback.workspace_id.clone(),
                export: readback.export.clone(),
                expected_authority: Some(readback.authority.clone()),
                new_non_writable_authority: authority(4, 6),
                reject_through_placement_epoch: 4,
            })
            .await
            .unwrap();
        assert_eq!(advanced.authority, authority(4, 6));
        assert!(advanced.active_session.is_none());
    }

    #[tokio::test]
    async fn corrupt_durable_record_fails_closed() {
        let fs = new_export_fs().await;
        let key = crate::fs::key_codec::KeyCodec::new().export_authority_key("workspace-a");
        fs.db
            .inject_reserved_authority_value_for_test(
                key,
                Bytes::from_static(b"not-a-versioned-authority-record"),
            )
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.export_authority.get("workspace-a").await,
            Err(ExportAuthorityError::Corrupt)
        );
    }

    #[tokio::test]
    async fn authority_record_copied_under_another_workspace_key_is_corrupt() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let copied = encode_record(&active).unwrap();
        let key = crate::fs::key_codec::KeyCodec::new().export_authority_key("workspace-other");
        fs.db
            .inject_reserved_authority_value_for_test(key, copied)
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.export_authority.get("workspace-other").await,
            Err(ExportAuthorityError::Corrupt)
        );
    }

    #[tokio::test]
    async fn raw_transactions_cannot_mutate_reserved_authority_keys() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let codec = crate::fs::key_codec::KeyCodec::new();
        let boot_key = codec.export_boot_key();
        let boot_before = fs.db.get_bytes(&boot_key).await.unwrap().unwrap();
        let binding = reverse_binding_for(&active);
        let (reverse_name_key, reverse_inode_key) = reverse_binding_keys(&binding);
        let keys = [
            codec.export_authority_key("workspace-a"),
            codec.export_authority_key("workspace-other"),
            reverse_name_key,
            reverse_inode_key,
            boot_key.clone(),
        ];
        for key in keys {
            let mut put = Transaction::new();
            put.put_bytes(&key, Bytes::from_static(b"attacker"));
            assert_eq!(
                fs.write_coordinator.commit(put).await,
                Err(crate::fs::errors::FsError::OperationNotPermitted)
            );
            let mut delete = Transaction::new();
            delete.delete_bytes(&key);
            assert_eq!(
                fs.write_coordinator.commit(delete).await,
                Err(crate::fs::errors::FsError::OperationNotPermitted)
            );
        }
        assert_eq!(fs.db.get_bytes(&boot_key).await.unwrap(), Some(boot_before));
        assert_eq!(
            fs.export_authority.get("workspace-a").await.unwrap(),
            Some(active)
        );
        assert!(
            fs.export_authority
                .get("workspace-other")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_workspaces_cannot_activate_the_same_export() {
        let fs = Arc::new(new_export_fs().await);
        let first = activate_command(authority(3, 5));
        let mut second = first.clone();
        second.workspace_id = "workspace-b".into();
        second.session.session_id = "session-b".into();
        second.session.capability_id = "capability-b".into();
        let (left, right) = tokio::join!(
            fs.export_authority.activate(first),
            fs.export_authority.activate(second)
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert!(matches!(left, Ok(_) | Err(ExportAuthorityError::Conflict)));
        assert!(matches!(right, Ok(_) | Err(ExportAuthorityError::Conflict)));
    }

    #[tokio::test]
    async fn reverse_indexes_reject_name_and_inode_aliases() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();

        let mut same_name = active.export.clone();
        same_name.inode += 100;
        let mut name_alias = activate_command_for(authority(3, 5), same_name);
        name_alias.workspace_id = "workspace-name-alias".into();
        assert_eq!(
            fs.export_authority.activate(name_alias).await,
            Err(ExportAuthorityError::Conflict)
        );

        let mut same_inode = active.export.clone();
        same_inode.name = b"disk-alias".to_vec();
        let mut inode_alias = activate_command_for(authority(3, 5), same_inode);
        inode_alias.workspace_id = "workspace-inode-alias".into();
        assert_eq!(
            fs.export_authority.activate(inode_alias).await,
            Err(ExportAuthorityError::Conflict)
        );
    }

    #[tokio::test]
    async fn activation_rejects_a_hardlinked_export() {
        let fs = new_export_fs().await;
        let export = ensure_test_export(&fs, 4096).await.unwrap();
        fs.link(
            &crate::fs::types::AuthContext::default(),
            export.inode,
            export.nbd_directory_inode,
            b"disk-hardlink",
        )
        .await
        .unwrap();
        assert_eq!(
            fs.export_authority
                .activate(activate_command_for(authority(3, 5), export))
                .await,
            Err(ExportAuthorityError::Invalid)
        );
    }

    #[tokio::test]
    async fn ordinary_hardlink_cannot_change_an_active_export() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        assert_eq!(
            fs.link(
                &crate::fs::types::AuthContext::default(),
                active.export.inode,
                active.export.nbd_directory_inode,
                b"disk-hardlink",
            )
            .await,
            Err(crate::fs::errors::FsError::OperationNotPermitted)
        );
        let mutation = ExportMutationBuilder::build(
            token(&active),
            [0x73; SHA256_SIZE],
            ExportMutationCommand::Flush,
        )
        .unwrap();
        fs.export_authority.commit_mutation(mutation).await.unwrap();
    }

    #[tokio::test]
    async fn unknown_first_activation_never_publishes_partial_reverse_bindings() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let fs = open_fs(object_store.clone()).await.unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        let command = activate_command(authority(3, 5));
        let binding = ExportReverseBinding {
            workspace_id: command.workspace_id.clone(),
            actor: command.authority.actor.clone(),
            actor_generation: command.authority.actor_generation,
            export: command.export.clone(),
        };
        let (name_key, inode_key) = reverse_binding_keys(&binding);
        fs.write_coordinator.dst_fail_next_workspace_durable_flush();
        assert_eq!(
            fs.export_authority.activate(command).await,
            Err(ExportAuthorityError::CommitOutcomeUnknown)
        );
        let crash_snapshot = snapshot_object_store(&object_store).await;
        fs.db.close().await.unwrap();
        drop(fs);

        let reopened = open_fs(crash_snapshot).await.unwrap();
        assert!(
            reopened
                .export_authority
                .get("workspace-a")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            read_reverse_binding_current(&reopened.db, &name_key)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            read_reverse_binding_current(&reopened.db, &inode_key)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn first_activation_reply_loss_and_cancellation_converge_through_three_row_readback() {
        let fs = Arc::new(new_export_fs().await);
        let command = activate_command(authority(3, 5));
        fs.write_coordinator.dst_drop_next_workspace_durable_reply();
        assert_eq!(
            fs.export_authority.activate(command.clone()).await,
            Err(ExportAuthorityError::CommitOutcomeUnknown)
        );
        let readback = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(readback.binding_initialized);
        assert_eq!(
            fs.export_authority.activate(command).await.unwrap(),
            readback
        );

        let other = Arc::new(new_export_fs().await);
        let mut cancelled = activate_command(authority(3, 5));
        cancelled.workspace_id = "workspace-cancelled".into();
        cancelled.session.session_id = "session-cancelled".into();
        cancelled.session.capability_id = "capability-cancelled".into();
        other
            .write_coordinator
            .dst_pause_next_authority_after_permit();
        let request = tokio::spawn({
            let other = other.clone();
            async move { other.export_authority.activate(cancelled).await }
        });
        other
            .write_coordinator
            .dst_wait_authority_after_permit()
            .await;
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        other.write_coordinator.dst_release_authority_after_permit();
        other.write_coordinator.barrier().await.unwrap();
        let cancelled_readback = other
            .export_authority
            .get("workspace-cancelled")
            .await
            .unwrap()
            .unwrap();
        assert!(cancelled_readback.binding_initialized);
    }

    #[tokio::test]
    async fn reverse_bindings_survive_restart_and_fail_closed_on_cross_key_copy() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let first = open_fs(object_store.clone()).await.unwrap();
        let active = first
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let binding = reverse_binding_for(&active);
        let (name_key, inode_key) = reverse_binding_keys(&binding);
        first.db.close().await.unwrap();
        drop(first);

        let reopened = open_fs(object_store).await.unwrap();
        assert_eq!(
            read_reverse_binding_current(&reopened.db, &name_key)
                .await
                .unwrap(),
            Some(binding.clone())
        );
        assert_eq!(
            read_reverse_binding_current(&reopened.db, &inode_key)
                .await
                .unwrap(),
            Some(binding.clone())
        );
        let copied = reopened.db.get_bytes(&name_key).await.unwrap().unwrap();
        reopened
            .db
            .inject_reserved_authority_value_for_test(inode_key, copied)
            .await
            .unwrap();
        let replacement = ActivateExport {
            workspace_id: active.workspace_id,
            export: active.export,
            authority: authority(4, 6),
            session: session("session-next", "capability-next", u64::MAX),
        };
        assert_eq!(
            reopened.export_authority.activate(replacement).await,
            Err(ExportAuthorityError::Corrupt)
        );
    }

    #[tokio::test]
    async fn durable_get_rejects_missing_or_mismatched_reverse_rows() {
        for delete_name in [true, false] {
            let fs = new_export_fs().await;
            let active = fs
                .export_authority
                .activate(activate_command(authority(3, 5)))
                .await
                .unwrap();
            let binding = reverse_binding_for(&active);
            let (name_key, inode_key) = reverse_binding_keys(&binding);
            fs.db
                .inject_reserved_authority_delete_for_test(if delete_name {
                    name_key
                } else {
                    inode_key
                })
                .await
                .unwrap();
            fs.flush_coordinator.flush().await.unwrap();
            assert_eq!(
                fs.export_authority.get("workspace-a").await,
                Err(ExportAuthorityError::Corrupt)
            );
        }

        for corrupt_name in [true, false] {
            let fs = new_export_fs().await;
            let active = fs
                .export_authority
                .activate(activate_command(authority(3, 5)))
                .await
                .unwrap();
            let binding = reverse_binding_for(&active);
            let (name_key, inode_key) = reverse_binding_keys(&binding);
            let mismatched = ExportReverseBinding {
                workspace_id: "workspace-other".into(),
                ..binding
            };
            let target = if corrupt_name { name_key } else { inode_key };
            fs.db
                .inject_reserved_authority_value_for_test(
                    target.clone(),
                    encode_reverse_binding(&mismatched, &target).unwrap(),
                )
                .await
                .unwrap();
            fs.flush_coordinator.flush().await.unwrap();
            assert_eq!(
                fs.export_authority.get("workspace-a").await,
                Err(ExportAuthorityError::Corrupt)
            );
        }

        let fs = new_export_fs().await;
        let command = activate_command(authority(3, 5));
        let active = fs.export_authority.activate(command.clone()).await.unwrap();
        let (name_key, inode_key) = reverse_binding_keys(&reverse_binding_for(&active));
        fs.db
            .inject_reserved_authority_delete_for_test(name_key)
            .await
            .unwrap();
        fs.db
            .inject_reserved_authority_delete_for_test(inode_key)
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.export_authority.get("workspace-a").await,
            Err(ExportAuthorityError::Corrupt)
        );
        assert_eq!(
            fs.export_authority.activate(command).await,
            Err(ExportAuthorityError::Corrupt)
        );
    }

    #[tokio::test]
    async fn forward_binding_fences_raw_mutations_when_reverse_rows_are_missing() {
        for missing in 0..3 {
            let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
                Arc::new(slatedb::object_store::memory::InMemory::new());
            let first = open_fs(object_store.clone()).await.unwrap();
            let active = first
                .export_authority
                .activate(activate_command(authority(3, 5)))
                .await
                .unwrap();
            let codec = crate::fs::key_codec::KeyCodec::new();
            let (name_key, inode_key) = reverse_binding_keys(&reverse_binding_for(&active));
            if missing != 1 {
                first
                    .db
                    .inject_reserved_authority_delete_for_test(name_key.clone())
                    .await
                    .unwrap();
            }
            if missing != 0 {
                first
                    .db
                    .inject_reserved_authority_delete_for_test(inode_key.clone())
                    .await
                    .unwrap();
            }
            first.flush_coordinator.flush().await.unwrap();
            first.db.close().await.unwrap();
            drop(first);
            let fs = open_fs(object_store).await.unwrap();
            let protected = [
                codec.inode_key(active.export.inode),
                codec.extent_key(active.export.inode, 0),
                codec.inode_key(active.export.nbd_directory_inode),
                codec.dir_entry_key(active.export.nbd_directory_inode, &active.export.name),
                codec.dir_entry_key(0, b".nbd"),
            ];
            for key in protected {
                let original = fs
                    .db
                    .get_bytes(&key)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| Bytes::from_static(b"candidate"));
                for value in [Some(original), None] {
                    let mut transaction = Transaction::new();
                    if let Some(value) = value {
                        transaction.put_bytes(&key, value);
                    } else {
                        transaction.delete_bytes(&key);
                    }
                    assert_eq!(
                        fs.write_coordinator.commit(transaction).await,
                        Err(crate::fs::errors::FsError::OperationNotPermitted)
                    );
                }
            }
            assert_eq!(fs.export_authority.dst_prepared_mutations(), 0);
        }
    }

    #[tokio::test]
    async fn retained_reverse_rows_fence_raw_mutations_when_forward_is_missing() {
        for retained in 0..3 {
            let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
                Arc::new(slatedb::object_store::memory::InMemory::new());
            let first = open_fs(object_store.clone()).await.unwrap();
            let active = first
                .export_authority
                .activate(activate_command(authority(3, 5)))
                .await
                .unwrap();
            let codec = crate::fs::key_codec::KeyCodec::new();
            let (name_key, inode_key) = reverse_binding_keys(&reverse_binding_for(&active));
            first
                .db
                .inject_reserved_authority_delete_for_test(
                    codec.export_authority_key(&active.workspace_id),
                )
                .await
                .unwrap();
            if retained == 0 {
                first
                    .db
                    .inject_reserved_authority_delete_for_test(inode_key)
                    .await
                    .unwrap();
            } else if retained == 1 {
                first
                    .db
                    .inject_reserved_authority_delete_for_test(name_key)
                    .await
                    .unwrap();
            }
            first.flush_coordinator.flush().await.unwrap();
            first.db.close().await.unwrap();
            drop(first);
            let fs = open_fs(object_store).await.unwrap();
            let protected = [
                codec.inode_key(active.export.inode),
                codec.extent_key(active.export.inode, 0),
                codec.inode_key(active.export.nbd_directory_inode),
                codec.dir_entry_key(active.export.nbd_directory_inode, &active.export.name),
                codec.dir_entry_key(0, b".nbd"),
            ];
            for key in protected {
                let original = fs
                    .db
                    .get_bytes(&key)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| Bytes::from_static(b"candidate"));
                for value in [Some(original), None] {
                    let mut transaction = Transaction::new();
                    if let Some(value) = value {
                        transaction.put_bytes(&key, value);
                    } else {
                        transaction.delete_bytes(&key);
                    }
                    assert_eq!(
                        fs.write_coordinator.commit(transaction).await,
                        Err(crate::fs::errors::FsError::OperationNotPermitted)
                    );
                }
            }
            assert_eq!(fs.export_authority.dst_prepared_mutations(), 0);
        }
    }

    #[tokio::test]
    async fn deny_index_scans_once_inserts_activation_and_stays_conservative() {
        let fs = new_export_fs().await;
        assert_eq!(fs.write_coordinator.dst_export_binding_index_rebuilds(), 1);
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let codec = crate::fs::key_codec::KeyCodec::new();
        let attack_key = codec.extent_key(active.export.inode, 777);
        let mut attack = Transaction::new();
        attack.put_bytes(&attack_key, Bytes::from_static(b"blocked"));
        assert_eq!(
            fs.write_coordinator.commit(attack).await,
            Err(crate::fs::errors::FsError::OperationNotPermitted)
        );
        assert_eq!(fs.write_coordinator.dst_export_binding_index_rebuilds(), 1);

        let (name_key, inode_key) = reverse_binding_keys(&reverse_binding_for(&active));
        for key in [
            codec.export_authority_key(&active.workspace_id),
            name_key,
            inode_key,
        ] {
            fs.db
                .inject_reserved_authority_delete_for_test(key)
                .await
                .unwrap();
        }
        let mut retry = Transaction::new();
        retry.put_bytes(&attack_key, Bytes::from_static(b"still-blocked"));
        assert_eq!(
            fs.write_coordinator.commit(retry).await,
            Err(crate::fs::errors::FsError::OperationNotPermitted)
        );
        assert_eq!(fs.write_coordinator.dst_export_binding_index_rebuilds(), 1);
    }

    #[tokio::test]
    async fn malformed_binding_graph_poisons_the_index_without_repeated_scans() {
        let fs = ZeroFS::new_in_memory().await.unwrap();
        let codec = crate::fs::key_codec::KeyCodec::new();
        fs.db
            .inject_reserved_authority_value_for_test(
                codec.export_authority_key("workspace-corrupt"),
                Bytes::from_static(b"malformed"),
            )
            .await
            .unwrap();
        let unbound_key = codec.extent_key(999, 0);
        for value in [b"first".as_slice(), b"second".as_slice()] {
            let mut transaction = Transaction::new();
            transaction.put_bytes(&unbound_key, Bytes::copy_from_slice(value));
            assert_eq!(
                fs.write_coordinator.commit(transaction).await,
                Err(crate::fs::errors::FsError::InvalidData)
            );
        }
        assert_eq!(fs.write_coordinator.dst_export_binding_index_rebuilds(), 1);
        assert!(fs.db.get_bytes(&unbound_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn legacy_v1_forward_or_outcome_blocks_profile_enablement() {
        for subtype in [1u8, 2u8] {
            let fs = ZeroFS::new_in_memory().await.unwrap();
            let mut key = b"meta".to_vec();
            key.extend_from_slice(&[0x0b, 1, subtype]);
            key.extend_from_slice(b"legacy");
            fs.db
                .inject_reserved_authority_value_for_test(
                    Bytes::from(key),
                    Bytes::from_static(b"legacy-v1"),
                )
                .await
                .unwrap();
            fs.export_authority
                .install_process_guard(ShardProcessGuard::for_test())
                .unwrap();
            assert_eq!(
                fs.export_authority.enable_standalone_profile().await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            assert_eq!(
                fs.export_authority.get("workspace-a").await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            let model = apply_transition(
                None,
                ExportAuthorityTransition::Activate(activate_command(authority(3, 5))),
                NOW,
                BOOT,
            )
            .unwrap();
            let expected =
                mutation_for(&model, Transaction::new(), MutationKind::Flush, 79).expectation();
            assert_eq!(
                fs.export_authority.lookup_mutation_current(&expected).await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            assert_eq!(
                fs.export_authority.lookup_mutation_durable(&expected).await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            assert_eq!(
                fs.export_authority
                    .activate(activate_command(authority(3, 5)))
                    .await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            assert_eq!(
                fs.export_authority
                    .refresh(RefreshExport {
                        workspace_id: model.workspace_id.clone(),
                        expected_export: model.export.clone(),
                        expected_authority: model.authority.clone(),
                        session_id: "session-a".into(),
                        expected_capability_id: "capability-a".into(),
                        replacement_authority: authority(3, 6),
                        replacement_capability_id: "capability-b".into(),
                        replacement_expires_at_unix_millis: u64::MAX,
                    })
                    .await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            assert_eq!(
                fs.export_authority
                    .deactivate(DeactivateExport {
                        workspace_id: model.workspace_id.clone(),
                        expected_export: model.export.clone(),
                        expected_authority: model.authority.clone(),
                        session_id: "session-a".into(),
                    })
                    .await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            assert_eq!(
                fs.export_authority
                    .advance_fence(AdvanceFence {
                        workspace_id: model.workspace_id.clone(),
                        export: model.export.clone(),
                        expected_authority: Some(model.authority.clone()),
                        new_non_writable_authority: model.authority.clone(),
                        reject_through_placement_epoch: model.authority.placement_epoch,
                    })
                    .await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            assert_eq!(
                fs.export_authority
                    .commit_mutation(mutation_for(
                        &model,
                        Transaction::new(),
                        MutationKind::Flush,
                        80,
                    ))
                    .await,
                Err(ExportAuthorityError::MigrationRequired)
            );
            let raw_key = crate::fs::key_codec::KeyCodec::new().extent_key(999, 0);
            for value in [b"first".as_slice(), b"second".as_slice()] {
                let mut raw = Transaction::new();
                raw.put_bytes(&raw_key, Bytes::copy_from_slice(value));
                assert_eq!(
                    fs.write_coordinator.commit(raw).await,
                    Err(crate::fs::errors::FsError::InvalidData)
                );
            }
            assert_eq!(fs.write_coordinator.dst_export_binding_index_rebuilds(), 1);
            assert!(fs.db.get_bytes(&raw_key).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn scan_setup_or_stream_error_sticky_poison_the_deny_index() {
        for phase in 1..=4 {
            for midstream in [false, true] {
                let fs = ZeroFS::new_in_memory().await.unwrap();
                if midstream {
                    fs.db.dst_fail_scan_midstream_on(phase);
                } else {
                    fs.db.dst_fail_scan_setup_on(phase);
                }
                let key = crate::fs::key_codec::KeyCodec::new().extent_key(999, 0);
                for value in [b"first".as_slice(), b"second".as_slice()] {
                    let mut transaction = Transaction::new();
                    transaction.put_bytes(&key, Bytes::copy_from_slice(value));
                    assert_eq!(
                        fs.write_coordinator.commit(transaction).await,
                        Err(crate::fs::errors::FsError::InvalidData)
                    );
                }
                assert_eq!(fs.write_coordinator.dst_export_binding_index_rebuilds(), 1);
                assert!(fs.db.get_bytes(&key).await.unwrap().is_none());
            }
        }
    }

    #[tokio::test]
    async fn activation_requires_the_canonical_root_nbd_directory() {
        let fs = new_export_fs().await;
        let creds = crate::fs::test_util::test_creds();
        let other_directory = fs
            .mkdir(
                &creds,
                0,
                b"other",
                &crate::fs::types::SetAttributes::default(),
            )
            .await
            .unwrap()
            .0;
        let other_file = fs
            .create(
                &creds,
                other_directory,
                b"disk-a",
                &crate::fs::types::SetAttributes::default(),
            )
            .await
            .unwrap()
            .0;
        assert_eq!(
            fs.export_authority
                .activate(activate_command_for(
                    authority(3, 5),
                    export_with_size(other_directory, other_file, 0),
                ))
                .await,
            Err(ExportAuthorityError::Invalid)
        );
    }

    #[tokio::test]
    async fn final_gate_ignores_warm_metadata_caches_and_reads_current_db_rows() {
        for candidate in 0..4 {
            let fs = new_export_fs().await;
            let active = fs
                .export_authority
                .activate(activate_command(authority(3, 5)))
                .await
                .unwrap();
            fs.inode_store.get(active.export.inode).await.unwrap();
            fs.directory_store
                .get(active.export.nbd_directory_inode, &active.export.name)
                .await
                .unwrap();
            let mut corrupt = Transaction::new();
            if candidate == 0 {
                let mut inode = fs.inode_store.get(active.export.inode).await.unwrap();
                let crate::fs::inode::Inode::File(file) = &mut inode else {
                    panic!("export must remain a file");
                };
                file.size += 1;
                corrupt.put_bytes(
                    &crate::fs::key_codec::KeyCodec::new().inode_key(active.export.inode),
                    bincode::serialize(&inode).unwrap().into(),
                );
            } else if candidate == 1 {
                corrupt.put_bytes(
                    &crate::fs::key_codec::KeyCodec::new()
                        .dir_entry_key(active.export.nbd_directory_inode, &active.export.name),
                    crate::fs::key_codec::KeyCodec::encode_dir_entry(active.export.inode + 100, 3),
                );
            } else if candidate == 2 {
                corrupt.put_bytes(
                    &crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, 999),
                    Bytes::from_static(b"raw-extent-must-not-apply"),
                );
            } else {
                corrupt.delete_bytes(
                    &crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, 0),
                );
            }
            let expected = mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Flush,
                81 + candidate,
            )
            .expectation();
            assert_eq!(
                fs.write_coordinator.commit(corrupt).await,
                Err(crate::fs::errors::FsError::OperationNotPermitted)
            );
            assert_eq!(fs.export_authority.dst_prepared_mutations(), 0);
            assert_eq!(
                fs.export_authority
                    .lookup_mutation_current(&expected)
                    .await
                    .unwrap(),
                ExportMutationLookup::Unknown
            );
            let inode = fs.inode_store.get(active.export.inode).await.unwrap();
            assert_eq!(inode.size(), active.export.advertised_size);
            assert_eq!(
                fs.directory_store
                    .get(active.export.nbd_directory_inode, &active.export.name)
                    .await
                    .unwrap(),
                active.export.inode
            );
        }

        let fs = new_export_fs().await;
        let unbound_key = crate::fs::key_codec::KeyCodec::new().extent_key(999, 0);
        let mut put = Transaction::new();
        put.put_bytes(&unbound_key, Bytes::from_static(b"unbound"));
        fs.write_coordinator.commit(put).await.unwrap();
        assert_eq!(
            fs.db.get_bytes(&unbound_key).await.unwrap().as_deref(),
            Some(&b"unbound"[..])
        );
        let mut delete = Transaction::new();
        delete.delete_bytes(&unbound_key);
        fs.write_coordinator.commit(delete).await.unwrap();
        assert!(fs.db.get_bytes(&unbound_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn physical_binding_decoder_rejects_trailing_inode_or_directory_bytes() {
        for corrupt_inode in [true, false] {
            let fs = new_export_fs().await;
            let export = ensure_test_export(&fs, 4096).await.unwrap();
            let codec = crate::fs::key_codec::KeyCodec::new();
            let key = if corrupt_inode {
                codec.inode_key(export.inode)
            } else {
                codec.dir_entry_key(export.nbd_directory_inode, &export.name)
            };
            let mut bytes = fs.db.get_bytes(&key).await.unwrap().unwrap().to_vec();
            bytes.push(0xff);
            let mut corrupt = Transaction::new();
            corrupt.put_bytes(&key, Bytes::from(bytes));
            fs.write_coordinator.commit(corrupt).await.unwrap();
            assert_eq!(
                fs.export_authority
                    .activate(activate_command_for(authority(3, 5), export))
                    .await,
                Err(ExportAuthorityError::Corrupt)
            );
        }
    }

    #[tokio::test]
    async fn ordered_queue_prevents_fence_mutation_toctou() {
        let fs = Arc::new(new_export_fs().await);
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let key = crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, 999);
        let mut transaction = Transaction::new();
        transaction.put_bytes(&key, Bytes::from_static(b"before-fence"));

        let mutation = {
            let fs = fs.clone();
            let active = active.clone();
            tokio::spawn(async move {
                fs.export_authority
                    .commit_mutation(mutation_for(
                        &active,
                        transaction,
                        MutationKind::Write { fua: false },
                        45,
                    ))
                    .await
            })
        };
        let fence = {
            let fs = fs.clone();
            let active = active.clone();
            tokio::spawn(async move {
                fs.export_authority
                    .advance_fence(AdvanceFence {
                        workspace_id: active.workspace_id.clone(),
                        export: active.export.clone(),
                        expected_authority: Some(active.authority.clone()),
                        new_non_writable_authority: active.authority.clone(),
                        reject_through_placement_epoch: active.authority.placement_epoch,
                    })
                    .await
            })
        };

        let mutation_result = mutation.await.unwrap();
        let fence_result = fence.await.unwrap();
        assert!(fence_result.is_ok());
        match mutation_result {
            Ok(_) => assert_eq!(
                fs.db.get_bytes(&key).await.unwrap().as_deref(),
                Some(&b"before-fence"[..])
            ),
            Err(error) => {
                assert_eq!(error, ExportAuthorityError::StaleMutation);
                assert!(fs.db.get_bytes(&key).await.unwrap().is_none());
            }
        }
    }

    #[tokio::test]
    async fn reopen_durably_invalidates_the_previous_process_session() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let first = open_fs(object_store.clone()).await.unwrap();
        let active = first
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        first.db.close().await.unwrap();
        drop(first);

        let reopened = open_fs(object_store).await.unwrap();
        let record = reopened
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(record.active_session.is_none());
        assert_eq!(record.rejected_through_placement_epoch, 3);
        let refresh = reopened
            .export_authority
            .refresh(RefreshExport {
                workspace_id: active.workspace_id.clone(),
                expected_export: active.export.clone(),
                expected_authority: active.authority.clone(),
                session_id: active.active_session.as_ref().unwrap().session_id.clone(),
                expected_capability_id: active
                    .active_session
                    .as_ref()
                    .unwrap()
                    .capability_id
                    .clone(),
                replacement_authority: authority(3, 6),
                replacement_capability_id: "capability-after-reopen".into(),
                replacement_expires_at_unix_millis: u64::MAX,
            })
            .await;
        assert_eq!(refresh, Err(ExportAuthorityError::Conflict));
        let error = reopened
            .export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Flush,
                46,
            ))
            .await
            .unwrap_err();
        assert_eq!(error, ExportAuthorityError::StaleMutation);
        let replacement = reopened
            .export_authority
            .activate(ActivateExport {
                workspace_id: active.workspace_id.clone(),
                export: active.export.clone(),
                authority: authority(4, 7),
                session: session("session-after-reopen", "capability-after-reopen", u64::MAX),
            })
            .await
            .unwrap();
        assert_eq!(replacement.authority.placement_epoch, 4);
        assert_eq!(
            replacement
                .active_session
                .as_ref()
                .unwrap()
                .committed_through_sequence,
            0
        );
    }

    #[tokio::test]
    async fn stale_mutation_uses_the_common_counter_failure_epilogue() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let fs = open_fs(object_store.clone()).await.unwrap();
        let rejected_id = fs.inode_store.allocate();
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        fs.export_authority
            .advance_fence(AdvanceFence {
                workspace_id: active.workspace_id.clone(),
                export: active.export.clone(),
                expected_authority: Some(active.authority.clone()),
                new_non_writable_authority: active.authority.clone(),
                reject_through_placement_epoch: active.authority.placement_epoch,
            })
            .await
            .unwrap();

        let mut rejected = Transaction::new();
        rejected.put_bytes(
            &crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, 47),
            Bytes::from_static(b"rejected"),
        );
        assert_eq!(
            fs.export_authority
                .commit_mutation(mutation_for(
                    &active,
                    rejected,
                    MutationKind::Write { fua: false },
                    47,
                ),)
                .await,
            Err(ExportAuthorityError::StaleMutation)
        );

        let committed_id = fs.inode_store.allocate();
        assert!(committed_id > rejected_id);
        let mut committed = Transaction::new();
        fs.inode_store
            .save(&mut committed, committed_id, &test_file_inode(2))
            .unwrap();
        fs.write_coordinator.commit(committed).await.unwrap();
        fs.db.close().await.unwrap();
        drop(fs);

        let reopened = open_fs(object_store).await.unwrap();
        assert!(reopened.inode_store.allocate() > committed_id);
    }

    #[tokio::test]
    async fn mutation_outcomes_dedupe_sequence_and_fence_digest_conflicts() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let key = crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, 700);
        let make = |command: u8, value: &'static [u8], operation: u8| {
            let mut transaction = Transaction::new();
            transaction.put_bytes(&key, Bytes::from_static(value));
            ExportMutationBuilder::from_transaction_for_test(
                token(&active),
                [operation; SHA256_SIZE],
                ExportMutationCommand::Write {
                    offset: u64::from(command),
                    data: Bytes::from_static(value),
                    fua: false,
                },
                transaction,
            )
            .unwrap()
        };

        let first = make(1, b"first", 50);
        let first_expected = first.expectation();
        let committed = fs.export_authority.commit_mutation(first).await.unwrap();
        assert_eq!(committed.mutation.sequence, 1);

        let replay = fs
            .export_authority
            .commit_mutation(make(1, b"first", 50))
            .await
            .unwrap();
        assert_eq!(replay, committed);
        assert_eq!(
            fs.export_authority
                .lookup_mutation_current(&first_expected)
                .await
                .unwrap(),
            ExportMutationLookup::Committed(Box::new(committed.clone()))
        );

        assert_eq!(
            fs.export_authority
                .commit_mutation(make(2, b"different", 50))
                .await,
            Err(ExportAuthorityError::Conflict)
        );
        let fenced = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(fenced.active_session.is_none());
        assert_eq!(fenced.rejected_through_placement_epoch, 3);

        let blocked_key =
            crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, 701);
        let mut blocked = Transaction::new();
        blocked.put_bytes(&blocked_key, Bytes::from_static(b"blocked"));
        assert_eq!(
            fs.export_authority
                .commit_mutation(
                    ExportMutationBuilder::from_transaction_for_test(
                        token(&active),
                        [51; SHA256_SIZE],
                        ExportMutationCommand::Write {
                            offset: 0,
                            data: Bytes::from_static(b"blocked"),
                            fua: false,
                        },
                        blocked,
                    )
                    .unwrap(),
                )
                .await,
            Err(ExportAuthorityError::StaleMutation)
        );
        assert!(fs.db.get_bytes(&blocked_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn coordinator_sequences_distinct_mutations_and_replays_older_outcomes() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let first = mutation_for(
            &active,
            Transaction::new(),
            MutationKind::Write { fua: false },
            52,
        );
        let first_expected = first.expectation();
        let first_outcome = fs.export_authority.commit_mutation(first).await.unwrap();
        let second = fs
            .export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Trim { fua: false },
                53,
            ))
            .await
            .unwrap();
        assert_eq!(first_outcome.mutation.sequence, 1);
        assert_eq!(second.mutation.sequence, 2);
        assert_eq!(
            fs.export_authority
                .lookup_mutation_current(&first_expected)
                .await
                .unwrap(),
            ExportMutationLookup::Committed(Box::new(first_outcome.clone()))
        );
        let replay = fs
            .export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Write { fua: false },
                52,
            ))
            .await
            .unwrap();
        assert_eq!(replay, first_outcome);
    }

    #[tokio::test]
    async fn cancelled_caller_cannot_release_mutation_dedupe_serialization() {
        let fs = Arc::new(new_export_fs().await);
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        fs.write_coordinator.dst_pause_next_export_after_permit();
        let first = tokio::spawn({
            let fs = fs.clone();
            let active = active.clone();
            async move {
                fs.export_authority
                    .commit_mutation(mutation_for(
                        &active,
                        Transaction::new(),
                        MutationKind::Write { fua: false },
                        58,
                    ))
                    .await
            }
        });
        fs.write_coordinator.dst_wait_export_after_permit().await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        let replay = tokio::spawn({
            let fs = fs.clone();
            let active = active.clone();
            async move {
                fs.export_authority
                    .commit_mutation(mutation_for(
                        &active,
                        Transaction::new(),
                        MutationKind::Write { fua: false },
                        58,
                    ))
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(
            !replay.is_finished(),
            "the queued request must retain the dedupe guard after caller cancellation"
        );
        fs.write_coordinator.dst_release_export_after_permit();
        let outcome = replay.await.unwrap().unwrap();
        assert_eq!(outcome.mutation.sequence, 1);
    }

    #[tokio::test]
    async fn fua_unknown_converges_by_outcome_without_reapplying_data() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let fs = open_fs(object_store.clone()).await.unwrap();
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let crash_snapshot = snapshot_object_store(&object_store).await;
        let build = || {
            let key = crate::fs::key_codec::KeyCodec::new().extent_key(active.export.inode, 800);
            let mut transaction = Transaction::new();
            transaction.put_bytes(&key, Bytes::from_static(b"fua-data"));
            ExportMutationBuilder::from_transaction_for_test(
                token(&active),
                [54; SHA256_SIZE],
                ExportMutationCommand::Write {
                    offset: 800,
                    data: Bytes::from_static(b"fua-data"),
                    fua: true,
                },
                transaction,
            )
            .unwrap()
        };
        let expected = build().expectation();
        fs.write_coordinator.dst_fail_next_workspace_durable_flush();
        assert_eq!(
            fs.export_authority.commit_mutation(build()).await,
            Err(ExportAuthorityError::CommitOutcomeUnknown)
        );
        let current = match fs
            .export_authority
            .lookup_mutation_current(&expected)
            .await
            .unwrap()
        {
            ExportMutationLookup::Committed(outcome) => *outcome,
            ExportMutationLookup::Unknown => panic!("local apply must publish current outcome"),
        };
        assert_eq!(current.mutation.sequence, 1);
        assert_eq!(
            fs.export_authority
                .lookup_mutation_durable(&expected)
                .await
                .unwrap(),
            ExportMutationLookup::Unknown
        );

        let reopened = open_fs(crash_snapshot).await.unwrap();
        assert_eq!(
            reopened
                .export_authority
                .lookup_mutation_durable(&expected)
                .await
                .unwrap(),
            ExportMutationLookup::Unknown
        );

        let replay = fs.export_authority.commit_mutation(build()).await.unwrap();
        assert_eq!(replay, current);
        assert_eq!(
            fs.export_authority
                .lookup_mutation_durable(&expected)
                .await
                .unwrap(),
            ExportMutationLookup::Committed(Box::new(current))
        );
    }

    #[tokio::test]
    async fn typed_builder_rejects_another_export_inode_before_commit() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let other_key = crate::fs::key_codec::KeyCodec::new().extent_key(88, 0);
        let mut transaction = Transaction::new();
        transaction.put_bytes(&other_key, Bytes::from_static(b"other-export"));
        assert!(matches!(
            ExportMutationBuilder::from_transaction_for_test(
                token(&active),
                [55; SHA256_SIZE],
                ExportMutationCommand::Write {
                    offset: 0,
                    data: Bytes::from_static(b"other-export"),
                    fua: false,
                },
                transaction,
            ),
            Err(ExportAuthorityError::Invalid)
        ));
        assert!(fs.db.get_bytes(&other_key).await.unwrap().is_none());
    }

    #[test]
    fn every_authority_transition_preserves_the_immutable_export_binding() {
        let active = apply_transition(
            None,
            ExportAuthorityTransition::Activate(activate_command(authority(3, 5))),
            NOW,
            BOOT,
        )
        .unwrap();
        let other = export(88);
        assert_eq!(
            apply_transition(
                Some(active.clone()),
                ExportAuthorityTransition::Refresh(RefreshExport {
                    workspace_id: active.workspace_id.clone(),
                    expected_export: other.clone(),
                    expected_authority: active.authority.clone(),
                    session_id: "session-a".into(),
                    expected_capability_id: "capability-a".into(),
                    replacement_authority: authority(3, 6),
                    replacement_capability_id: "capability-b".into(),
                    replacement_expires_at_unix_millis: u64::MAX,
                }),
                NOW,
                BOOT,
            ),
            Err(ExportAuthorityError::Conflict)
        );
        assert_eq!(
            apply_transition(
                Some(active.clone()),
                ExportAuthorityTransition::Deactivate(DeactivateExport {
                    workspace_id: active.workspace_id.clone(),
                    expected_export: other.clone(),
                    expected_authority: active.authority.clone(),
                    session_id: "session-a".into(),
                }),
                NOW,
                BOOT,
            ),
            Err(ExportAuthorityError::Conflict)
        );
        assert_eq!(
            apply_transition(
                Some(active.clone()),
                ExportAuthorityTransition::AdvanceFence(AdvanceFence {
                    workspace_id: active.workspace_id.clone(),
                    export: other,
                    expected_authority: Some(active.authority.clone()),
                    new_non_writable_authority: active.authority.clone(),
                    reject_through_placement_epoch: active.authority.placement_epoch,
                }),
                NOW,
                BOOT,
            ),
            Err(ExportAuthorityError::Conflict)
        );
        assert_eq!(active.export, export(2));
    }

    #[test]
    fn activate_always_resets_caller_sequence_to_zero() {
        let mut command = activate_command(authority(3, 5));
        command.session.committed_through_sequence = u64::MAX;
        let active = apply_transition(
            None,
            ExportAuthorityTransition::Activate(command),
            NOW,
            BOOT,
        )
        .unwrap();
        assert_eq!(
            active
                .active_session
                .as_ref()
                .unwrap()
                .committed_through_sequence,
            0
        );
    }

    #[tokio::test]
    async fn mutation_outcome_copied_under_another_operation_key_is_corrupt() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let mutation = mutation_for(
            &active,
            Transaction::new(),
            MutationKind::Write { fua: false },
            56,
        );
        let original = fs.export_authority.commit_mutation(mutation).await.unwrap();
        let other_mutation = mutation_for(
            &active,
            Transaction::new(),
            MutationKind::Write { fua: false },
            57,
        );
        let expected = other_mutation.expectation();
        let copied_key = mutation_outcome_key(&expected);
        fs.db
            .inject_reserved_authority_value_for_test(
                copied_key,
                encode_outcome(&original).unwrap(),
            )
            .await
            .unwrap();
        fs.flush_coordinator.flush().await.unwrap();
        assert_eq!(
            fs.export_authority.lookup_mutation_durable(&expected).await,
            Err(ExportAuthorityError::Corrupt)
        );
    }

    async fn real_export_fs() -> (ZeroFS, ExportAuthorityRecord) {
        let fs = new_export_fs().await;
        let export = ensure_test_export(&fs, 4096).await.unwrap();
        fs.write(
            &crate::fs::types::AuthContext::default(),
            export.inode,
            0,
            &Bytes::from(vec![0x11; 4096]),
        )
        .await
        .unwrap();
        let active = fs
            .export_authority
            .activate(activate_command_for(authority(3, 5), export))
            .await
            .unwrap();
        (fs, active)
    }

    async fn sparse_real_export_fs(
        object_store: Arc<dyn slatedb::object_store::ObjectStore>,
        size: u64,
    ) -> (ZeroFS, ExportAuthorityRecord) {
        let fs = open_fs(object_store).await.unwrap();
        let mut export = ensure_test_export(&fs, 4096).await.unwrap();
        let mut inode = fs.inode_store.get(export.inode).await.unwrap();
        let crate::fs::inode::Inode::File(file) = &mut inode else {
            panic!("created export must be a file");
        };
        file.size = size;
        let mut transaction = fs.db.new_transaction().unwrap();
        fs.inode_store
            .save(&mut transaction, export.inode, &inode)
            .unwrap();
        fs.write_coordinator.commit(transaction).await.unwrap();
        export.advertised_size = size;
        let active = fs
            .export_authority
            .activate(activate_command_for(authority(3, 5), export))
            .await
            .unwrap();
        (fs, active)
    }

    async fn object_inventory(store: &Arc<dyn slatedb::object_store::ObjectStore>) -> (usize, u64) {
        let objects = store.list(None).try_collect::<Vec<_>>().await.unwrap();
        let bytes = objects.iter().map(|object| object.size).sum();
        (objects.len(), bytes)
    }

    #[tokio::test]
    async fn typed_commands_build_and_commit_their_exact_filesystem_effect() {
        let (fs, active) = real_export_fs().await;
        let write = ExportMutationBuilder::build(
            token(&active),
            [0x61; SHA256_SIZE],
            ExportMutationCommand::Write {
                offset: 8,
                data: Bytes::from_static(b"rhizome"),
                fua: true,
            },
        )
        .unwrap();
        let write_outcome = fs.export_authority.commit_mutation(write).await.unwrap();
        assert_eq!(write_outcome.mutation.sequence, 1);
        let (bytes, _) = fs
            .read_file(
                &crate::fs::types::AuthContext::default(),
                active.export.inode,
                8,
                7,
            )
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), b"rhizome");

        let trim = ExportMutationBuilder::build(
            token(&active),
            [0x62; SHA256_SIZE],
            ExportMutationCommand::Trim {
                offset: 9,
                length: 3,
                fua: false,
            },
        )
        .unwrap();
        assert_eq!(
            fs.export_authority
                .commit_mutation(trim)
                .await
                .unwrap()
                .mutation
                .sequence,
            2
        );
        let (bytes, _) = fs
            .read_file(
                &crate::fs::types::AuthContext::default(),
                active.export.inode,
                8,
                7,
            )
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), b"r\0\0\0ome");

        let zeroes = ExportMutationBuilder::build(
            token(&active),
            [0x63; SHA256_SIZE],
            ExportMutationCommand::WriteZeroes {
                offset: 12,
                length: 3,
                fua: true,
            },
        )
        .unwrap();
        assert_eq!(
            fs.export_authority
                .commit_mutation(zeroes)
                .await
                .unwrap()
                .mutation
                .sequence,
            3
        );
        let (bytes, _) = fs
            .read_file(
                &crate::fs::types::AuthContext::default(),
                active.export.inode,
                8,
                7,
            )
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), b"r\0\0\0\0\0\0");

        let flush = ExportMutationBuilder::build(
            token(&active),
            [0x64; SHA256_SIZE],
            ExportMutationCommand::Flush,
        )
        .unwrap();
        assert_eq!(
            fs.export_authority
                .commit_mutation(flush)
                .await
                .unwrap()
                .mutation
                .sequence,
            4
        );
    }

    #[tokio::test]
    async fn typed_replay_never_prepares_or_reapplies_the_old_effect() {
        let (fs, active) = real_export_fs().await;
        let original = || {
            ExportMutationBuilder::build(
                token(&active),
                [0x65; SHA256_SIZE],
                ExportMutationCommand::Write {
                    offset: 0,
                    data: Bytes::from_static(b"first"),
                    fua: false,
                },
            )
            .unwrap()
        };
        let first = fs
            .export_authority
            .commit_mutation(original())
            .await
            .unwrap();
        let later = ExportMutationBuilder::build(
            token(&active),
            [0x66; SHA256_SIZE],
            ExportMutationCommand::Write {
                offset: 0,
                data: Bytes::from_static(b"later"),
                fua: false,
            },
        )
        .unwrap();
        fs.export_authority.commit_mutation(later).await.unwrap();
        assert_eq!(
            fs.export_authority
                .commit_mutation(original())
                .await
                .unwrap(),
            first
        );
        let (bytes, _) = fs
            .read_file(
                &crate::fs::types::AuthContext::default(),
                active.export.inode,
                0,
                5,
            )
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), b"later");
    }

    #[tokio::test]
    async fn refreshed_session_is_durably_fenced_on_old_operation_digest_conflict() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        fs.export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Write { fua: false },
                0x67,
            ))
            .await
            .unwrap();
        let refreshed = fs
            .export_authority
            .refresh(RefreshExport {
                workspace_id: active.workspace_id.clone(),
                expected_export: active.export.clone(),
                expected_authority: active.authority.clone(),
                session_id: "session-a".into(),
                expected_capability_id: "capability-a".into(),
                replacement_authority: authority(3, 6),
                replacement_capability_id: "capability-b".into(),
                replacement_expires_at_unix_millis: u64::MAX,
            })
            .await
            .unwrap();
        let conflicting = ExportMutationBuilder::from_transaction_for_test(
            token(&active),
            [0x67; SHA256_SIZE],
            ExportMutationCommand::Write {
                offset: 9,
                data: Bytes::from_static(b"different"),
                fua: false,
            },
            Transaction::new(),
        )
        .unwrap();
        let error = fs
            .export_authority
            .commit_mutation(conflicting)
            .await
            .unwrap_err();
        assert_eq!(error, ExportAuthorityError::Conflict);
        assert!(error.close_session());
        let fenced = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(fenced.active_session.is_none());
        assert_eq!(
            fenced.rejected_through_placement_epoch,
            refreshed.authority.placement_epoch
        );
    }

    #[tokio::test]
    async fn conflict_fence_unknown_outcomes_require_authority_readback() {
        let fs = new_export_fs().await;
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        fs.export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Write { fua: false },
                0x68,
            ))
            .await
            .unwrap();
        let conflict = || {
            ExportMutationBuilder::from_transaction_for_test(
                token(&active),
                [0x68; SHA256_SIZE],
                ExportMutationCommand::Write {
                    offset: 10,
                    data: Bytes::from_static(b"conflict"),
                    fua: false,
                },
                Transaction::new(),
            )
            .unwrap()
        };

        fs.write_coordinator.dst_fail_next_workspace_durable_flush();
        assert_eq!(
            fs.export_authority.commit_mutation(conflict()).await,
            Err(ExportAuthorityError::CommitOutcomeUnknown)
        );
        let durable_before_retry = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(durable_before_retry.active_session.is_some());

        fs.write_coordinator.dst_drop_next_workspace_durable_reply();
        assert_eq!(
            fs.export_authority.commit_mutation(conflict()).await,
            Err(ExportAuthorityError::CommitOutcomeUnknown)
        );
        let durable = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(durable.active_session.is_none());
        assert_eq!(durable.rejected_through_placement_epoch, 3);
    }

    #[tokio::test]
    async fn conflict_fence_reproves_the_exact_outcome_at_final_permit() {
        let fs = Arc::new(new_export_fs().await);
        let active = fs
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let original = fs
            .export_authority
            .commit_mutation(mutation_for(
                &active,
                Transaction::new(),
                MutationKind::Write { fua: false },
                0x69,
            ))
            .await
            .unwrap();
        let conflicting = ExportMutationBuilder::from_transaction_for_test(
            token(&active),
            [0x69; SHA256_SIZE],
            ExportMutationCommand::Write {
                offset: 11,
                data: Bytes::from_static(b"conflicting-command"),
                fua: false,
            },
            Transaction::new(),
        )
        .unwrap();
        let expected = conflicting.expectation();
        fs.write_coordinator.dst_pause_next_conflict_after_permit();
        let task = tokio::spawn({
            let fs = fs.clone();
            async move { fs.export_authority.commit_mutation(conflicting).await }
        });
        fs.write_coordinator.dst_wait_conflict_after_permit().await;

        let mut replacement = original;
        replacement.mutation.command_digest = CommandDigest([0xa5; SHA256_SIZE]);
        let key = mutation_outcome_key(&expected);
        fs.db
            .inject_reserved_authority_value_for_test(key, encode_outcome(&replacement).unwrap())
            .await
            .unwrap();
        fs.write_coordinator.dst_release_conflict_after_permit();
        assert_eq!(task.await.unwrap(), Err(ExportAuthorityError::Corrupt));
        let authority = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(authority.active_session.is_some());
    }

    #[tokio::test]
    async fn durable_fence_rejects_repeated_large_writes_before_any_object_store_cost() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let size = crate::fs::store::extent::SEAL_THRESHOLD as u64 + crate::fs::EXTENT_SIZE as u64;
        let (fs, active) = sparse_real_export_fs(object_store.clone(), size).await;
        fs.export_authority
            .advance_fence(AdvanceFence {
                workspace_id: active.workspace_id.clone(),
                export: active.export.clone(),
                expected_authority: Some(active.authority.clone()),
                new_non_writable_authority: active.authority.clone(),
                reject_through_placement_epoch: active.authority.placement_epoch,
            })
            .await
            .unwrap();
        let prepared_before = fs.export_authority.dst_prepared_mutations();
        let before = object_inventory(&object_store).await;
        let data = Bytes::from(vec![0x5a; crate::fs::store::extent::SEAL_THRESHOLD + 1]);
        for ordinal in [0x71, 0x72, 0x73] {
            let mutation = ExportMutationBuilder::build(
                token(&active),
                [ordinal; SHA256_SIZE],
                ExportMutationCommand::Write {
                    offset: 0,
                    data: data.clone(),
                    fua: false,
                },
            )
            .unwrap();
            assert_eq!(
                fs.export_authority.commit_mutation(mutation).await,
                Err(ExportAuthorityError::StaleMutation)
            );
        }
        assert_eq!(
            fs.export_authority.dst_prepared_mutations(),
            prepared_before,
            "a durably fenced request must not enter ExtentStore preparation"
        );
        assert_eq!(object_inventory(&object_store).await, before);
    }

    #[tokio::test]
    async fn fence_waits_for_admitted_prepare_and_then_orders_after_the_mutation() {
        let (fs, active) = real_export_fs().await;
        let fs = Arc::new(fs);
        fs.export_authority.dst_pause_next_after_admission();
        let mutation = ExportMutationBuilder::build(
            token(&active),
            [0x74; SHA256_SIZE],
            ExportMutationCommand::Write {
                offset: 0,
                data: Bytes::from_static(b"admitted"),
                fua: false,
            },
        )
        .unwrap();
        let mutation_task = tokio::spawn({
            let fs = fs.clone();
            async move { fs.export_authority.commit_mutation(mutation).await }
        });
        fs.export_authority.dst_wait_after_admission().await;
        let fence_task = tokio::spawn({
            let fs = fs.clone();
            let active = active.clone();
            async move {
                fs.export_authority
                    .advance_fence(AdvanceFence {
                        workspace_id: active.workspace_id.clone(),
                        export: active.export.clone(),
                        expected_authority: Some(active.authority.clone()),
                        new_non_writable_authority: active.authority.clone(),
                        reject_through_placement_epoch: active.authority.placement_epoch,
                    })
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(
            !fence_task.is_finished(),
            "the fence must wait for the admitted prepare reservation"
        );
        fs.export_authority.dst_release_after_admission();
        let outcome = mutation_task.await.unwrap().unwrap();
        assert_eq!(outcome.mutation.sequence, 1);
        fence_task.await.unwrap().unwrap();
        let (bytes, _) = fs
            .read_file(
                &crate::fs::types::AuthContext::default(),
                active.export.inode,
                0,
                8,
            )
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), b"admitted");
        let fenced = fs
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(fenced.active_session.is_none());
    }

    #[tokio::test]
    async fn external_boot_supersession_after_early_gate_blocks_physical_prepare() {
        let (fs, active) = real_export_fs().await;
        let fs = Arc::new(fs);
        let prepared_before = fs.export_authority.dst_prepared_mutations();
        fs.export_authority.dst_pause_next_after_admission();
        let mutation = ExportMutationBuilder::build(
            token(&active),
            [0x7c; SHA256_SIZE],
            ExportMutationCommand::Write {
                offset: 0,
                data: Bytes::from_static(b"must-not-stage"),
                fua: false,
            },
        )
        .unwrap();
        let task = tokio::spawn({
            let fs = fs.clone();
            async move { fs.export_authority.commit_mutation(mutation).await }
        });
        fs.export_authority.dst_wait_after_admission().await;
        fs.db
            .inject_reserved_authority_value_for_test(
                crate::fs::key_codec::KeyCodec::new().export_boot_key(),
                Bytes::from_static(b"external-process-boot"),
            )
            .await
            .unwrap();
        fs.export_authority.dst_release_after_admission();
        assert_eq!(
            task.await.unwrap(),
            Err(ExportAuthorityError::StaleMutation)
        );
        assert_eq!(
            fs.export_authority.dst_prepared_mutations(),
            prepared_before,
            "external durable boot supersession must win before ExtentStore preparation"
        );
        let (bytes, _) = fs
            .read_file(
                &crate::fs::types::AuthContext::default(),
                active.export.inode,
                0,
                14,
            )
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), &[0x11; 14]);
    }

    #[tokio::test]
    async fn block_commands_reject_unrepresentable_final_extent_without_panicking() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let (fs, active) = sparse_real_export_fs(object_store, u64::MAX).await;
        let invalid_offset = u64::MAX - 1;
        for (ordinal, command) in [
            (
                0x75,
                ExportMutationCommand::Write {
                    offset: invalid_offset,
                    data: Bytes::from_static(b"x"),
                    fua: false,
                },
            ),
            (
                0x76,
                ExportMutationCommand::Trim {
                    offset: invalid_offset,
                    length: 1,
                    fua: false,
                },
            ),
            (
                0x77,
                ExportMutationCommand::WriteZeroes {
                    offset: invalid_offset,
                    length: 1,
                    fua: false,
                },
            ),
        ] {
            let mutation =
                ExportMutationBuilder::build(token(&active), [ordinal; 32], command).unwrap();
            assert_eq!(
                fs.export_authority.commit_mutation(mutation).await,
                Err(ExportAuthorityError::Invalid)
            );
        }
        for (ordinal, command) in [
            (
                0x78,
                ExportMutationCommand::Write {
                    offset: u64::MAX,
                    data: Bytes::from_static(b"x"),
                    fua: false,
                },
            ),
            (
                0x79,
                ExportMutationCommand::Trim {
                    offset: u64::MAX,
                    length: 1,
                    fua: false,
                },
            ),
            (
                0x7a,
                ExportMutationCommand::WriteZeroes {
                    offset: u64::MAX,
                    length: 1,
                    fua: false,
                },
            ),
        ] {
            let mutation =
                ExportMutationBuilder::build(token(&active), [ordinal; 32], command).unwrap();
            assert_eq!(
                fs.export_authority.commit_mutation(mutation).await,
                Err(ExportAuthorityError::Invalid)
            );
        }
    }

    #[tokio::test]
    async fn old_boot_outcome_cannot_fence_a_reused_session_and_operation_id() {
        let object_store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(slatedb::object_store::memory::InMemory::new());
        let first = open_fs(object_store.clone()).await.unwrap();
        let active = first
            .export_authority
            .activate(activate_command(authority(3, 5)))
            .await
            .unwrap();
        let old = ExportMutationBuilder::from_transaction_for_test(
            token(&active),
            [0x7b; SHA256_SIZE],
            ExportMutationCommand::Write {
                offset: 0,
                data: Bytes::from_static(b"old-boot"),
                fua: false,
            },
            Transaction::new(),
        )
        .unwrap();
        let old_outcome = first.export_authority.commit_mutation(old).await.unwrap();
        first.db.close().await.unwrap();
        drop(first);

        let reopened = open_fs(object_store).await.unwrap();
        let replacement = reopened
            .export_authority
            .activate(ActivateExport {
                workspace_id: active.workspace_id.clone(),
                export: active.export.clone(),
                authority: authority(4, 7),
                session: session("session-a", "capability-new-boot", u64::MAX),
            })
            .await
            .unwrap();
        let new = ExportMutationBuilder::from_transaction_for_test(
            token(&replacement),
            [0x7b; SHA256_SIZE],
            ExportMutationCommand::Write {
                offset: 0,
                data: Bytes::from_static(b"new-boot"),
                fua: false,
            },
            Transaction::new(),
        )
        .unwrap();
        let new_outcome = reopened
            .export_authority
            .commit_mutation(new)
            .await
            .unwrap();
        assert_eq!(new_outcome.mutation.sequence, 1);
        assert_ne!(new_outcome.server_boot_id, old_outcome.server_boot_id);
        assert_ne!(
            new_outcome.authority.placement_epoch,
            old_outcome.authority.placement_epoch
        );
        let current = reopened
            .export_authority
            .get("workspace-a")
            .await
            .unwrap()
            .unwrap();
        assert!(current.active_session.is_some());
        assert_eq!(current.authority, replacement.authority);
    }
}
