# Rhizome Workspace durability barrier mechanics candidate

This branch adds a non-default `rhizome-workspace-barrier-core` feature on top
of the combined export-authority and Workspace-genesis mechanics. It is a
protocol-neutral storage primitive, not an RPC implementation and not a signed
`WorkspaceDurabilityReceipt` authority.

## Reused durability mechanics

The implementation does not add a journal, object format, manifest publisher,
or retrying effect executor. It reuses the pinned SlateDB commit/flush path at
`20c14bbe9cb22405acc5b5067028c7b6d159baba`, ZeroFS's one
`WriteCoordinator`, the open-segment seal hook, and the manifest-publication
hold. A successful data cut therefore means:

1. every earlier per-export mutation has passed the final authority/physical
   mapping permit and has a coordinator-assigned sequence;
2. the open segment has completed its object-store PUT;
3. SlateDB has published the manifest that makes the covered metadata remote
   durable; and
4. one coherent `DbStatus` borrow supplied writer epoch, manifest ID, and
   durable sequence for the cut.

The manifest ID is SlateDB's exact monotonic `VersionedManifest.id`; it is not
inferred from LIST, an ETag, or a separately sampled status field.

## One operation lifecycle

`meta + 0x0A` remains the only operation lifecycle. Before the first flush, the
barrier stores PENDING and then an immutable effect-dispatch claim. The claim
binds the canonical request digest, a random barrier UUID, and a random
installer UUID. Only the invocation that installs (or reads back its own
unknown claim result before dispatch) may perform the one data flush.

If the process or call loses the result after the claim but before the immutable
barrier record is durable, later invocations perform readback only. They never
flush again and never manufacture a different cut. This deliberately accepts a
fail-closed liveness gap rather than making two possible barrier effects share
one operation identity.

Genesis atomically publishes the version-1 current head plus its immutable
version row. A missing initial/current/version row is corruption; barrier code
never falls back to rebuilding a new chain from Genesis.

After the data cut, the same per-Workspace admission guard still excludes every
authority transition and export mutation. The sole WriteCoordinator atomically
publishes:

- one immutable barrier record keyed by Workspace plus request ID;
- the successor immutable versioned head; and
- the successor current Workspace head.

Both live under the reserved `meta + 0x0D` namespace. General transactions,
weak coordinator commits, and direct DB mutation cannot write that namespace.
The 0x0D records are domain state and materialization evidence, not a second
operation state machine. The exact signed terminal bytes, when a future strict
signer supplies them, still complete the existing 0x0A claim.

## Exact cut and head binding

The mechanical receipt binds the canonical request digest, exact effect claim,
complete export session/fence token, Actor generation and AuthorityVersion,
export inode/name/size, expected prior head digest, new head, barrier ID,
coordinator-assigned included write sequence, SlateDB writer epoch, manifest ID,
remote-durable sequence, guarded storage shard, routing revision, and commit
time. A domain-separated digest covers all of those fields.

The initial head is derived only from the immutable Genesis record. Readback
walks the durable version chain and requires every versioned head, predecessor
receipt, and 0x0A terminal/claim relationship to close exactly. Head-only,
receipt-only, missing-predecessor, or forked version graphs fail closed. Each
successor tail-chain digest commits to the complete prior head digest, canonical
barrier command, included export sequence, writer epoch, manifest ID, and
durable sequence. A later barrier is rejected until the prior head's 0x0A
operation contains exact SUCCEEDED terminal bytes. This prevents unsigned
mechanical materialization from silently becoming a new externally usable
authority chain.

## Unknown outcome and recovery

- A lost response after atomic 0x0D publication converges by exact-key remote-
  durable readback and returns byte-identical materialization evidence.
- A failure after the data flush but before 0x0D publication remains
  `CommitOutcomeUnknown`; the durable dispatch claim permanently forbids a
  second flush.
- Cold reopen can read the immutable materialized cut without adopting the old
  server boot or authorizing a mutation.
- A stale placement epoch, different session/process boot, replaced physical
  export, missing/mismatched reverse binding, different shard/routing revision,
  or wrong expected head fails before 0x0D publication. The durable guarded
  process boot, both reverse bindings, physical export, immutable Genesis, and
  complete authority/session are re-read at the final write permit.
- The authority profile remains unsupported with ZeroFS HA because ordered
  standby application/readback for these authority records is not implemented.

## Evidence and explicit exclusions

The feature suite exercises exact manifest/cut publication, coordinator export
sequence inclusion, two successive heads, stale-epoch rejection, response-loss
readback, no-repeat behavior after an unknown post-flush outcome, clean cold
SlateDB reopen, process-boot replacement at the final permit, reverse-binding
loss, closed head/receipt/predecessor graphs, caller cancellation with guard
retention, full-record corruption/key-binding checks, and reserved-namespace
firewalls. Dedicated process-isolated failpoints cover both sides of 0x0D
publication. Clean close/reopen is not SIGKILL evidence.

This candidate does **not** expose `CreateExportBarrier`, verify a capability,
sign or verify COSE, emit protobuf, implement a production S3 credential path,
wire NBD FLUSH to the barrier operation, qualify RustFS/external S3, or authorize
Actor READY/release. The production constructors remain absent until ADR-0005's
registry and dual-language fixture gate covers the barrier command and receipt.
NBD FLUSH remains a separate fenced durability command without a Rhizome
barrier request identity.

The current closed-graph verifier walks the complete immutable barrier history
with remote-durable point reads. That is correct but O(history) and is not a
qualified long-term scale shape. Before enabling the feature in production,
replace it with an immutable verified-summary/checkpoint scheme that preserves
the same corruption and fork detection; do not weaken closure or impose a
product-visible barrier-count limit as a shortcut.

## Explicit real-S3 smoke entrypoint

The ignored unit test
`fs::workspace_barrier::tests::foundation_rustfs_clean_reopen_smoke` is the
only real-S3 entrypoint in this candidate. It requires a fresh empty prefix in
`RHIZOME_BARRIER_S3_PREFIX` under `rhizome/zerofs-barrier/`, a bucket in
`RHIZOME_BARRIER_S3_BUCKET`, and endpoint/region/credentials through the
object_store standard `AWS_*` environment. TLS trust remains process-scoped.

The test prefixes every SlateDB, segment, and Genesis object, refuses a nonempty
prefix, runs Genesis -> Activate -> Barrier -> signed-test-terminal -> clean
close/cold reopen/exact readback, emits only non-secret cut identities, deletes
only the objects visible through that exact prefix wrapper, and requires the
post-run listing to be empty. It is deliberately ignored in ordinary CI and
must be invoked only by an operator-controlled conformance run.

Even when it passes against RustFS, this test proves only a clean-close/cold-
reopen integration smoke for that exact endpoint and prefix. It contains no
SIGKILL, power-loss, response-loss, NBD, Firecracker, production capability, or
signed receipt evidence and must not be cited for those properties.

## Export-data and process-fault harness candidate

The ignored Linux-only
`fs::workspace_barrier::tests::foundation_rustfs_process_fault_matrix` advances
the next evidence gate without changing the production surface. It runs only
with an operator-created root-owned `0700` run directory whose basename is the
same canonical UUIDv4 used by the exact
`rhizome/zerofs-barrier-fault/<uuid>` S3 prefix. Partial or mismatched
configuration fails before an object-store mutation.

The harness uses production-coordinated SlateDB settings: WAL, periodic flush,
compactor, and garbage collector are disabled; automatic size flush thresholds
are moved to the coordinated maxima; the writer store is wrapped by the shared
`ManifestPublicationStore`; and ZeroFS's `FlushCoordinator` owns the only
seal-plus-manifest barrier.

A test-only one-shot hook runs only after the barrier's 0x0A effect-dispatch
claim is remote durable. It commits one real buffered export `Write` through the
typed `ExportMutationBuilder`, requires coordinator sequence 1, and then lets
the barrier continue. Thus earlier PENDING/claim flushes cannot make the
barrier's data cut a no-op. The resulting receipt must include write sequence 1,
and cold recovery verifies the exact payload from the segment store.

Each process-crash scenario has its own child process and S3 sub-prefix. A
root-only durable context plus an exact handshake binds run/scenario, child PID,
request digest, included sequence, and expected receipt digest. The parent
kills only after reading that handshake and must observe `SIGKILL`; a child
guard kills and joins on every parent failure path.

The closed scenarios are:

- `before-data-cut`: after the real buffered Write and complete admission, but
  before the sole barrier flush; read-only recovery requires the durable 0x0A
  claim, no 0x0D materialization, and an absent payload;
- `after-0x0d-apply`: after the atomic current/version/receipt batch applies
  locally but before its manifest flush; read-only recovery requires the claim,
  no 0x0D materialization, and the payload made durable by the earlier data cut;
- `manifest-applied-before-response`: a test-only object-store decorator is
  armed only after the 0x0D local apply, delegates the next exact manifest PUT
  to real S3, emits the handshake only after that PUT succeeds, and then blocks
  without returning to SlateDB until SIGKILL;
- `after-manifest-publish`: after the final flush returns but before caller
  readback/reply; recovery requires the exact materialization and payload.

Every recovery opens a SlateDB `DbReader`/read-only ZeroFS handle, performs only
remote-durable operation/head/receipt and extent reads, asserts the object-store
PUT count remains zero, and drops the reader. It never opens an RW writer,
calls `materialize`, retries a barrier, or invokes `close`/flush.

The parent bounds the retained S3 inventory to 512 objects and 64 MiB, deletes
only paths returned through its exact `PrefixStore`, and requires the final
prefix to be empty. Context, handshake, and recovery records are intentionally
retained in the operator run directory for later evidence hashing.

The ordinary unit suite separately verifies an applied manifest response error
against a real coordinated SlateDB stack and exact read-only recovery. That is
algorithm evidence only; the process harness's post-apply blocker is the
Foundation response-loss/SIGKILL boundary.

This harness remains **unexecuted** until its exact source commit passes both
storage/unknown-outcome and authority/fencing review. Even after a pass it is
not NBD FLUSH, Firecracker, production COSE/receipt, external-production-S3,
power-loss, HA, release, or Actor READY evidence.
