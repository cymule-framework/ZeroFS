# ZeroFS fork contributor instructions

This branch adds durable, protocol-neutral Workspace operation and per-export
authority primitives. They are storage primitives, not RPC implementations.

- Keep ledger values opaque. Protocol decoding, authorization, signing, and
  effect execution belong outside this module.
- Keep all ledger mutations on the sole `WriteCoordinator` path. Do not add a
  second writer, direct SlateDB writes, or an in-memory fallback.
- The sequencing guard must remain owned by the queued coordinator request
  until durable completion. Caller cancellation must not release terminal
  serialization early.
- A failure after local apply is `CommitOutcomeUnknown` and requires durable
  readback. A missing record is `Unknown`, never proof that no mutation ran.
- Terminal bytes are immutable and replay byte-for-byte.
- `meta + 0x0A` is a reserved mutation namespace. General `Transaction` writes,
  deletes, weak-coordinator commits, and direct `Db` puts must reject it before
  mutation. Only the module-private typed Workspace-ledger request may enter the
  coordinator's ledger variant; extend the central reserved-prefix registry when
  another authority-owned namespace is added.
- Keep public transaction construction compatible with upstream callers. Raw
  `Db` batch/put application is crate-internal because it bypasses the public
  coordinator ingress firewall.
- Run failpoint cases through `test_helpers::isolated_failpoint`; the failpoint
  registry is process-global and cannot be isolated with test ordering or a
  mutex. Every armed failpoint needs a Drop guard.

The repository remains licensed under AGPL-3.0. Keep `LICENSE` and upstream
attribution intact.

- `fs::export_authority` is the crate-private per-export Rhizome authority
  primitive. Bare inputs are accepted only after a future strict capability
  verifier; do not expose this module as a public library or network API.
- Export authority transitions and fenced mutations share the one
  `WriteCoordinator` queue. Validate the complete Actor generation, home,
  authority, placement, assignment, session, capability, expiry, node, and
  runtime binding at the final commit boundary. SlateDB `writer_epoch` is not a
  Rhizome placement epoch.
- The export name and device inode are immutable authority state. Only the
  sealed export-mutation builder may admit a data transaction, and it must
  reject every inode/extent key outside that device before enqueueing.
- Each export mutation has a 32-byte operation ID, domain-separated command and
  data digests, a coordinator-assigned sequence, and an immutable 0x0B outcome
  committed atomically with data. Replay the exact outcome before checking live
  authority; conflicting reuse durably fences the active session. Never use the
  process-local DedupCache as mutation authority.
- The sealed mutation owns its complete fence token; callers cannot attach a
  different token at commit time. Command identity covers Workspace, export,
  authority, session, boot, operation ID, typed command fields, and WRITE data.
- Production mutation construction accepts only typed block commands. Durable
  replay is checked before ExtentStore transaction preparation; never add a
  caller-supplied Transaction, command byte string, or parallel checksum.
- Authority transitions and mutation preparation share one per-Workspace
  admission reservation. Validate the current boot, full token, and monotonic
  expiry before ExtentStore staging, carry the reservation through the queued
  commit, and still revalidate at the final write permit. A stale session must
  not append frames, trigger sealing, or upload objects.
- Mutation outcome identity includes Actor, generation, placement epoch,
  session, and server boot as well as Workspace and operation ID. A conflict
  fence must match the current boot session plus Actor generation and placement;
  an old-boot outcome can never fence a replacement session.
- Typed block commands use `u32` lengths and reject a range whose final complete
  extent would overflow `u64` before calling ExtentStore.
- On writer restart, normalize the old boot session only inside the queued
  authority transition and allow only a strictly higher placement epoch. Do not
  add a startup export scan. Activation resets sequence to zero; sequence is
  coordinator-owned.
- Operation-ID digest conflict uses the typed coordinator conflict fence. It
  must carry the exact committed outcome plus attempted command identity,
  re-read that outcome at the final write permit, prove same operation and
  different digest, then durably close the current matching session. It must
  never treat an unproven authority Conflict as successful fencing.
- Stale-cost tests use synchronous preparation counters as the primary witness;
  compressed payload size and an unjoined background PUT are not proof that
  ExtentStore preparation was skipped.
- Enabling the Rhizome authority profile requires a process-lifetime Linux
  shard guard acquired before the durable boot write. The guard opens the exact
  SHA-256-derived shard lock with rustix `openat` from a configured absolute
  root-controlled directory and verifies directory/lock uid, gid, exact mode,
  device, inode, regular-file type, and `nlink == 1` before taking the exclusive
  file lock. The root supervisor must create `root:zerofs 0750` directory and a
  `zerofs:zerofs 0600` immutable lock inode, then kill and join the prior process
  before replacement. The dedicated worker UID must be non-root and equal the
  process effective UID; the configured GID must be effective or supplementary.
  Install is synchronous and one-shot before any boot-initialization await, and
  the Store retains the guard across cancellation or unknown boot commit so the
  same Store can converge by retry. Do not accept an arbitrary caller file as a
  shard guard.
- This guard is host-local. Cross-host automatic writer takeover remains
  unsupported and must fail closed without an external STONITH/Node fence
  receipt.
- An export identity is the exact `.nbd` directory inode, entry name, device
  inode, and advertised size. Its first successful activation validates the
  single-link directory mapping and atomically installs immutable key-bound
  reverse-name and reverse-inode rows with the forward authority record. Later
  refresh, deactivate, and fence transitions retain both reverse rows; never
  scan for or delete them outside a future typed retirement/GC protocol.
- Export schema v2 enablement must fail with `MigrationRequired` when the narrow
  reserved v1 prefix contains any forward or outcome row. Do not silently treat
  v1 data as absent or rebuild missing reverse rows for an initialized record.
  Physical checks at activation and the final mutation permit read and strictly
  decode current DB inode/directory rows rather than trusting metadata caches.
- The coordinator derives inode/directory candidates from every ordinary
  transaction and, under the final write permit, rejects changes to any retained
  reverse-bound file, `.nbd` directory, exact entry, or root `.nbd` mapping.
  Keep the host-local `.nbd` ingress supervisor-owned as an additional adapter
  release gate; do not rely on metadata caches for this protection.
- If a retained authority shard is opened with a replicator, ordinary bound
  mutations must be rejected before replication ship and rechecked under the
  final local write permit. The authority profile itself remains unsupported in
  HA mode; never ship first and discover a binding violation only at local apply.
- Raw-write fencing uses a conservative, rebuildable in-memory deny index. Its
  first use scans and strictly decodes all v2 forward and both reverse prefixes;
  malformed keys/envelopes or scan errors poison the index and fail closed.
  Decodable partial or mismatched graphs are conservatively unioned so every
  represented physical identity remains denied while unrelated writes continue.
  The single coordinator inserts newly committed bindings, and uncertain writes
  invalidate the index. Final admission is bounded per candidate; never restore
  per-write full scans.
- Raw `Db` mutation methods are crate-private, and every public `Transaction`
  commit rejects the export-authority prefix and process-boot key. Only typed
  coordinator requests may mutate those reserved keys; do not reopen a direct
  database escape hatch.
- A reopened writer must durably advance the one process-boot identity before
  serving; sessions bound to an older boot are thereby invalid without an
  unbounded per-export startup scan. Stale WRITE, FLUSH, TRIM, and
  WRITE_ZEROES attempts return the typed close-session outcome; an empty FLUSH
  is still gated. `CommitOutcomeUnknown` also closes the presenting session.
- Export authority replication is deliberately fail-closed while the HA
  standby apply/readback protocol is absent. Never ship a fenced mutation before
  its authority check or replicate authority through an unordered side path.
- The Rhizome export-authority profile is explicitly enabled after ordinary
  ZeroFS construction. Never initialize its boot identity unconditionally:
  default and HA ZeroFS profiles must remain unaffected. Enabling the profile
  on HA fails closed until ordered authority replication exists.
- The staged core is behind the non-default
  `rhizome-export-authority-core` Cargo feature. It is a conformance/development
  boundary, not a release feature: do not enable it in a release profile until
  strict capability verification and NBD session negotiation are wired. Its
  dedicated feature test, clippy, and deterministic pure-model gates must stay
  green.
- This slice is not wired to the public NBD server. Do not claim NBD fencing
  conformance until negotiation installs verified session state and every real
  WRITE/FUA/FLUSH/TRIM/WRITE_ZEROES handler uses the token-bearing commit path.
- The first Rhizome NBD profile is one host-local root-owned Unix socket per
  export. Do not expose TCP, unauthenticated LIST, or `CAN_MULTI_CONN`; reuse the
  upstream NBD and nbd-proto mechanics behind the verified session adapter.
- Keep this branch protocol-neutral. Do not add protobuf descriptors, generated
  bindings, copied protobuf field numbers, or a Rhizome transport workflow to
  this repository as part of the authority core.
- Read `RHIZOME_EXPORT_AUTHORITY.md` before changing the reserved namespace,
  transition model, commit-time fence validation, or feature boundary.

- `fs::workspace_genesis` is the non-default `rhizome-workspace-genesis-core`
  mechanics candidate. It reuses the sole 0x0A Workspace operation ledger;
  0x0C stores only the immutable genesis domain record and is not another
  lifecycle state machine.
- Genesis root objects are SHA-256 addressed and installed with native
  conditional Create followed by exact-key byte/digest readback. Never replace
  this with HEAD-before-PUT, overwrite, retrying an unknown mutation, or Redis
  authority.
- The generic ZeroFS object-store stack is not a genesis mutation executor: it
  may contain automatic or unbounded PUT retries. Genesis uses a dedicated
  single-dispatch adapter. The production adapter is intentionally unavailable
  in this candidate; only tests have a direct non-retrying implementation.
- Before the one Create attempt, atomically advance the same 0x0A operation from
  PENDING to its immutable effect-dispatch claim. Only the call that installs
  that claim may send Create. Every replay, including cold reopen after unknown
  Create/readback, may perform exact-key GET only. Generic terminal completion
  is rejected after a claim; only the typed genesis completion path may finish
  it after exact receipt and durable graph verification.
- The coordinator atomically publishes the sparse `.nbd` file, immutable 0x0C
  record, and both 0x0B reverse bindings, then flushes and reads writer epoch
  plus durable sequence from one `DbStatus` snapshot. Activation under this
  profile requires the exact genesis/export/Actor-generation binding.
- Keep the production capability-verifier and receipt-signer constructors
  unreachable until Rhizome's normative CDDL and official fixtures exist.
  Tests may use only the sealed test constructors. Genesis records use the
  explicit closed codec; do not serialize them with bincode or protobuf.
- The 0x0C row binds the complete operation key, authority creation baseline,
  tenant, immutable template/root-policy refs, source CreateActor digest,
  object lineage, storage shard/routing revision, root identity, and exact
  export identity. Validate the configured local shard before lookup or effect.
  Activation requires the same home/authority baseline and a durable 0x0A
  SUCCEEDED outcome; PENDING or effect-dispatched is not genesis success.
