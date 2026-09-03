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
  authority, session, boot, operation ID, kind, canonical command, and data
  checksum.
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
- Keep this branch protocol-neutral. Do not add protobuf descriptors, generated
  bindings, copied protobuf field numbers, or a Rhizome transport workflow to
  this repository as part of the authority core.
- Read `RHIZOME_EXPORT_AUTHORITY.md` before changing the reserved namespace,
  transition model, commit-time fence validation, or feature boundary.
