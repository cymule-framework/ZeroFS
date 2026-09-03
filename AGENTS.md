# ZeroFS fork contributor instructions

This branch adds a durable, protocol-neutral Workspace operation ledger. It is
a storage primitive, not an RPC implementation or an authority boundary.

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
