# Rhizome Workspace genesis mechanics candidate

This branch adds a non-default, protocol-neutral Workspace genesis effect behind
`rhizome-workspace-genesis-core`. It does not expose an RPC, decode protobuf,
verify a capability, or sign a receipt. The production constructors for verified
commands and signed terminal bytes intentionally do not exist yet.

## One lifecycle authority

Genesis uses the existing `meta + 0x0A` Workspace operation ledger for PENDING
and immutable terminal outcomes. The new `meta + 0x0C` row is only the immutable
domain result: Workspace and Actor identity, Actor generation, canonical request
digest, SHA-256 root identity and object key, and exact physical export binding.
It is not a second operation state machine.

The execution boundary is split deliberately. `materialize` establishes or
replays the PENDING operation, converges the content-addressed object, and
publishes physical/durable state. `complete` accepts exact signed terminal bytes
from a sealed verifier/signer boundary and completes the same 0x0A operation.
Only test code can currently construct those seals.

## Object and physical commit

The immutable root object is written at
`rhizome/workspace-genesis/sha256/<lowercase digest>` with native conditional
Create. Success, AlreadyExists, and an ambiguous Create response all converge by
one exact-key GET whose length, SHA-256, and bytes must match. A failed readback
is UNKNOWN; no mutation retry or overwrite is authorized.

After object convergence, the sole `WriteCoordinator` acquires the database
write permit and either replays an exact existing genesis graph or atomically
publishes all of:

- the sparse regular-file inode under the pre-existing `.nbd` directory;
- its directory entry, scan entry, cookie, parent update, inode watermark, and
  stats update;
- the explicit-codec 0x0C immutable genesis row;
- the 0x0B reverse-name and reverse-inode bindings.

The batch is flushed before returning. The receipt's SlateDB writer epoch and
durable sequence are read from one post-flush `DbStatus` snapshot. A write,
flush, or reply failure after the point of no return is UNKNOWN and converges
through durable 0x0C plus physical/reverse-graph readback.

## Activation boundary

When this profile is built for production, `ActivateExport` requires a durable
genesis row whose Workspace, Actor, Actor generation, and complete export
identity match. Activation also re-reads the physical `.nbd` graph even when the
reverse bindings were preinstalled by genesis. The normal export-authority test
profile keeps this additional gate disabled unless a test explicitly enables it,
so the independent authority-core suite remains scoped to its own primitive.

HA genesis remains fail-closed. This candidate does not qualify a release, NBD
listener, S3 provider, checkpoint, clone, GC, signed receipt, runtime, route, or
Actor READY transition.
