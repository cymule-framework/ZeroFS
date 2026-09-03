# Rhizome Workspace genesis mechanics candidate

This branch adds a non-default, protocol-neutral Workspace genesis effect behind
`rhizome-workspace-genesis-core`. It does not expose an RPC, decode protobuf,
verify a capability, or sign a receipt. The production constructors for verified
commands and signed terminal bytes intentionally do not exist yet.

The canonical command and physical materialization plan are distinct types.
`virtual_size_bytes` is part of the command. Export name and initial root
bytes/digest are plan outputs that must eventually be derived from the exact
immutable template, root-policy, and spec inputs. Only tests can currently seal
such a plan; production cannot pass caller-selected root/export data.

## One lifecycle authority

Genesis uses the existing `meta + 0x0A` Workspace operation ledger for PENDING
effect-dispatch claim, and immutable terminal outcomes. The claim includes a
fresh installer UUID and authorizes one external Create attempt; only the exact
installing call may dispatch, including after its own ambiguous claim reply is
resolved by exact durable readback. The new
`meta + 0x0C` row is only the immutable
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
Create through a dedicated single-dispatch adapter. The generic ZeroFS object
store is deliberately not reused because its retry layers may repeat PUT.
Success, AlreadyExists, and an ambiguous Create response all converge by
one exact-key GET whose length, SHA-256, and bytes must match. A failed readback
is UNKNOWN; every later invocation and cold reopen performs GET only, never a
second mutation. The production adapter remains unavailable until its exact
non-retry configuration and wire-count conformance are qualified.

If that unique installer process disappears after the claim commits but before
dispatch, the operation remains fail-closed at EffectDispatched. A later process
cannot distinguish the crash window safely and therefore performs GET only. A
future supervised installer-incarnation receipt is required to recover this
liveness case without weakening the one-mutation invariant.

Deterministic exact-object and pre-write physical conflicts return a typed
rejection proof. A separately sealed negative terminal can complete the same
claimed 0x0A operation as FAILED only through the coordinator, which atomically
rechecks the exact claim and refuses the negative if the matching 0x0C effect
exists. UNKNOWN outcomes remain EffectDispatched; this path never fabricates a
NOT_COMMITTED absence proof.

After object convergence, the sole `WriteCoordinator` acquires the database
write permit and either replays an exact existing genesis graph or atomically
publishes all of:

- the sparse regular-file inode under the pre-existing `.nbd` directory;
- its directory entry, scan entry, cookie, parent update, inode watermark, and
  stats update;
- the explicit-codec 0x0C immutable genesis row;
- the 0x0B reverse-name and reverse-inode bindings.

The batch is flushed before returning. The pre-terminal materialization
receipt's SlateDB writer epoch and durable sequence are a coherent durable
readback cut read from one post-flush `DbStatus` snapshot. Replaying an
unterminated effect after reopen may return a newer cut; it does not pretend the
new writer performed the original commit. Once exact signed terminal bytes are
stored in 0x0A, those bytes are immutable and no new receipt is produced. A write,
flush, or reply failure after the point of no return is UNKNOWN and converges
through durable 0x0C plus physical/reverse-graph readback.

## Activation boundary

When this profile is built for production, `ActivateExport` requires a durable
0x0A SUCCEEDED operation and a genesis row whose complete operation, authority
creation baseline, Workspace, tenant, Actor, Actor generation, immutable spec,
lineage, storage selection, root, and export identity match. Activation also
re-reads the physical `.nbd` graph even when the
reverse bindings were preinstalled by genesis. The normal export-authority test
profile keeps this additional gate disabled unless a test explicitly enables it,
so the independent authority-core suite remains scoped to its own primitive.

HA genesis remains fail-closed. This candidate does not qualify a release, NBD
listener, S3 provider, checkpoint, clone, GC, signed receipt, runtime, route, or
Actor READY transition.

The physical receipt currently exposes the root/export binding and coherent
SlateDB writer/durable cut. It does not yet construct the normative signed
`WorkspaceHead`, manifest ID, or commit-time payload. Those remain part of the
unreachable production signer integration, not values this mechanics candidate
may synthesize or claim as conformance evidence.
