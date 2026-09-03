# Rhizome per-export authority core

This branch adds a protocol-neutral authority primitive under the non-default
`rhizome-export-authority-core` Cargo feature. It does not add a Rhizome RPC
server, protobuf descriptor, generated binding, capability verifier, receipt
signer, or public NBD integration.

## Persisted namespaces

- `meta + 0x0A` remains the existing Workspace operation ledger. Its typed
  ingress, request serialization, and durable outcome rules are unchanged.
- `meta + 0x0B + version + authority-subkind` stores one authority/session and
  immutable export-binding record per Workspace.
- `meta + 0x0B + version + mutation-subkind` stores immutable outcomes keyed by
  Workspace, Actor, Actor generation, placement epoch, session, server boot, and
  the exact 32-byte operation ID. These high-frequency data-plane outcomes do
  not reuse the 0x0A control-operation ledger.
- The reserved system boot subtype stores the current export-server boot
  identity. Restarting the writer advances this identity before the authority
  profile can serve, invalidating sessions from an earlier process.

The central transaction firewall rejects all three key classes from general
transactions. Only typed requests on the single `WriteCoordinator` may mutate
them.

## Authority and fencing

The internal domain model binds the Actor generation, home authority,
authority epoch, placement epoch, assignment revision, Workspace, exact NBD
export-name bytes and device inode, session, capability, expiry, node
incarnation, runtime, and export-server boot identity. Every transition
preserves the original export binding. The model deliberately contains no
protobuf wire representation or copied field numbers.

Activate, refresh, deactivate, advance-fence, and token-bearing data mutations
are serialized by the existing `WriteCoordinator`. A mutation is validated
again after acquiring the final database write permit. The current authority
record, coordinator-assigned session sequence, and immutable mutation outcome
are written in the same SlateDB batch as the data, so they share one point of no
return. Empty FLUSH operations still perform that atomic authority/outcome write
and, like FUA operations, require a durable flush.

A sealed crate-private builder accepts only the complete fence token, operation
ID, and a typed WRITE/TRIM/WRITE_ZEROES/FLUSH command. The authority store checks
durable replay before preparing the exact ExtentStore transaction and segment
deltas; callers cannot supply a parallel transaction, command byte string, or
payload checksum. Its domain-separated SHA-256 identity covers Workspace,
export, authority, session, boot, operation ID, typed mutation fields, and WRITE
data. The coordinator uses a dedicated
`ExportMutation` request rather than a side channel on ordinary transactions.
Same-operation/same-digest retries return the stored outcome without applying
or preparing data again. A same-operation conflicting digest enters a typed
coordinator fence that reads and durably closes the current matching session;
the request carries the exact observed outcome and attempted identity, and the
worker re-reads the immutable outcome at its final write permit before fencing.
It does not depend on a stale presenting authority version. Outcomes remain
addressable after later commands, and current versus
object-storage-durable lookup is explicit.

Every Workspace has one ordered admission reservation shared by authority
transitions, conflict fences, mutation preparation, and mutation commit. A new
mutation checks the current boot, complete authority/session binding, and
monotonic expiry while holding that reservation. Only then may ExtentStore stage
frames or trigger sealing/upload. The reservation travels with the queued
request through the final write boundary, where authority is checked again.
This prevents a durable fence from racing between admission and preparation and
prevents already-stale sessions from manufacturing segment/object-store work.

Stale authority returns `StaleMutation`; an error after the local point of no
return returns `CommitOutcomeUnknown`. Both outcomes require the presenting
session to close. Neither lease expiry nor SlateDB's unrelated writer epoch is
treated as a Rhizome fence receipt.

Authority lookup is an object-storage-durable readback, not a view of the live
SlateDB memtable. It rejects a record copied under a different Workspace key.
Commit-time validation separately uses the current state while holding the final
write permit.

HA mode remains fail-closed because ordered standby authority apply/readback is
not implemented. The feature must remain disabled in ordinary and release
profiles until strict capability verification and NBD session negotiation are
connected to every mutating command.

The remaining NBD adapter must extend immutable export identity with the `.nbd`
directory inode and advertised size, then revalidate directory inode, exact name,
device inode, and size at the final permit. That schema is intentionally not
guessed before the host-local listener owns the verified binding. The first
listener profile is one root-owned Unix socket per export; it must not expose
TCP, unauthenticated LIST, or `CAN_MULTI_CONN`. It must create operation IDs from
a connection incarnation plus command ordinal/cookie, construct the exact typed
command, and route every real mutating handler through this path. It must also
protect the bound `.nbd` directory entry from replacement and define typed
outcome retention/GC. Until those pieces and strict capability verification
exist, the feature remains ineligible for an NBD or release profile.

Profile enablement itself is durable authority. A boot write or flush with an
unknown outcome leaves the in-process profile disabled; authority and mutation
methods remain unavailable until an exact retry durably commits the current
boot identity.

The first authority transition after restart normalizes an old-boot active
session inside the coordinator's final write permit, advances reject-through,
and may atomically activate a strictly higher placement epoch. There is no
startup scan. Activation always resets the session sequence to zero; only the
coordinator increments it.

Block mutation lengths are bounded to the NBD `u32` command width. Admission
rejects any range whose mathematical final extent cannot be represented in
`u64`, before ExtentStore performs extent arithmetic.

## Verification

The feature-specific unit suite covers transition monotonicity, restart boot
invalidation, stale WRITE/FLUSH/TRIM/WRITE_ZEROES rejection, final-permit race
ordering, unknown commit outcomes and durable convergence, operation replay and
digest conflict, cross-key corruption, wrong-inode rejection, HA rejection
before ship, reserved-key rejection, and proptest-generated action traces.
CI runs Rust 1.98 formatting, clippy, feature unit tests, and the deterministic
DST transition model in addition to the unchanged default and failpoint gates.
