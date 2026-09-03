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
  Workspace, session, and the exact 32-byte operation ID. These high-frequency
  data-plane outcomes do not reuse the 0x0A control-operation ledger.
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

A sealed crate-private builder accepts the complete fence token and computes a
domain-separated SHA-256 command digest over its Workspace, export, authority,
session, boot, operation ID, mutation kind, canonical command, and data
checksum. It rejects transactions touching an inode other than the immutable
export device. The coordinator uses a dedicated
`ExportMutation` request rather than a side channel on ordinary transactions.
Same-operation/same-digest retries return the stored outcome without applying
data again. A same-operation conflicting digest durably fences the active
session. Outcomes remain addressable after later commands, and current versus
object-storage-durable lookup is explicit.

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

The remaining NBD adapter must create operation IDs from a connection
incarnation plus command ordinal/cookie, supply the exact canonical command and
WRITE payload to the builder, and route every real mutating handler through this
path. It must also protect the bound `.nbd` directory entry from replacement and
define typed outcome retention/GC. Until those pieces and strict capability
verification exist, the feature remains ineligible for an NBD or release
profile.

Profile enablement itself is durable authority. A boot write or flush with an
unknown outcome leaves the in-process profile disabled; authority and mutation
methods remain unavailable until an exact retry durably commits the current
boot identity.

## Verification

The feature-specific unit suite covers transition monotonicity, restart boot
invalidation, stale WRITE/FLUSH/TRIM/WRITE_ZEROES rejection, final-permit race
ordering, unknown commit outcomes and durable convergence, operation replay and
digest conflict, cross-key corruption, wrong-inode rejection, HA rejection
before ship, reserved-key rejection, and proptest-generated action traces.
CI runs Rust 1.98 formatting, clippy, feature unit tests, and the deterministic
DST transition model in addition to the unchanged default and failpoint gates.
