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

The remaining NBD adapter must install the already-defined immutable export
identity and revalidate the root-owned `.nbd` ingress before opening a session.
The core schema already binds the canonical `.nbd` directory inode, exact name,
device inode, and advertised size, and revalidates raw current database rows at
the final permit. The coordinator also rejects any ordinary transaction that
would mutate a retained reverse-bound inode, directory entry, `.nbd` directory,
or root `.nbd` mapping. On a shard opened with a replicator this check runs
before ship and again under the final local write permit; this does not enable
the still-unsupported HA authority profile. The first
listener profile is one root-owned Unix socket per export; it must not expose
TCP, unauthenticated LIST, or `CAN_MULTI_CONN`. It must create operation IDs from
a connection incarnation plus command ordinal/cookie, construct the exact typed
command, and route every real mutating handler through this path. It must also
protect the bound `.nbd` directory entry from replacement and define typed
outcome retention/GC. Until those pieces and strict capability verification
exist, the feature remains ineligible for an NBD or release profile.

Ordinary-write protection uses a conservative derived deny index owned by the
single coordinator. Its first use scans and strictly decodes the complete v2
forward, reverse-name, and reverse-inode prefixes; corrupt initialization blocks
all writes. Malformed rows and scan errors poison the index; decodable partial
or mismatched graphs are conservatively unioned to protect every represented
physical identity without blocking unrelated data. Successful first activation inserts the binding, while an uncertain
authority apply invalidates the index for reconstruction. Steady-state final
checks are constant-time per transaction candidate rather than Actor-count scans.

Profile enablement itself is durable authority. A boot write or flush with an
unknown outcome leaves the in-process profile disabled; authority and mutation
methods remain unavailable until an exact retry durably commits the current
boot identity.

The first authority transition after restart normalizes an old-boot active
session inside the coordinator's final write permit, advances reject-through,
and may atomically activate a strictly higher placement epoch. There is no
startup scan. Activation always resets the session sequence to zero; only the
coordinator increments it.

## NBD session contract boundary

The staged session core mirrors the authoritative data in Rhizome's unreleased
`InstallNBDSession` and `GetNBDConnection` protobuf candidate without importing
protobuf descriptors or field numbers into ZeroFS. The mapping is closed:

| Rhizome contract data | ZeroFS domain data |
| --- | --- |
| request ID and canonical request digest | `request_id`, `VerifiedNbdInstallDigest` |
| Workspace, session, complete AuthorityVersion, installed capability, expiry | `MutationFenceToken` |
| Node-allocated connection ID | `expected_connection_id` / `connection_id` plus one shard-global immutable reservation |
| connector boot, PID/start, peer UID/GID, Node and runtime | `NbdConnectorIdentity` |
| bind target and captured listener identity | `NbdSocketTarget`, `NbdSocketIdentity` |
| exact export and closed NBD profile | `NbdExportIdentity`, `NbdProtocolProfile` |
| guarded writer boot, shard and routing revision | `NbdServerBootIdentity`, `storage_routing_revision` |
| activation receipt digest and commit times | exact digest and millisecond timestamps |
| successful GO flags and connection ordinal | `NbdConnectionExpectation`, `NbdConnectionReceipt` |

Signed capabilities, protobuf parsing, UUID string normalization, request-digest
construction, and receipt signing deliberately stay outside this crate. The
only Install constructor remains test-only until the normative CDDL registry
and exact fixtures can supply a strictly verified domain value. In particular,
the internal bincode storage format is never hashed as a command identity and
cannot substitute for the missing CDDL preimage.

Install first commits `Pending`; only then may the supervisor atomically bind
and capture the socket identity. Completion revalidates the current guarded
server boot, full Actor/session authority, both reverse bindings, and the exact
physical export mapping under the final write permit. The first accepted FD is
then durably claimed before any NBD handshake or option byte is processed. The
adapter must stop accepting before dispatching that claim and retain the same
open file description plus its in-memory lifecycle owner through unknown-result
readback. An exact durable claim may continue on that FD without another write.
An absent/conflicting claim, lost FD, or restarted process requires fence and
cold rebuild; the durable tuple never authorizes stream reconstruction.

All related durable rows are read from one SlateDB remote-durable snapshot
while holding the same per-Workspace admission reservation. Install outcome and
record plus the connection-ID reservation must all exist at one sequence. The
Pending Install creates the reservation atomically, and any later session or
Workspace attempting to reuse that UUID conflicts. A successful connection additionally
requires the exact receipt and consumed Install at that sequence. Partial graphs
are corruption, including after reopen; independent point reads are not a valid
receipt.

This slice retains Install, claim/burn, and connection rows indefinitely. It
has no delete, tombstone, retirement, or GC command, so it makes no bounded
retention claim. A future typed retirement protocol must preserve unknown-result
readback and retained reverse-binding safety before any row can be collected.

Before the authority profile can initialize its durable boot identity, the
supervisor must supply a process-lifetime guard for the exact configured shard.
On Linux the guard resolves a SHA-256-derived lock name with rustix `openat`
from an absolute root-controlled directory, verifies the configured directory
and lock device/inode plus ownership, exact modes, regular-file type and single
link, then takes an exclusive file lock. The worker is a dedicated non-root UID
whose effective UID must match configuration; its configured GID must be an
effective or supplementary group. Guard installation is synchronous and
one-shot before boot initialization, and retains the guard across cancellation
or an unknown boot write so retry converges within the same Store. A replacement
process may proceed only after the supervisor
kills and joins the previous process and obtains the same inode lock. This is a
same-host boundary; cross-host takeover remains fail-closed until external
STONITH/Node fencing exists.

The immutable export identity binds the `.nbd` directory inode, exact entry
name, device inode, and advertised size. First activation validates the
single-link file and exact directory entry, then commits the forward authority
record plus key-bound reverse-name and reverse-inode rows in one coordinator
batch. Refresh, deactivate, and fence retain these rows. Retirement and garbage
collection are intentionally outside this core slice.

With `rhizome-workspace-genesis-core`, genesis creates that physical graph and
the two reverse rows before activation. The 0x0C genesis row is a separate
immutable domain record, while NBD Install/outcome/connection/reservation remain
0x0B version-2 subtypes 5 through 8. Both genesis admission and NBD admission
read the storage shard installed from the same retained process guard. A
combined test covers genesis terminal completion, gated activation, NBD Install
completion, and first-FD claim without inventing a second shard or lifecycle
authority.

Export key and envelope version 2 are an explicit pre-release schema boundary.
Profile enablement scans the narrow reserved version-1 prefix and fails with
`MigrationRequired` if any legacy forward or mutation-outcome row exists. It
never treats old state as an empty database or performs an implicit reset.
Deployments must use a fresh shard or a future typed one-shot migration.

Implementation checkpoint `19fd69e` contains both the raw extent-key fencing
candidate and the schema-gate ordering/readback tests, despite its narrower Git
subject. Review and qualification must therefore use its full diff, not infer
scope from the subject line.

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
