# Rhizome ZeroFS v2.3.2 Base Qualification

Date: 2026-09-02 (UTC)

## Verdict

The unmodified ZeroFS v2.3.2 source at
`b66813eeb75b5ee4add3ea47845a17507a37247c` passes the upstream Rust build,
lint, unit, deterministic-simulation, failpoint, and memory-backed 9P client
gates on the Foundation Linux host described below.

This is a **source-base qualification only**. It is suitable as the exact base
commit for Rhizome fork development. It is not a qualification of a Rhizome
workspace service, a release binary, or the terminal Firecracker-to-NBD-to-S3
data path.

In particular, this result provides no evidence yet for Rhizome Actor
generation or placement-epoch fencing, per-export lifecycle isolation,
external S3 semantics, checkpoint/clone/GC isolation, NBD durability, or
microVM recovery. Those remain blocking qualification gates after the fork is
modified.

## Source identity and provenance

- Fork: `cymule-framework/ZeroFS`
- Upstream: `Barre/ZeroFS`
- Exact source commit: `b66813eeb75b5ee4add3ea47845a17507a37247c`
- Upstream tag: `v2.3.2`, directly on the exact source commit
- Fork base branch: `rhizome-base-v2.3.2`, directly on the exact source commit
- Local qualification branch: `agent/base-qualification`
- Package workspace version: `2.3.2`
- License: GNU Affero General Public License v3.0 (`AGPL-3.0`)

At qualification time, fork `main` was
`4b260e6d66b2ddc9754919eacb01f1c1fd72238b`, two commits ahead of the selected
tag. Both fork `main` and `rhizome-base-v2.3.2` were unprotected. The base was
therefore selected by full commit identity, not by floating `main`.

The upstream exact commit had successful GitHub workflow runs for the Rust
suite, the broader `ci` workflow, CodeQL, coverage, MinIO Action testing, FFI,
Docker/CSI images, PGO release, and native-package publication. Scheduled DST
soaks recorded against the same exact commit also succeeded. These upstream
receipts are corroborating historical evidence only: they do not substitute
for the fork-local Foundation executions below.

## Toolchain and dependency pins

The repository has no `rust-toolchain` or `rust-toolchain.toml`. Its Rust CI
uses `dtolnay/rust-toolchain@stable`, so the compiler is floating rather than
reproducibly pinned.

The authoritative Foundation execution used:

- Ubuntu 24.04, Linux `6.18.49-rhizome`, x86_64
- `rustc 1.98.0 (88d9e12ae 2026-08-18)`
- `cargo 1.98.0 (797e8a9bc 2026-08-05)`

The crate uses Rust edition 2024. SlateDB is pinned consistently by
`Cargo.toml` and `Cargo.lock`:

- `slatedb 0.15.0`
- `slatedb-common 0.15.0`
- `slatedb-txn-obj 0.15.0`
- Git source `Barre/slatedb`
- Exact revision `20c14bbe9cb22405acc5b5067028c7b6d159baba`
- ZeroFS enables SlateDB's `wal_disable` and `foyer` features

A Rhizome-qualified fork release should add an explicit Rust toolchain pin.
Until then, future executions using “stable” may not reproduce this result.

## Foundation Linux execution matrix

All commands were run from `zerofs/` at the exact source commit. Wall-clock
durations include cold or partially cold compilation and are not benchmarks.

| Gate | Result | Evidence summary | Wall time |
| --- | --- | --- | ---: |
| `cargo fmt -- --check` | PASS | No formatting drift | 0.72 s |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS | Entire workspace and all targets warning-clean on Linux | 186.02 s |
| DST clippy with upstream `RUSTFLAGS` | PASS | `cargo clippy --test dst -- -D warnings` | 129.58 s |
| `cargo build --verbose` | PASS | Default debug build completed | 86.81 s |
| `cargo test --verbose` | PASS | Main library: 857 passed, 0 failed, 1 ignored; real-process failover integration target: 15 ignored; doctest: 1 passed | 112.19 s |
| DST with upstream `RUSTFLAGS` | PASS | 6 passed, including seeded model and same-seed digest checks | 134.49 s |
| `cargo test -p zerofs-client --all-features --verbose` | PASS | 1 unit test and 1 doctest passed | 8.65 s |
| Upstream quickstart E2E | PASS | Real ZeroFS process, memory object store, Unix 9P socket, client write/read/copy/list/statfs | about 3 s |
| `cargo test --features failpoints --test failpoints --verbose` | PASS | 61 passed, 0 failed | 54.41 s |
| DST `crash_points` with failpoints | PASS | 1 passed, 6 filtered; the crash-point test itself ran for 101.24 s | 146.64 s |

The 16 ignored tests in the general test command were not silently counted as
passes. Fifteen are real-process HA failover E2E cases that upstream marks as
ignored on shared runners and delegates to Jepsen coverage; the other ignored
library test is likewise not evidence produced by this execution.

## Cross-platform diagnostic execution

A secondary, non-authoritative execution was performed on macOS arm64 with
`rustc 1.97.1`. It was useful for separating platform behavior from Linux
base qualification:

- Formatting, build, DST (6/6), failpoints (61/61), DST crash points (1/1),
  client all-features/doctest, and the memory-backed 9P quickstart passed.
- Both clippy commands failed because the Linux-used
  `FileLockManager::session_has_locks` method is dead code on macOS under
  `-D warnings`.
- The general library test finished with 825 passed, 3 failed, and 1 ignored.
  The failures involved platform-specific open flags/protocol expectation and
  recursive directory removal errno behavior. The same tests passed in the
  Foundation Linux run.

These macOS failures are retained as cross-platform gaps; they were not
suppressed or reclassified as passing. They do not fail the Linux base verdict,
but the fork should decide explicitly whether macOS remains a supported
development target.

## Not executed in this qualification

The following upstream suites were not rerun locally and remain **SKIPPED**, not
passing evidence for the fork:

- The 15 ignored real-process HA failover tests
- Jepsen local-fs and Jepsen HA
- pjdfstest over NFS, 9P, and FUSE
- xfstests over NFS, 9P, and FUSE
- kernel-build-on-mounted-filesystem jobs
- stress-ng filesystem workloads
- ZFS-over-NBD workload
- CSI and Kubernetes E2E suites
- native kernel module build/load matrix
- fuzzing and the scheduled 50-minute DST soak
- external S3 or S3-compatible storage
- NBD client, FLUSH/FUA, reconnect, and `/dev/nbd*` qualification
- Firecracker/Jailer integration

Historical upstream workflow success at the exact commit is useful provenance,
but it does not turn these skipped fork-local runs into passes.

## Rhizome blockers and next gate

Before any Rhizome ZeroFS binary can be called runtime-qualified, the fork must:

1. Pin the Rust toolchain and maintain an exact dependency/source lock.
2. Add the versioned Rhizome control contract and immutable export identity.
3. Linearize Actor generation and placement epoch transitions with every
   mutating NBD boundary through the single write coordinator.
4. Emit exact-byte, durable, verifiable receipts and reject stale capabilities.
5. Provide per-export checkpoint, writable clone, deletion, and GC isolation.
6. Re-run this Rust matrix after each slice, then qualify external S3
   conditional writes and strong read-after-write semantics.
7. Qualify NBD FLUSH/FUA and failure recovery before connecting Firecracker.
8. Run the terminal Firecracker/Jailer -> Linux NBD -> ZeroFS fork -> external
   S3 path on Foundation, including crash, restart, stale-epoch, and unknown
   commit cases.

No workaround, mock success path, in-memory authority fallback, or Redis
conditional-write substitute is accepted for these gates.
