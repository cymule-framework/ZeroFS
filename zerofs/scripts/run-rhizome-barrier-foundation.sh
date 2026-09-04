#!/usr/bin/env bash
set -euo pipefail

# Execute exactly one already-built, reviewed Foundation barrier fault matrix.
# The caller creates the fresh run/evidence directories and starts this script
# in the exact transient systemd unit named below. Credentials are consumed
# only through the object_store standard AWS environment chain.

require_var() {
    local name=$1
    [[ -n ${!name:-} ]] || { echo "missing required variable: $name" >&2; exit 2; }
}

for name in \
    RHIZOME_BARRIER_FAULT_RUN_ID \
    RHIZOME_BARRIER_FAULT_RUN_ROOT \
    RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT \
    RHIZOME_BARRIER_S3_PREFIX \
    RHIZOME_BARRIER_S3_BUCKET \
    RHIZOME_BARRIER_SOURCE_ROOT \
    RHIZOME_BARRIER_TEST_EXECUTABLE \
    RHIZOME_BARRIER_BUILD_RECORD \
    RHIZOME_BARRIER_RUSTC \
    RHIZOME_BARRIER_CARGO \
    RHIZOME_BARRIER_BACKEND_UNIT \
    RHIZOME_BARRIER_BACKEND_BINARY \
    RHIZOME_BARRIER_BACKEND_UNIT_FILE \
    RHIZOME_BARRIER_BACKEND_CONFIG_REVISION \
    RHIZOME_BARRIER_CA_FILE \
    RHIZOME_BARRIER_TERMINAL_COLLECTOR \
    AWS_ACCESS_KEY_ID \
    AWS_SECRET_ACCESS_KEY \
    AWS_ENDPOINT \
    AWS_DEFAULT_REGION
do
    require_var "$name"
done

for name in \
    RHIZOME_BARRIER_BACKEND_CONFIG_REVISION \
    RHIZOME_BARRIER_BACKEND_UNIT \
    RHIZOME_BARRIER_S3_BUCKET \
    AWS_ENDPOINT \
    AWS_DEFAULT_REGION
do
    value=${!name}
    [[ $value != *$'\n'* && $value != *=* ]] || {
        echo "non-canonical value for: $name" >&2
        exit 2
    }
done

[[ $(id -u) == 0 ]] || { echo "runner must execute as root" >&2; exit 2; }
RUN_ID=$RHIZOME_BARRIER_FAULT_RUN_ID
python3 - "$RUN_ID" <<'PY'
import sys, uuid
value = uuid.UUID(sys.argv[1])
assert value.version == 4 and str(value) == sys.argv[1]
PY

EXPECTED_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/runs/$RUN_ID"
EXPECTED_PREFIX="rhizome/zerofs-barrier-fault/$RUN_ID"
EXPECTED_UNIT="zerofs-barrier-fault-$RUN_ID.service"
[[ $RHIZOME_BARRIER_FAULT_RUN_ROOT == "$EXPECTED_ROOT" ]]
[[ $RHIZOME_BARRIER_S3_PREFIX == "$EXPECTED_PREFIX" ]]
[[ $(stat -c '%a:%U:%G' "$EXPECTED_ROOT") == 700:root:root ]]
[[ $(find "$EXPECTED_ROOT" -mindepth 1 -maxdepth 1 | wc -l) == 0 ]]
[[ $(stat -c '%a:%U:%G' "$RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT") == 700:root:root ]]
[[ $(find "$RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT" -mindepth 1 -maxdepth 1 | wc -l) == 0 ]]

SELF=$(readlink -f "$0")
COLLECTOR=$(readlink -f "$RHIZOME_BARRIER_TERMINAL_COLLECTOR")
SOURCE=$(readlink -f "$RHIZOME_BARRIER_SOURCE_ROOT")
TEST_EXE=$(readlink -f "$RHIZOME_BARRIER_TEST_EXECUTABLE")
BUILD_RECORD=$(readlink -f "$RHIZOME_BARRIER_BUILD_RECORD")
RUSTC=$(readlink -f "$RHIZOME_BARRIER_RUSTC")
CARGO=$(readlink -f "$RHIZOME_BARRIER_CARGO")
BACKEND_BINARY=$(readlink -f "$RHIZOME_BARRIER_BACKEND_BINARY")
BACKEND_UNIT_FILE=$(readlink -f "$RHIZOME_BARRIER_BACKEND_UNIT_FILE")
CA_FILE=$(readlink -f "$RHIZOME_BARRIER_CA_FILE")
for path in "$SELF" "$COLLECTOR" "$TEST_EXE" "$BUILD_RECORD" "$RUSTC" "$CARGO" "$BACKEND_BINARY" "$BACKEND_UNIT_FILE" "$CA_FILE"; do
    [[ -f $path && ! -L $path ]]
done
[[ -d $SOURCE && ! -L $SOURCE ]]
[[ $(git -C "$SOURCE" status --porcelain=v1 | wc -l) == 0 ]]

CGROUP=$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)
[[ -n $CGROUP && $CGROUP == */"$EXPECTED_UNIT" ]]
export RHIZOME_BARRIER_FAULT_SUPERVISOR_UNIT=$EXPECTED_UNIT
export RHIZOME_BARRIER_FAULT_SUPERVISOR_CGROUP=$CGROUP

BACKEND_PID=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p MainPID --value)
[[ $BACKEND_PID =~ ^[1-9][0-9]*$ ]]
BACKEND_START=$(python3 - "$BACKEND_PID" <<'PY'
import sys
text=open(f'/proc/{sys.argv[1]}/stat').read()
print(text[text.rfind(')') + 2:].split()[19])
PY
)
BACKEND_CGROUP=$(awk -F: '$1 == "0" { print $3 }' "/proc/$BACKEND_PID/cgroup")
BACKEND_INVOCATION=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p InvocationID --value)
BACKEND_ACTIVE_MONOTONIC=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p ActiveEnterTimestampMonotonic --value)
LINUX_BOOT_ID=$(tr -d '\n' </proc/sys/kernel/random/boot_id)
SYSROOT=$($RUSTC --print sysroot)
[[ -d $SYSROOT && ! -L $SYSROOT ]]

EVIDENCE=$RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT
TOOLCHAIN_MANIFEST=$EVIDENCE/toolchain-tree.sha256
find "$SYSROOT" -xdev -type f -print0 | sort -z | xargs -0 sha256sum >"$TOOLCHAIN_MANIFEST"
chmod 0600 "$TOOLCHAIN_MANIFEST"

PREFLIGHT=$EVIDENCE/preflight.receipt
cat >"$PREFLIGHT.pending" <<EOF
schema=1
run_id=$RUN_ID
source_commit=$(git -C "$SOURCE" rev-parse HEAD)
source_tree=$(git -C "$SOURCE" rev-parse 'HEAD^{tree}')
source_clean=true
test_executable_sha256=$(sha256sum "$TEST_EXE" | cut -d' ' -f1)
build_record_sha256=$(sha256sum "$BUILD_RECORD" | cut -d' ' -f1)
rustc_version=$($RUSTC --version)
rustc_sha256=$(sha256sum "$RUSTC" | cut -d' ' -f1)
cargo_version=$($CARGO --version)
cargo_sha256=$(sha256sum "$CARGO" | cut -d' ' -f1)
toolchain_tree_sha256=$(sha256sum "$TOOLCHAIN_MANIFEST" | cut -d' ' -f1)
runner_sha256=$(sha256sum "$SELF" | cut -d' ' -f1)
terminal_collector_sha256=$(sha256sum "$COLLECTOR" | cut -d' ' -f1)
linux_boot_id=$LINUX_BOOT_ID
supervisor_unit=$EXPECTED_UNIT
supervisor_cgroup=$CGROUP
backend_unit=$RHIZOME_BARRIER_BACKEND_UNIT
backend_main_pid=$BACKEND_PID
backend_pid_start_time_ticks=$BACKEND_START
backend_linux_boot_id=$LINUX_BOOT_ID
backend_invocation_id=$BACKEND_INVOCATION
backend_cgroup=$BACKEND_CGROUP
backend_active_enter_monotonic=$BACKEND_ACTIVE_MONOTONIC
backend_binary_sha256=$(sha256sum "$BACKEND_BINARY" | cut -d' ' -f1)
backend_unit_file_sha256=$(sha256sum "$BACKEND_UNIT_FILE" | cut -d' ' -f1)
backend_config_revision=$RHIZOME_BARRIER_BACKEND_CONFIG_REVISION
endpoint_origin=$AWS_ENDPOINT
region=$AWS_DEFAULT_REGION
addressing=path
bucket=$RHIZOME_BARRIER_S3_BUCKET
prefix=$RHIZOME_BARRIER_S3_PREFIX
ca_sha256=$(sha256sum "$CA_FILE" | cut -d' ' -f1)
credential_values_recorded=false
started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
chmod 0600 "$PREFLIGHT.pending"
sync -f "$PREFLIGHT.pending"
ln "$PREFLIGHT.pending" "$PREFLIGHT"
sync -f "$EVIDENCE"
unlink "$PREFLIGHT.pending"
sync -f "$EVIDENCE"
export RHIZOME_BARRIER_FAULT_PREFLIGHT_RECEIPT_SHA256
RHIZOME_BARRIER_FAULT_PREFLIGHT_RECEIPT_SHA256=$(sha256sum "$PREFLIGHT" | cut -d' ' -f1)

set +e
"$TEST_EXE" --exact fs::workspace_barrier::tests::foundation_rustfs_process_fault_matrix --ignored --nocapture >"$EVIDENCE/test.log" 2>&1
TEST_EXIT=$?
set -e
printf '%s\n' "$TEST_EXIT" >"$EVIDENCE/exit-code"
BACKEND_PID_AFTER=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p MainPID --value)
BACKEND_INVOCATION_AFTER=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p InvocationID --value)
BACKEND_START_AFTER=$(python3 - "$BACKEND_PID_AFTER" <<'PY'
import sys
text=open(f'/proc/{sys.argv[1]}/stat').read()
print(text[text.rfind(')') + 2:].split()[19])
PY
)
if [[ $BACKEND_PID_AFTER != "$BACKEND_PID" || $BACKEND_START_AFTER != "$BACKEND_START" || $BACKEND_INVOCATION_AFTER != "$BACKEND_INVOCATION" ]]; then
    TEST_EXIT=125
    printf '%s\n' "$TEST_EXIT" >"$EVIDENCE/exit-code"
    printf 'backend process generation changed during run\n' >>"$EVIDENCE/test.log"
fi
if grep -R -F -q -- "$AWS_ACCESS_KEY_ID" "$EVIDENCE" "$EXPECTED_ROOT" || \
   grep -R -F -q -- "$AWS_SECRET_ACCESS_KEY" "$EVIDENCE" "$EXPECTED_ROOT"
then
    TEST_EXIT=126
    printf '%s\n' "$TEST_EXIT" >"$EVIDENCE/exit-code"
    printf 'credential material detected in run evidence\n' >>"$EVIDENCE/test.log"
fi
if [[ $TEST_EXIT == 0 ]]; then
    printf 'BEHAVIOR_PASS_AWAITING_TERMINAL_COLLECTION\n' >"$EVIDENCE/status"
else
    printf 'FAIL_PERMANENT_DO_NOT_REUSE\n' >"$EVIDENCE/status"
fi
find "$EXPECTED_ROOT" -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum >"$EVIDENCE/RUN-SHA256SUMS"
find "$EVIDENCE" -maxdepth 1 -type f ! -name SHA256SUMS ! -name status -print0 | sort -z | xargs -0 sha256sum >"$EVIDENCE/SHA256SUMS"
chmod 0600 "$EVIDENCE"/* "$EXPECTED_ROOT"/* 2>/dev/null || true
exit "$TEST_EXIT"
