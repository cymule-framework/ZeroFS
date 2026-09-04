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
    RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT
do
    require_var "$name"
done

[[ $(id -u) == 0 ]] || { echo "runner must execute as root" >&2; exit 2; }
RUN_ID=$RHIZOME_BARRIER_FAULT_RUN_ID
python3 - "$RUN_ID" <<'PY'
import sys, uuid
value = uuid.UUID(sys.argv[1])
assert value.version == 4 and str(value) == sys.argv[1]
PY

EXPECTED_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/runs/$RUN_ID"
EXPECTED_EVIDENCE="/opt/rhizome/validation/zerofs-barrier-fault/evidence/$RUN_ID"
EXPECTED_UNIT="zerofs-barrier-fault-$RUN_ID.service"
[[ $RHIZOME_BARRIER_FAULT_RUN_ROOT == "$EXPECTED_ROOT" ]]
[[ $RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT == "$EXPECTED_EVIDENCE" ]]
[[ $(stat -c '%a:%U:%G' "$EXPECTED_ROOT") == 700:root:root ]]
[[ $(stat -c '%a:%U:%G' "$EXPECTED_EVIDENCE") == 700:root:root ]]
python3 - "$EXPECTED_ROOT" "$EXPECTED_EVIDENCE" <<'PY'
import os,stat,sys
for path in sys.argv[1:]:
    assert os.path.isabs(path) and os.path.realpath(path)==path
    current='/'
    for part in (part for part in path.split('/') if part):
        current=os.path.join(current,part); info=os.lstat(current)
        assert info.st_uid==0 and info.st_gid==0 and info.st_mode & 0o022 == 0
        assert not stat.S_ISLNK(info.st_mode)
    assert stat.S_ISDIR(os.lstat(path).st_mode)
PY
exec {RUN_OWNER_FD}<"$EXPECTED_EVIDENCE"
flock -n "$RUN_OWNER_FD"
RUN_OWNER_FD_PATH="/proc/self/fd/$RUN_OWNER_FD"
EVIDENCE_ROOT_DEVICE_INODE=$(stat -Lc '%d:%i' "$RUN_OWNER_FD_PATH")
[[ $(stat -Lc '%d:%i' "$EXPECTED_EVIDENCE") == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
[[ $(find "$EXPECTED_ROOT" -mindepth 1 -maxdepth 1 | wc -l) == 0 ]]
[[ $(find "$EXPECTED_EVIDENCE" -mindepth 1 -maxdepth 1 | wc -l) == 0 ]]

SELF_START=$(python3 - $$ <<'PY'
import sys
text=open(f'/proc/{sys.argv[1]}/stat').read()
print(text[text.rfind(')') + 2:].split()[19])
PY
)
ATTEMPT_BOOT_ID=$(tr -d '\n' </proc/sys/kernel/random/boot_id)
ATTEMPT="$EXPECTED_EVIDENCE/attempt.receipt"
ATTEMPTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$ATTEMPT.pending" "$RUN_ID" "$$" "$SELF_START" "$ATTEMPT_BOOT_ID" "$EXPECTED_UNIT" "$EVIDENCE_ROOT_DEVICE_INODE" "$ATTEMPTED_AT" <<'PY'
import os,sys
path,run,pid,start,boot,unit,evidence,when=sys.argv[1:]
data=f'schema=1\nrun_id={run}\nrunner_pid={pid}\nrunner_pid_start_time_ticks={start}\nlinux_boot_id={boot}\nsupervisor_unit={unit}\nevidence_root_device_inode={evidence}\nattempted_at_utc={when}\n'.encode()
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    view=memoryview(data)
    while view:
        written=os.write(fd,view)
        assert written>0
        view=view[written:]
    os.fsync(fd)
finally:
    os.close(fd)
PY
ln "$ATTEMPT.pending" "$ATTEMPT"
sync -f "$EXPECTED_EVIDENCE"
unlink "$ATTEMPT.pending"
sync -f "$EXPECTED_EVIDENCE"

SELF=$(readlink -f "$0")
[[ -f $SELF && ! -L $SELF ]]
SUPERVISOR_CGROUP=$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)
SUPERVISOR_INVOCATION=$(systemctl show "$EXPECTED_UNIT" -p InvocationID --value)
SUPERVISOR_CONTROL_GROUP=$(systemctl show "$EXPECTED_UNIT" -p ControlGroup --value)
SUPERVISOR_MAIN_PID=$(systemctl show "$EXPECTED_UNIT" -p MainPID --value)
[[ $SUPERVISOR_CGROUP == */"$EXPECTED_UNIT" ]]
[[ $SUPERVISOR_CONTROL_GROUP == "$SUPERVISOR_CGROUP" ]]
[[ $SUPERVISOR_MAIN_PID == "$$" ]]
[[ $SUPERVISOR_INVOCATION =~ ^[0-9a-f]{32}$ ]]

for name in \
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
    AWS_DEFAULT_REGION \
    SSL_CERT_FILE
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
python3 - "$AWS_ENDPOINT" <<'PY'
import sys, urllib.parse
value=sys.argv[1]
url=urllib.parse.urlsplit(value)
assert url.scheme == 'https' and url.hostname == '127.0.0.1' and url.port == 19000
assert url.username is None and url.password is None
assert url.path in ('', '/') and not url.query and not url.fragment
assert value == 'https://127.0.0.1:19000'
PY

EXPECTED_PREFIX="rhizome/zerofs-barrier-fault/$RUN_ID"
[[ $RHIZOME_BARRIER_S3_PREFIX == "$EXPECTED_PREFIX" ]]

COLLECTOR=$(readlink -f "$RHIZOME_BARRIER_TERMINAL_COLLECTOR")
SOURCE=$(readlink -f "$RHIZOME_BARRIER_SOURCE_ROOT")
TEST_EXE=$(readlink -f "$RHIZOME_BARRIER_TEST_EXECUTABLE")
BUILD_RECORD=$(readlink -f "$RHIZOME_BARRIER_BUILD_RECORD")
RUSTC=$(readlink -f "$RHIZOME_BARRIER_RUSTC")
CARGO=$(readlink -f "$RHIZOME_BARRIER_CARGO")
BACKEND_BINARY=$(readlink -f "$RHIZOME_BARRIER_BACKEND_BINARY")
BACKEND_UNIT_FILE=$(readlink -f "$RHIZOME_BARRIER_BACKEND_UNIT_FILE")
CA_FILE=$(readlink -f "$RHIZOME_BARRIER_CA_FILE")
[[ $(readlink -f "$SSL_CERT_FILE") == "$CA_FILE" ]]
for path in "$COLLECTOR" "$TEST_EXE" "$BUILD_RECORD" "$RUSTC" "$CARGO" "$BACKEND_BINARY" "$BACKEND_UNIT_FILE" "$CA_FILE"; do
    [[ -f $path && ! -L $path ]]
done
[[ -d $SOURCE && ! -L $SOURCE ]]
python3 - "$EXPECTED_ROOT" "$EXPECTED_EVIDENCE" "$SELF" "$COLLECTOR" "$TEST_EXE" "$BUILD_RECORD" "$RUSTC" "$CARGO" "$BACKEND_BINARY" "$BACKEND_UNIT_FILE" "$CA_FILE" "$SOURCE" <<'PY'
import os, stat, sys
for raw in sys.argv[1:]:
    assert os.path.isabs(raw) and os.path.realpath(raw) == raw
    current = '/'
    parts = [part for part in raw.split('/') if part]
    for i, part in enumerate(parts):
        current = os.path.join(current, part)
        info = os.lstat(current)
        assert info.st_uid == 0 and info.st_gid == 0
        assert info.st_mode & 0o022 == 0
        assert not stat.S_ISLNK(info.st_mode)
        if i < len(parts) - 1:
            assert stat.S_ISDIR(info.st_mode)
    final = os.lstat(raw)
    if stat.S_ISREG(final.st_mode):
        assert final.st_nlink == 1
PY
[[ $(git -C "$SOURCE" status --porcelain=v1 | wc -l) == 0 ]]
exec {SELF_FD}<"$SELF"
exec {COLLECTOR_FD}<"$COLLECTOR"
exec {TEST_FD}<"$TEST_EXE"
exec {BUILD_RECORD_FD}<"$BUILD_RECORD"
exec {RUSTC_FD}<"$RUSTC"
exec {CARGO_FD}<"$CARGO"
exec {BACKEND_BINARY_FD}<"$BACKEND_BINARY"
exec {BACKEND_UNIT_FD}<"$BACKEND_UNIT_FILE"
exec {CA_FD}<"$CA_FILE"
SELF_FD_PATH="/proc/self/fd/$SELF_FD"
COLLECTOR_FD_PATH="/proc/self/fd/$COLLECTOR_FD"
TEST_FD_PATH="/proc/self/fd/$TEST_FD"
export RHIZOME_BARRIER_FAULT_TEST_EXECUTABLE_FD=$TEST_FD
BUILD_RECORD_FD_PATH="/proc/self/fd/$BUILD_RECORD_FD"
RUSTC_FD_PATH="/proc/self/fd/$RUSTC_FD"
CARGO_FD_PATH="/proc/self/fd/$CARGO_FD"
BACKEND_BINARY_FD_PATH="/proc/self/fd/$BACKEND_BINARY_FD"
BACKEND_UNIT_FD_PATH="/proc/self/fd/$BACKEND_UNIT_FD"
CA_FD_PATH="/proc/self/fd/$CA_FD"
export SSL_CERT_FILE=$CA_FD_PATH

CGROUP=$SUPERVISOR_CGROUP
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
BACKEND_FRAGMENT=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p FragmentPath --value)
BACKEND_CONTROL_GROUP=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p ControlGroup --value)
BACKEND_EXE=$(readlink -f "/proc/$BACKEND_PID/exe")
[[ $BACKEND_FRAGMENT == "$BACKEND_UNIT_FILE" ]]
[[ $BACKEND_CONTROL_GROUP == "$BACKEND_CGROUP" ]]
[[ $BACKEND_EXE == "$BACKEND_BINARY" ]]
[[ $(stat -Lc '%d:%i' "/proc/$BACKEND_PID/exe") == "$(stat -Lc '%d:%i' "$BACKEND_BINARY")" ]]
BACKEND_LISTENER_INODE=$(python3 - "$BACKEND_PID" "$AWS_ENDPOINT" <<'PY'
import os, socket, sys, urllib.parse
pid=int(sys.argv[1]); url=urllib.parse.urlsplit(sys.argv[2])
assert url.scheme == 'https' and url.hostname == '127.0.0.1' and url.port == 19000
target_ip='0100007F'; target_port=f'{url.port:04X}'
matches=[]
for table in ('/proc/net/tcp',):
    for line in open(table).read().splitlines()[1:]:
        fields=line.split()
        ip,port=fields[1].split(':')
        if ip == target_ip and port == target_port and fields[3] == '0A': matches.append(fields[9])
assert len(matches) == 1, matches
owned=[]
for name in os.listdir(f'/proc/{pid}/fd'):
    try: link=os.readlink(f'/proc/{pid}/fd/{name}')
    except FileNotFoundError: continue
    if link == f'socket:[{matches[0]}]': owned.append(name)
assert len(owned) == 1, owned
print(matches[0])
PY
)
LINUX_BOOT_ID=$(tr -d '\n' </proc/sys/kernel/random/boot_id)
SYSROOT=$($RUSTC_FD_PATH --print sysroot)
[[ -d $SYSROOT && ! -L $SYSROOT ]]

EVIDENCE=$RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT
TOOLCHAIN_MANIFEST=$EVIDENCE/toolchain-tree.sha256
find "$SYSROOT" -xdev -type f -print0 | sort -z | xargs -0 sha256sum >"$TOOLCHAIN_MANIFEST"
chmod 0600 "$TOOLCHAIN_MANIFEST"
sync -f "$TOOLCHAIN_MANIFEST"
sync -f "$EVIDENCE"

SOURCE_COMMIT=$(git -C "$SOURCE" rev-parse HEAD)
SOURCE_TREE=$(git -C "$SOURCE" rev-parse 'HEAD^{tree}')
TEST_EXE_SHA=$(sha256sum "$TEST_FD_PATH" | cut -d' ' -f1)
TEST_EXE_IDENTITY=$(stat -Lc '%d:%i:%s' "$TEST_FD_PATH")
BUILD_RECORD_SHA=$(sha256sum "$BUILD_RECORD_FD_PATH" | cut -d' ' -f1)
BUILD_RECORD_IDENTITY=$(stat -Lc '%d:%i:%s' "$BUILD_RECORD_FD_PATH")
RUSTC_SHA=$(sha256sum "$RUSTC_FD_PATH" | cut -d' ' -f1)
RUSTC_IDENTITY=$(stat -Lc '%d:%i:%s' "$RUSTC_FD_PATH")
CARGO_SHA=$(sha256sum "$CARGO_FD_PATH" | cut -d' ' -f1)
CARGO_IDENTITY=$(stat -Lc '%d:%i:%s' "$CARGO_FD_PATH")
TOOLCHAIN_SHA=$(sha256sum "$TOOLCHAIN_MANIFEST" | cut -d' ' -f1)
RUNNER_SHA=$(sha256sum "$SELF_FD_PATH" | cut -d' ' -f1)
RUNNER_IDENTITY=$(stat -Lc '%d:%i:%s' "$SELF_FD_PATH")
COLLECTOR_SHA=$(sha256sum "$COLLECTOR_FD_PATH" | cut -d' ' -f1)
COLLECTOR_IDENTITY=$(stat -Lc '%d:%i:%s' "$COLLECTOR_FD_PATH")
BACKEND_BINARY_SHA=$(sha256sum "$BACKEND_BINARY_FD_PATH" | cut -d' ' -f1)
BACKEND_BINARY_IDENTITY=$(stat -Lc '%d:%i:%s' "$BACKEND_BINARY_FD_PATH")
BACKEND_UNIT_SHA=$(sha256sum "$BACKEND_UNIT_FD_PATH" | cut -d' ' -f1)
BACKEND_UNIT_IDENTITY=$(stat -Lc '%d:%i:%s' "$BACKEND_UNIT_FD_PATH")
CA_SHA=$(sha256sum "$CA_FD_PATH" | cut -d' ' -f1)
CA_IDENTITY=$(stat -Lc '%d:%i:%s' "$CA_FD_PATH")

PREFLIGHT=$EVIDENCE/preflight.receipt
cat >"$PREFLIGHT.pending" <<EOF
schema=1
run_id=$RUN_ID
attempt_receipt_sha256=$(sha256sum "$ATTEMPT" | cut -d' ' -f1)
evidence_root_device_inode=$EVIDENCE_ROOT_DEVICE_INODE
source_commit=$SOURCE_COMMIT
source_tree=$SOURCE_TREE
source_clean=true
test_executable_sha256=$TEST_EXE_SHA
test_executable_device_inode_size=$TEST_EXE_IDENTITY
test_executable_fd_number=$TEST_FD
build_record_sha256=$BUILD_RECORD_SHA
build_record_device_inode_size=$BUILD_RECORD_IDENTITY
rustc_version=$($RUSTC_FD_PATH --version)
rustc_sha256=$RUSTC_SHA
rustc_device_inode_size=$RUSTC_IDENTITY
cargo_version=$($CARGO_FD_PATH --version)
cargo_sha256=$CARGO_SHA
cargo_device_inode_size=$CARGO_IDENTITY
toolchain_tree_sha256=$TOOLCHAIN_SHA
runner_sha256=$RUNNER_SHA
runner_device_inode_size=$RUNNER_IDENTITY
runner_pid=$$
runner_pid_start_time_ticks=$SELF_START
terminal_collector_sha256=$COLLECTOR_SHA
terminal_collector_device_inode_size=$COLLECTOR_IDENTITY
linux_boot_id=$LINUX_BOOT_ID
supervisor_unit=$EXPECTED_UNIT
supervisor_cgroup=$CGROUP
supervisor_invocation_id=$SUPERVISOR_INVOCATION
supervisor_main_pid=$SUPERVISOR_MAIN_PID
backend_unit=$RHIZOME_BARRIER_BACKEND_UNIT
backend_main_pid=$BACKEND_PID
backend_pid_start_time_ticks=$BACKEND_START
backend_linux_boot_id=$LINUX_BOOT_ID
backend_invocation_id=$BACKEND_INVOCATION
backend_cgroup=$BACKEND_CGROUP
backend_fragment_path=$BACKEND_FRAGMENT
backend_executable_device_inode=$(stat -Lc '%d:%i' "/proc/$BACKEND_PID/exe")
backend_listener_socket_inode=$BACKEND_LISTENER_INODE
backend_active_enter_monotonic=$BACKEND_ACTIVE_MONOTONIC
backend_binary_sha256=$BACKEND_BINARY_SHA
backend_binary_device_inode_size=$BACKEND_BINARY_IDENTITY
backend_unit_file_sha256=$BACKEND_UNIT_SHA
backend_unit_file_device_inode_size=$BACKEND_UNIT_IDENTITY
backend_config_revision=$RHIZOME_BARRIER_BACKEND_CONFIG_REVISION
endpoint_origin=$AWS_ENDPOINT
region=$AWS_DEFAULT_REGION
addressing=path
bucket=$RHIZOME_BARRIER_S3_BUCKET
prefix=$RHIZOME_BARRIER_S3_PREFIX
ca_sha256=$CA_SHA
ca_device_inode_size=$CA_IDENTITY
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
printf 'RHIZOME_BARRIER_RUNNER_START run_id=%s invocation_id=%s cgroup=%s preflight_sha256=%s\n' \
    "$RUN_ID" "$SUPERVISOR_INVOCATION" "$CGROUP" "$RHIZOME_BARRIER_FAULT_PREFLIGHT_RECEIPT_SHA256"

set +e
"$TEST_FD_PATH" --exact fs::workspace_barrier::tests::foundation_rustfs_process_fault_matrix --ignored --nocapture >"$EVIDENCE/test.log" 2>&1
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
BACKEND_EXE_AFTER=$(readlink -f "/proc/$BACKEND_PID_AFTER/exe")
BACKEND_FRAGMENT_AFTER=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p FragmentPath --value)
BACKEND_CONTROL_AFTER=$(systemctl show "$RHIZOME_BARRIER_BACKEND_UNIT" -p ControlGroup --value)
BACKEND_SOCKET_OWNERS=$(python3 - "$BACKEND_PID_AFTER" "$BACKEND_LISTENER_INODE" <<'PY'
import os,sys
pid,inode=sys.argv[1:]; count=0
for name in os.listdir(f'/proc/{pid}/fd'):
    try: target=os.readlink(f'/proc/{pid}/fd/{name}')
    except FileNotFoundError: continue
    count += target == f'socket:[{inode}]'
print(count)
PY
)
if [[ $BACKEND_PID_AFTER != "$BACKEND_PID" || $BACKEND_START_AFTER != "$BACKEND_START" || \
      $BACKEND_INVOCATION_AFTER != "$BACKEND_INVOCATION" || $BACKEND_EXE_AFTER != "$BACKEND_BINARY" || \
      $BACKEND_FRAGMENT_AFTER != "$BACKEND_UNIT_FILE" || $BACKEND_CONTROL_AFTER != "$BACKEND_CGROUP" || \
      $BACKEND_SOCKET_OWNERS != 1 ]]; then
    TEST_EXIT=125
    printf '%s\n' "$TEST_EXIT" >"$EVIDENCE/exit-code"
    printf 'backend process generation changed during run\n' >>"$EVIDENCE/test.log"
fi
if [[ $(git -C "$SOURCE" rev-parse HEAD) != "$SOURCE_COMMIT" || \
      $(git -C "$SOURCE" rev-parse 'HEAD^{tree}') != "$SOURCE_TREE" || \
      $(git -C "$SOURCE" status --porcelain=v1 | wc -l) != 0 || \
      $(stat -Lc '%d:%i' "$RUN_OWNER_FD_PATH") != "$EVIDENCE_ROOT_DEVICE_INODE" || \
      $(stat -Lc '%d:%i' "$EXPECTED_EVIDENCE") != "$EVIDENCE_ROOT_DEVICE_INODE" || \
      $(sha256sum "$SELF_FD_PATH" | cut -d' ' -f1) != "$RUNNER_SHA" || \
      $(stat -Lc '%d:%i:%s' "$SELF_FD_PATH") != "$RUNNER_IDENTITY" || \
      $(stat -Lc '%d:%i:%s' "$SELF") != "$RUNNER_IDENTITY" || \
      $(sha256sum "$COLLECTOR_FD_PATH" | cut -d' ' -f1) != "$COLLECTOR_SHA" || \
      $(stat -Lc '%d:%i:%s' "$COLLECTOR_FD_PATH") != "$COLLECTOR_IDENTITY" || \
      $(stat -Lc '%d:%i:%s' "$COLLECTOR") != "$COLLECTOR_IDENTITY" || \
      $(sha256sum "$TEST_FD_PATH" | cut -d' ' -f1) != "$TEST_EXE_SHA" || \
      $(stat -Lc '%d:%i:%s' "$TEST_FD_PATH") != "$TEST_EXE_IDENTITY" || \
      $(stat -Lc '%d:%i:%s' "$TEST_EXE") != "$TEST_EXE_IDENTITY" || \
      $(sha256sum "$BUILD_RECORD_FD_PATH" | cut -d' ' -f1) != "$BUILD_RECORD_SHA" || \
      $(stat -Lc '%d:%i:%s' "$BUILD_RECORD") != "$BUILD_RECORD_IDENTITY" || \
      $(sha256sum "$RUSTC_FD_PATH" | cut -d' ' -f1) != "$RUSTC_SHA" || \
      $(stat -Lc '%d:%i:%s' "$RUSTC") != "$RUSTC_IDENTITY" || \
      $(sha256sum "$CARGO_FD_PATH" | cut -d' ' -f1) != "$CARGO_SHA" || \
      $(stat -Lc '%d:%i:%s' "$CARGO") != "$CARGO_IDENTITY" || \
      $(sha256sum "$TOOLCHAIN_MANIFEST" | cut -d' ' -f1) != "$TOOLCHAIN_SHA" || \
      $(sha256sum "$BACKEND_BINARY_FD_PATH" | cut -d' ' -f1) != "$BACKEND_BINARY_SHA" || \
      $(stat -Lc '%d:%i:%s' "$BACKEND_BINARY") != "$BACKEND_BINARY_IDENTITY" || \
      $(sha256sum "$BACKEND_UNIT_FD_PATH" | cut -d' ' -f1) != "$BACKEND_UNIT_SHA" || \
      $(stat -Lc '%d:%i:%s' "$BACKEND_UNIT_FILE") != "$BACKEND_UNIT_IDENTITY" || \
      $(sha256sum "$CA_FD_PATH" | cut -d' ' -f1) != "$CA_SHA" || \
      $(stat -Lc '%d:%i:%s' "$CA_FILE") != "$CA_IDENTITY" ]]
then
    TEST_EXIT=127
    printf '%s\n' "$TEST_EXIT" >"$EVIDENCE/exit-code"
    printf 'preflight identity changed during run\n' >>"$EVIDENCE/test.log"
fi
if grep -R -F -q -- "$AWS_ACCESS_KEY_ID" "$EVIDENCE" "$EXPECTED_ROOT" || \
   grep -R -F -q -- "$AWS_SECRET_ACCESS_KEY" "$EVIDENCE" "$EXPECTED_ROOT"
then
    TEST_EXIT=126
    printf '%s\n' "$TEST_EXIT" >"$EVIDENCE/exit-code"
    printf 'credential material detected in run evidence\n' >>"$EVIDENCE/test.log"
fi
python3 - "$EXPECTED_ROOT" <<'PY'
import os,stat,sys
root=sys.argv[1]
scenarios=['before-data-cut','after-0x0d-apply','manifest-applied-before-response','after-manifest-publish']
expected={f'{scenario}.{suffix}' for scenario in scenarios for suffix in ('context','claim','handshake','exit','recovery')}
actual=set(os.listdir(root)); assert actual == expected, (actual,expected)
for name in actual:
    info=os.lstat(os.path.join(root,name))
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
PY
if [[ $TEST_EXIT == 0 ]]; then
    printf 'BEHAVIOR_PASS_AWAITING_TERMINAL_COLLECTION\n' >"$EVIDENCE/status"
else
    printf 'FAIL_PERMANENT_DO_NOT_REUSE\n' >"$EVIDENCE/status"
fi
chmod 0600 "$EVIDENCE"/* "$EXPECTED_ROOT"/* 2>/dev/null || true
find "$EXPECTED_ROOT" -maxdepth 1 -type f -exec sync -f {} \;
find "$EVIDENCE" -maxdepth 1 -type f ! -name SHA256SUMS ! -name RUN-SHA256SUMS -exec sync -f {} \;
sync -f "$EXPECTED_ROOT"
sync -f "$EVIDENCE"
[[ $(find "$EXPECTED_ROOT" "$EVIDENCE" -type f -name '*.pending' | wc -l) == 0 ]]
find "$EXPECTED_ROOT" -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum >"$EVIDENCE/RUN-SHA256SUMS.pending"
sync -f "$EVIDENCE/RUN-SHA256SUMS.pending"
ln "$EVIDENCE/RUN-SHA256SUMS.pending" "$EVIDENCE/RUN-SHA256SUMS"
sync -f "$EVIDENCE"
unlink "$EVIDENCE/RUN-SHA256SUMS.pending"
sync -f "$EVIDENCE"
find "$EVIDENCE" -maxdepth 1 -type f ! -name SHA256SUMS ! -name status ! -name '*.pending' -print0 | sort -z | xargs -0 sha256sum >"$EVIDENCE/SHA256SUMS.pending"
sync -f "$EVIDENCE/SHA256SUMS.pending"
ln "$EVIDENCE/SHA256SUMS.pending" "$EVIDENCE/SHA256SUMS"
sync -f "$EVIDENCE"
unlink "$EVIDENCE/SHA256SUMS.pending"
sync -f "$EVIDENCE"
printf 'RHIZOME_BARRIER_RUNNER_END run_id=%s invocation_id=%s cgroup=%s exit_code=%s\n' \
    "$RUN_ID" "$SUPERVISOR_INVOCATION" "$CGROUP" "$TEST_EXIT"
exit "$TEST_EXIT"
