#!/usr/bin/env bash
set -euo pipefail

[[ $(id -u) == 0 ]] || { echo "sealed-retry finalizer must execute as root" >&2; exit 2; }
[[ $# == 3 ]] || { echo "usage: $0 RUN_ID RUNNER COLLECTOR" >&2; exit 2; }
RUN_ID=$1
python3 - "$RUN_ID" <<'PY'
import sys,uuid
value=uuid.UUID(sys.argv[1]); assert value.version==4 and str(value)==sys.argv[1]
PY

RUN_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/runs/$RUN_ID"
EVIDENCE_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/evidence/$RUN_ID"
TERMINAL="$EVIDENCE_ROOT/terminal"
RETRY_PARENT="/opt/rhizome/validation/zerofs-barrier-fault/retry-evidence"
RETRY_ROOT="$RETRY_PARENT/$RUN_ID"
RUNNER=$(readlink -f "$2")
COLLECTOR=$(readlink -f "$3")
SELF=$(readlink -f "$0")
AFTER_STATUS_FSYNC_RESPONSE_LOSS=${RHIZOME_BARRIER_FINALIZER_TEST_AFTER_STATUS_FSYNC_RESPONSE_LOSS:-0}
[[ $AFTER_STATUS_FSYNC_RESPONSE_LOSS == 0 || $AFTER_STATUS_FSYNC_RESPONSE_LOSS == 1 ]]

[[ $(stat -c '%a:%U:%G' "$RUN_ROOT") == 500:root:root ]]
[[ $(stat -c '%a:%U:%G' "$EVIDENCE_ROOT") == 500:root:root ]]
[[ $(stat -c '%a:%U:%G' "$RETRY_PARENT") == 700:root:root ]]
[[ -f $EVIDENCE_ROOT/FINAL-SEAL.receipt && -f $EVIDENCE_ROOT/FINAL-SHA256SUMS ]]
[[ $(find "$RUN_ROOT" "$EVIDENCE_ROOT" -name '*.pending' | wc -l) == 0 ]]
python3 - "$RUN_ROOT" "$EVIDENCE_ROOT" "$RETRY_PARENT" <<'PY'
import os,stat,sys
for path in sys.argv[1:]:
    assert os.path.isabs(path) and os.path.realpath(path)==path
    current='/'
    for part in (part for part in path.split('/') if part):
        current=os.path.join(current,part); info=os.lstat(current)
        assert info.st_uid==0 and info.st_gid==0 and info.st_mode & 0o022 == 0,(current,info.st_uid,info.st_gid,oct(stat.S_IMODE(info.st_mode)))
        assert not stat.S_ISLNK(info.st_mode)
    assert stat.S_ISDIR(os.lstat(path).st_mode)
PY
exec {FINALIZER_OWNER_FD}<"$EVIDENCE_ROOT"
flock -n "$FINALIZER_OWNER_FD"
FINALIZER_OWNER_FD_PATH="/proc/self/fd/$FINALIZER_OWNER_FD"
EVIDENCE_ROOT_DEVICE_INODE=$(stat -Lc '%d:%i' "$FINALIZER_OWNER_FD_PATH")
[[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT") == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
STATUS_STATE=$(cat "$EVIDENCE_ROOT/status")
[[ $STATUS_STATE == SEALED_AWAITING_RETRY_VERIFICATION || $STATUS_STATE == PASS ]]

python3 - "$RUN_ROOT" "$EVIDENCE_ROOT" "$STATUS_STATE" <<'PY'
import os,stat,sys
run,evidence,status=sys.argv[1:]
scenarios=('before-data-cut','after-0x0d-apply','manifest-applied-before-response','after-manifest-publish')
expected_run={f'{scenario}.{suffix}' for scenario in scenarios for suffix in ('context','claim','handshake','exit','recovery')}
assert set(os.listdir(run))==expected_run
expected_evidence={'attempt.receipt','preflight.receipt','toolchain-tree.sha256','test.log','exit-code','status',
                   'RUN-SHA256SUMS','SHA256SUMS','collector-attempt.receipt','terminal',
                   'FINAL-SHA256SUMS','FINAL-SEAL.receipt'}
assert set(os.listdir(evidence))==expected_evidence
expected_terminal={'preflight-selection','unit-journal.jsonl','invocation-journal.jsonl','journal-validation',
                   'post-terminal-inventory','pre-exit-manifest-check','run-manifest-check','receipt',
                   'status-pass.receipt','status-sealed-awaiting-retry.receipt','SHA256SUMS'}
assert set(os.listdir(os.path.join(evidence,'terminal')))==expected_terminal
terminal=os.path.join(evidence,'terminal')
for root in (run,evidence):
    for current,dirs,files in os.walk(root,followlinks=False):
        current_info=os.lstat(current)
        assert stat.S_ISDIR(current_info.st_mode) and stat.S_IMODE(current_info.st_mode)==0o500
        assert current_info.st_uid==0 and current_info.st_gid==0
        for name in dirs:
            info=os.lstat(os.path.join(current,name))
            assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o500
            assert info.st_uid==0 and info.st_gid==0
        for name in files:
            path=os.path.join(current,name); info=os.lstat(path)
            assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o400
            assert info.st_uid==0 and info.st_gid==0
            sealed_pair=(os.path.join(evidence,'status'),os.path.join(terminal,'status-sealed-awaiting-retry.receipt'))
            pass_pair=(os.path.join(evidence,'status'),os.path.join(terminal,'status-pass.receipt'))
            if status=='SEALED_AWAITING_RETRY_VERIFICATION': expected_links=2 if path in sealed_pair else 1
            else: expected_links=2 if path in pass_pair else 1
            assert info.st_nlink==expected_links,(path,info.st_nlink,expected_links)
PY

for path in "$SELF" "$RUNNER" "$COLLECTOR"; do
    [[ -f $path && ! -L $path ]]
done
exec {SELF_FD}<"$SELF"
exec {RUNNER_FD}<"$RUNNER"
exec {COLLECTOR_FD}<"$COLLECTOR"
exec {PREFLIGHT_FD}<"$EVIDENCE_ROOT/preflight.receipt"
SELF_FD_PATH="/proc/self/fd/$SELF_FD"
RUNNER_FD_PATH="/proc/self/fd/$RUNNER_FD"
COLLECTOR_FD_PATH="/proc/self/fd/$COLLECTOR_FD"
PREFLIGHT_FD_PATH="/proc/self/fd/$PREFLIGHT_FD"
python3 - "$SELF" "$RUNNER" "$COLLECTOR" <<'PY'
import os,stat,sys
for path in sys.argv[1:]:
    assert os.path.isabs(path) and os.path.realpath(path)==path
    current='/'
    for part in (part for part in path.split('/') if part):
        current=os.path.join(current,part); info=os.lstat(current)
        assert info.st_uid==0 and info.st_gid==0 and info.st_mode & 0o022 == 0,(current,info.st_uid,info.st_gid,oct(stat.S_IMODE(info.st_mode)))
        assert not stat.S_ISLNK(info.st_mode)
    final=os.lstat(path); assert stat.S_ISREG(final.st_mode) and final.st_nlink==1
PY

field() { awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2) }' "$PREFLIGHT_FD_PATH"; }
for binding in \
    "$RUNNER_FD_PATH|$RUNNER|runner_sha256|runner_device_inode_size" \
    "$COLLECTOR_FD_PATH|$COLLECTOR|terminal_collector_sha256|terminal_collector_device_inode_size" \
    "$SELF_FD_PATH|$SELF|sealed_retry_verifier_sha256|sealed_retry_verifier_device_inode_size"
do
    IFS='|' read -r fd_path locator digest_field identity_field <<<"$binding"
    [[ $(sha256sum "$fd_path" | cut -d' ' -f1) == "$(field "$digest_field")" ]]
    [[ $(sha256sum "$locator" | cut -d' ' -f1) == "$(field "$digest_field")" ]]
    [[ $(stat -Lc '%d:%i:%s' "$fd_path") == "$(field "$identity_field")" ]]
    [[ $(stat -Lc '%d:%i:%s' "$locator") == "$(field "$identity_field")" ]]
done
[[ $(field evidence_root_device_inode) == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
(cd "$EVIDENCE_ROOT" && sha256sum -c FINAL-SHA256SUMS >/dev/null)
(cd "$TERMINAL" && sha256sum -c SHA256SUMS >/dev/null)
if [[ $STATUS_STATE == SEALED_AWAITING_RETRY_VERIFICATION ]]; then
    [[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT/status") == "$(stat -Lc '%d:%i' "$TERMINAL/status-sealed-awaiting-retry.receipt")" ]]
    [[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT/status") != "$(stat -Lc '%d:%i' "$TERMINAL/status-pass.receipt")" ]]
    [[ ! -e $RETRY_ROOT ]]
else
    [[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT/status") == "$(stat -Lc '%d:%i' "$TERMINAL/status-pass.receipt")" ]]
    [[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT/status") != "$(stat -Lc '%d:%i' "$TERMINAL/status-sealed-awaiting-retry.receipt")" ]]
    [[ -d $RETRY_ROOT ]]
fi
SOURCE_FINAL_SEAL_SHA=$(sha256sum "$EVIDENCE_ROOT/FINAL-SEAL.receipt" | cut -d' ' -f1)
SOURCE_FINAL_MANIFEST_SHA=$(sha256sum "$EVIDENCE_ROOT/FINAL-SHA256SUMS" | cut -d' ' -f1)
SOURCE_TERMINAL_MANIFEST_SHA=$(sha256sum "$TERMINAL/SHA256SUMS" | cut -d' ' -f1)
STATUS_PASS_SHA=$(sha256sum "$TERMINAL/status-pass.receipt" | cut -d' ' -f1)
STATUS_SEALED_SHA=$(sha256sum "$TERMINAL/status-sealed-awaiting-retry.receipt" | cut -d' ' -f1)
COLLECTOR_ATTEMPT_SHA=$(sha256sum "$EVIDENCE_ROOT/collector-attempt.receipt" | cut -d' ' -f1)
python3 - "$EVIDENCE_ROOT/FINAL-SEAL.receipt" "$RUN_ID" "$EVIDENCE_ROOT_DEVICE_INODE" \
    "$SOURCE_FINAL_MANIFEST_SHA" "$SOURCE_TERMINAL_MANIFEST_SHA" "$STATUS_PASS_SHA" \
    "$STATUS_SEALED_SHA" "$COLLECTOR_ATTEMPT_SHA" <<'PY'
import sys
path,run,evidence,manifest,terminal,status,sealed,attempt=sys.argv[1:]
expected={'schema','run_id','verdict','evidence_root_device_inode','mode_profile','final_manifest_sha256',
          'final_manifest_readback','terminal_manifest_sha256','status_pass_receipt_sha256',
          'status_sealed_receipt_sha256','collector_attempt_receipt_sha256'}
values={}; raw=open(path,'rb').read(); text=raw.decode(); assert text.endswith('\n')
for line in text.splitlines():
    key,value=line.split('=',1); assert key in expected and key not in values and value and '=' not in value
    values[key]=value
assert set(values)==expected
assert values=={'schema':'1','run_id':run,'verdict':'SEALED_AWAITING_RETRY_VERIFICATION',
                'evidence_root_device_inode':evidence,'mode_profile':'root-read-only-v1',
                'final_manifest_sha256':manifest,'final_manifest_readback':'verified',
                'terminal_manifest_sha256':terminal,'status_pass_receipt_sha256':status,
                'status_sealed_receipt_sha256':sealed,'collector_attempt_receipt_sha256':attempt}
PY

verify_retry_root() {
    python3 - "$RETRY_ROOT" "$RUN_ID" "$EVIDENCE_ROOT_DEVICE_INODE" "$SOURCE_FINAL_SEAL_SHA" \
        "$STATUS_PASS_SHA" "$(field sealed_retry_verifier_sha256)" "$(field sealed_retry_verifier_device_inode_size)" \
        "$(field runner_sha256)" "$(field runner_device_inode_size)" \
        "$(field terminal_collector_sha256)" "$(field terminal_collector_device_inode_size)" <<'PY'
import hashlib,os,re,stat,sys,uuid
root,run,evidence,source_seal,status_pass,verifier_sha,verifier_id,runner_sha,runner_id,collector_sha,collector_id=sys.argv[1:]
assert uuid.UUID(run).version==4 and str(uuid.UUID(run))==run
assert os.path.basename(root)==run and os.path.realpath(root)==root
info=os.lstat(root); assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o500
assert info.st_uid==0 and info.st_gid==0
retry_root=f'{info.st_dev}:{info.st_ino}'
expected={'attempt.receipt','before.inventory','after.inventory','runner-retry.log','collector-retry.log',
          'retry.receipt','SHA256SUMS','FINAL.receipt'}
actual=set(os.listdir(root)); assert actual==expected,(actual,expected)
for name in actual:
    file_info=os.lstat(os.path.join(root,name))
    assert stat.S_ISREG(file_info.st_mode) and stat.S_IMODE(file_info.st_mode)==0o400
    assert file_info.st_uid==0 and file_info.st_gid==0 and file_info.st_nlink==1
def record(name,fields):
    raw=open(os.path.join(root,name),'rb').read(); assert raw.endswith(b'\n')
    values={}
    for line in raw.decode().splitlines():
        key,value=line.split('=',1); assert key in fields and key not in values and value and '=' not in value
        values[key]=value
    assert set(values)==set(fields); return values,raw
attempt_fields=('schema','run_id','finalizer_pid','finalizer_pid_start_time_ticks','finalizer_linux_boot_id',
                'finalizer_cgroup','evidence_root_device_inode','retry_root_device_inode','verifier_sha256',
                'verifier_device_inode_size','source_final_seal_sha256','after_status_fsync_response_loss_armed','attempted_at_utc')
attempt,_=record('attempt.receipt',attempt_fields)
assert attempt['schema']=='1' and attempt['run_id']==run and int(attempt['finalizer_pid'])>1
assert int(attempt['finalizer_pid_start_time_ticks'])>0 and uuid.UUID(attempt['finalizer_linux_boot_id'])
assert attempt['evidence_root_device_inode']==evidence and attempt['retry_root_device_inode']==retry_root
assert attempt['verifier_sha256']==verifier_sha and attempt['verifier_device_inode_size']==verifier_id
assert attempt['source_final_seal_sha256']==source_seal
assert attempt['after_status_fsync_response_loss_armed'] in ('0','1')
assert re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',attempt['attempted_at_utc'])
retry_fields=('schema','run_id','verdict','evidence_root_device_inode','retry_root_device_inode',
              'source_final_seal_sha256','runner_retry_exit','collector_retry_exit','before_inventory_sha256',
              'after_inventory_sha256','runner_retry_log_sha256','collector_retry_log_sha256','runner_sha256',
              'runner_device_inode_size','collector_sha256','collector_device_inode_size','verifier_sha256',
              'verifier_device_inode_size','after_status_fsync_response_loss_armed')
retry,retry_raw=record('retry.receipt',retry_fields)
assert retry['schema']=='1' and retry['run_id']==run and retry['verdict']=='RETRIES_REJECTED_TREE_UNCHANGED'
assert retry['evidence_root_device_inode']==evidence and retry['retry_root_device_inode']==retry_root
assert retry['source_final_seal_sha256']==source_seal
assert int(retry['runner_retry_exit'])!=0 and int(retry['collector_retry_exit'])!=0
for field,name in (('before_inventory_sha256','before.inventory'),('after_inventory_sha256','after.inventory'),
                   ('runner_retry_log_sha256','runner-retry.log'),('collector_retry_log_sha256','collector-retry.log')):
    assert retry[field]==hashlib.sha256(open(os.path.join(root,name),'rb').read()).hexdigest()
assert retry['before_inventory_sha256']==retry['after_inventory_sha256']
assert open(os.path.join(root,'before.inventory'),'rb').read()==open(os.path.join(root,'after.inventory'),'rb').read()
assert retry['runner_sha256']==runner_sha and retry['runner_device_inode_size']==runner_id
assert retry['collector_sha256']==collector_sha and retry['collector_device_inode_size']==collector_id
assert retry['verifier_sha256']==verifier_sha and retry['verifier_device_inode_size']==verifier_id
assert retry['after_status_fsync_response_loss_armed']==attempt['after_status_fsync_response_loss_armed']
manifest_raw=open(os.path.join(root,'SHA256SUMS'),'rb').read(); manifest_sha=hashlib.sha256(manifest_raw).hexdigest()
manifest={}
for line in manifest_raw.decode().splitlines():
    digest,path=line.split('  ',1); assert re.fullmatch(r'[0-9a-f]{64}',digest) and path not in manifest
    manifest[path]=digest
expected_manifest={os.path.join(root,name) for name in ('attempt.receipt','before.inventory','after.inventory',
                   'runner-retry.log','collector-retry.log','retry.receipt')}
assert set(manifest)==expected_manifest
for path,digest in manifest.items(): assert hashlib.sha256(open(path,'rb').read()).hexdigest()==digest
final_fields=('schema','run_id','verdict','evidence_root_device_inode','retry_root_device_inode',
              'retry_manifest_sha256','retry_manifest_readback','retry_receipt_sha256',
              'source_final_seal_sha256','status_pass_receipt_sha256','verifier_sha256',
              'after_status_fsync_response_loss_armed')
final,_=record('FINAL.receipt',final_fields)
assert final=={'schema':'1','run_id':run,'verdict':'VERIFIED_AWAITING_STATUS',
              'evidence_root_device_inode':evidence,'retry_root_device_inode':retry_root,
              'retry_manifest_sha256':manifest_sha,'retry_manifest_readback':'verified',
              'retry_receipt_sha256':hashlib.sha256(retry_raw).hexdigest(),
              'source_final_seal_sha256':source_seal,'status_pass_receipt_sha256':status_pass,
              'verifier_sha256':verifier_sha,
              'after_status_fsync_response_loss_armed':attempt['after_status_fsync_response_loss_armed']}
PY
}

if [[ $STATUS_STATE == PASS ]]; then
    verify_retry_root
    exit 0
fi

umask 077
mkdir -m 0700 "$RETRY_ROOT"
chown root:root "$RETRY_ROOT"
sync -f "$RETRY_PARENT"
[[ $(stat -c '%a:%U:%G' "$RETRY_ROOT") == 700:root:root ]]
exec {RETRY_ROOT_FD}<"$RETRY_ROOT"
flock -n "$RETRY_ROOT_FD"
RETRY_ROOT_FD_PATH="/proc/self/fd/$RETRY_ROOT_FD"
RETRY_ROOT_DEVICE_INODE=$(stat -Lc '%d:%i' "$RETRY_ROOT_FD_PATH")
[[ $(stat -Lc '%d:%i' "$RETRY_ROOT") == "$RETRY_ROOT_DEVICE_INODE" ]]
FINALIZER_START=$(python3 - $$ <<'PY'
import sys
text=open(f'/proc/{sys.argv[1]}/stat').read()
print(text[text.rfind(')') + 2:].split()[19])
PY
)
FINALIZER_BOOT=$(tr -d '\n' </proc/sys/kernel/random/boot_id)
FINALIZER_CGROUP=$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)
ATTEMPTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$RETRY_ROOT/attempt.receipt" "$RUN_ID" "$$" "$FINALIZER_START" "$FINALIZER_BOOT" \
    "$FINALIZER_CGROUP" "$EVIDENCE_ROOT_DEVICE_INODE" "$RETRY_ROOT_DEVICE_INODE" \
    "$(field sealed_retry_verifier_sha256)" "$(field sealed_retry_verifier_device_inode_size)" \
    "$SOURCE_FINAL_SEAL_SHA" "$AFTER_STATUS_FSYNC_RESPONSE_LOSS" "$ATTEMPTED_AT" <<'PY'
import os,sys
path,run,pid,start,boot,cgroup,evidence,retry_root,digest,identity,source_seal,fault,when=sys.argv[1:]
data=f'schema=1\nrun_id={run}\nfinalizer_pid={pid}\nfinalizer_pid_start_time_ticks={start}\nfinalizer_linux_boot_id={boot}\nfinalizer_cgroup={cgroup}\nevidence_root_device_inode={evidence}\nretry_root_device_inode={retry_root}\nverifier_sha256={digest}\nverifier_device_inode_size={identity}\nsource_final_seal_sha256={source_seal}\nafter_status_fsync_response_loss_armed={fault}\nattempted_at_utc={when}\n'.encode()
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    view=memoryview(data)
    while view:
        written=os.write(fd,view); assert written>0; view=view[written:]
    os.fsync(fd)
finally:
    os.close(fd)
PY
sync -f "$RETRY_ROOT"
python3 - "$RETRY_ROOT/attempt.receipt" "$RUN_ID" "$$" "$FINALIZER_START" "$FINALIZER_BOOT" \
    "$FINALIZER_CGROUP" "$EVIDENCE_ROOT_DEVICE_INODE" "$RETRY_ROOT_DEVICE_INODE" "$(field sealed_retry_verifier_sha256)" \
    "$(field sealed_retry_verifier_device_inode_size)" "$SOURCE_FINAL_SEAL_SHA" "$AFTER_STATUS_FSYNC_RESPONSE_LOSS" <<'PY'
import re,sys
path,run,pid,start,boot,cgroup,evidence,retry_root,digest,identity,source,fault=sys.argv[1:]
expected={'schema','run_id','finalizer_pid','finalizer_pid_start_time_ticks','finalizer_linux_boot_id',
          'finalizer_cgroup','evidence_root_device_inode','retry_root_device_inode','verifier_sha256','verifier_device_inode_size',
          'source_final_seal_sha256','after_status_fsync_response_loss_armed','attempted_at_utc'}
values={}; raw=open(path,'rb').read(); text=raw.decode(); assert text.endswith('\n')
for line in text.splitlines():
    key,value=line.split('=',1); assert key in expected and key not in values and value and '=' not in value
    values[key]=value
assert set(values)==expected
assert values['schema']=='1' and values['run_id']==run and values['finalizer_pid']==pid
assert values['finalizer_pid_start_time_ticks']==start and values['finalizer_linux_boot_id']==boot
assert values['finalizer_cgroup']==cgroup and values['evidence_root_device_inode']==evidence
assert values['retry_root_device_inode']==retry_root
assert values['verifier_sha256']==digest and values['verifier_device_inode_size']==identity
assert values['source_final_seal_sha256']==source
assert values['after_status_fsync_response_loss_armed']==fault
assert re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',values['attempted_at_utc'])
PY

inventory() {
    local output=$1
    python3 - "$RUN_ROOT" "$EVIDENCE_ROOT" >"$output" <<'PY'
import hashlib,os,stat,sys
for root in sys.argv[1:]:
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs.sort(); files.sort()
        current_info=os.lstat(current)
        assert stat.S_ISDIR(current_info.st_mode) and stat.S_IMODE(current_info.st_mode)==0o500
        assert current_info.st_uid==0 and current_info.st_gid==0
        for name in ['.']+dirs+files:
            path=current if name=='.' else os.path.join(current,name)
            info=os.lstat(path); kind='dir' if stat.S_ISDIR(info.st_mode) else 'file'; digest='-'
            if kind=='file':
                assert stat.S_IMODE(info.st_mode)==0o400 and info.st_uid==0 and info.st_gid==0
                expected_links=2 if path in (os.path.join(sys.argv[2],'status'),
                                             os.path.join(sys.argv[2],'terminal','status-sealed-awaiting-retry.receipt')) else 1
                assert info.st_nlink==expected_links
                with open(path,'rb') as source: digest=hashlib.sha256(source.read()).hexdigest()
            else:
                assert stat.S_IMODE(info.st_mode)==0o500 and info.st_uid==0 and info.st_gid==0
            print('|'.join((path,kind,oct(stat.S_IMODE(info.st_mode)),str(info.st_uid),str(info.st_gid),
                            str(info.st_nlink),str(info.st_dev),str(info.st_ino),str(info.st_size),digest)))
PY
    chmod 0600 "$output"
    sync -f "$output"
}

inventory "$RETRY_ROOT/before.inventory"
set +e
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    RHIZOME_BARRIER_FAULT_RUN_ID="$RUN_ID" \
    RHIZOME_BARRIER_FAULT_RUN_ROOT="$RUN_ROOT" \
    RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT="$EVIDENCE_ROOT" \
    "$RUNNER_FD_PATH" >"$RETRY_ROOT/runner-retry.log" 2>&1
RUNNER_EXIT=$?
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    "$COLLECTOR_FD_PATH" "$RUN_ID" >"$RETRY_ROOT/collector-retry.log" 2>&1
COLLECTOR_EXIT=$?
set -e
chmod 0600 "$RETRY_ROOT/runner-retry.log" "$RETRY_ROOT/collector-retry.log"
sync -f "$RETRY_ROOT/runner-retry.log"
sync -f "$RETRY_ROOT/collector-retry.log"
[[ $RUNNER_EXIT != 0 && $COLLECTOR_EXIT != 0 ]]
inventory "$RETRY_ROOT/after.inventory"
cmp -s "$RETRY_ROOT/before.inventory" "$RETRY_ROOT/after.inventory"
[[ $(stat -Lc '%d:%i' "$FINALIZER_OWNER_FD_PATH") == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
[[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT") == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
for binding in \
    "$RUNNER_FD_PATH|$RUNNER|runner_sha256|runner_device_inode_size" \
    "$COLLECTOR_FD_PATH|$COLLECTOR|terminal_collector_sha256|terminal_collector_device_inode_size" \
    "$SELF_FD_PATH|$SELF|sealed_retry_verifier_sha256|sealed_retry_verifier_device_inode_size"
do
    IFS='|' read -r fd_path locator digest_field identity_field <<<"$binding"
    [[ $(sha256sum "$fd_path" | cut -d' ' -f1) == "$(field "$digest_field")" ]]
    [[ $(sha256sum "$locator" | cut -d' ' -f1) == "$(field "$digest_field")" ]]
    [[ $(stat -Lc '%d:%i:%s' "$fd_path") == "$(field "$identity_field")" ]]
    [[ $(stat -Lc '%d:%i:%s' "$locator") == "$(field "$identity_field")" ]]
done

BEFORE_SHA=$(sha256sum "$RETRY_ROOT/before.inventory" | cut -d' ' -f1)
AFTER_SHA=$(sha256sum "$RETRY_ROOT/after.inventory" | cut -d' ' -f1)
RUNNER_LOG_SHA=$(sha256sum "$RETRY_ROOT/runner-retry.log" | cut -d' ' -f1)
COLLECTOR_LOG_SHA=$(sha256sum "$RETRY_ROOT/collector-retry.log" | cut -d' ' -f1)
cat >"$RETRY_ROOT/retry.receipt.pending" <<EOF
schema=1
run_id=$RUN_ID
verdict=RETRIES_REJECTED_TREE_UNCHANGED
evidence_root_device_inode=$EVIDENCE_ROOT_DEVICE_INODE
retry_root_device_inode=$RETRY_ROOT_DEVICE_INODE
source_final_seal_sha256=$SOURCE_FINAL_SEAL_SHA
runner_retry_exit=$RUNNER_EXIT
collector_retry_exit=$COLLECTOR_EXIT
before_inventory_sha256=$BEFORE_SHA
after_inventory_sha256=$AFTER_SHA
runner_retry_log_sha256=$RUNNER_LOG_SHA
collector_retry_log_sha256=$COLLECTOR_LOG_SHA
runner_sha256=$(field runner_sha256)
runner_device_inode_size=$(field runner_device_inode_size)
collector_sha256=$(field terminal_collector_sha256)
collector_device_inode_size=$(field terminal_collector_device_inode_size)
verifier_sha256=$(field sealed_retry_verifier_sha256)
verifier_device_inode_size=$(field sealed_retry_verifier_device_inode_size)
after_status_fsync_response_loss_armed=$AFTER_STATUS_FSYNC_RESPONSE_LOSS
EOF
chmod 0600 "$RETRY_ROOT/retry.receipt.pending"
sync -f "$RETRY_ROOT/retry.receipt.pending"
ln "$RETRY_ROOT/retry.receipt.pending" "$RETRY_ROOT/retry.receipt"
sync -f "$RETRY_ROOT"
unlink "$RETRY_ROOT/retry.receipt.pending"
sync -f "$RETRY_ROOT"
python3 - "$RETRY_ROOT/retry.receipt" "$RUN_ID" "$EVIDENCE_ROOT_DEVICE_INODE" "$RETRY_ROOT_DEVICE_INODE" \
    "$SOURCE_FINAL_SEAL_SHA" "$RUNNER_EXIT" "$COLLECTOR_EXIT" "$BEFORE_SHA" "$AFTER_SHA" \
    "$RUNNER_LOG_SHA" "$COLLECTOR_LOG_SHA" "$(field runner_sha256)" "$(field runner_device_inode_size)" \
    "$(field terminal_collector_sha256)" "$(field terminal_collector_device_inode_size)" \
    "$(field sealed_retry_verifier_sha256)" "$(field sealed_retry_verifier_device_inode_size)" \
    "$AFTER_STATUS_FSYNC_RESPONSE_LOSS" <<'PY'
import sys
path,run,evidence,retry_root,source,runner_exit,collector_exit,before,after,runner_log,collector_log,runner_sha,runner_id,collector_sha,collector_id,verifier_sha,verifier_id,fault=sys.argv[1:]
expected={'schema','run_id','verdict','evidence_root_device_inode','retry_root_device_inode','source_final_seal_sha256',
          'runner_retry_exit','collector_retry_exit','before_inventory_sha256','after_inventory_sha256',
          'runner_retry_log_sha256','collector_retry_log_sha256','runner_sha256','runner_device_inode_size',
          'collector_sha256','collector_device_inode_size','verifier_sha256','verifier_device_inode_size',
          'after_status_fsync_response_loss_armed'}
values={}; raw=open(path,'rb').read(); text=raw.decode(); assert text.endswith('\n')
for line in text.splitlines():
    key,value=line.split('=',1); assert key in expected and key not in values and value and '=' not in value
    values[key]=value
assert set(values)==expected
assert values=={'schema':'1','run_id':run,'verdict':'RETRIES_REJECTED_TREE_UNCHANGED',
                'evidence_root_device_inode':evidence,'retry_root_device_inode':retry_root,
                'source_final_seal_sha256':source,
                'runner_retry_exit':runner_exit,'collector_retry_exit':collector_exit,
                'before_inventory_sha256':before,'after_inventory_sha256':after,
                'runner_retry_log_sha256':runner_log,'collector_retry_log_sha256':collector_log,
                'runner_sha256':runner_sha,'runner_device_inode_size':runner_id,
                'collector_sha256':collector_sha,'collector_device_inode_size':collector_id,
                'verifier_sha256':verifier_sha,'verifier_device_inode_size':verifier_id,
                'after_status_fsync_response_loss_armed':fault}
PY
find "$RETRY_ROOT" -maxdepth 1 -type f ! -name SHA256SUMS ! -name '*.pending' -print0 | \
    sort -z | xargs -0 sha256sum >"$RETRY_ROOT/SHA256SUMS.pending"
chmod 0600 "$RETRY_ROOT/SHA256SUMS.pending"
sync -f "$RETRY_ROOT/SHA256SUMS.pending"
ln "$RETRY_ROOT/SHA256SUMS.pending" "$RETRY_ROOT/SHA256SUMS"
sync -f "$RETRY_ROOT"
unlink "$RETRY_ROOT/SHA256SUMS.pending"
sync -f "$RETRY_ROOT"
(cd "$RETRY_ROOT" && sha256sum -c SHA256SUMS >/dev/null)
RETRY_MANIFEST_SHA=$(sha256sum "$RETRY_ROOT/SHA256SUMS" | cut -d' ' -f1)
RETRY_RECEIPT_SHA=$(sha256sum "$RETRY_ROOT/retry.receipt" | cut -d' ' -f1)
cat >"$RETRY_ROOT/FINAL.receipt.pending" <<EOF
schema=1
run_id=$RUN_ID
verdict=VERIFIED_AWAITING_STATUS
evidence_root_device_inode=$EVIDENCE_ROOT_DEVICE_INODE
retry_root_device_inode=$RETRY_ROOT_DEVICE_INODE
retry_manifest_sha256=$RETRY_MANIFEST_SHA
retry_manifest_readback=verified
retry_receipt_sha256=$RETRY_RECEIPT_SHA
source_final_seal_sha256=$SOURCE_FINAL_SEAL_SHA
status_pass_receipt_sha256=$STATUS_PASS_SHA
verifier_sha256=$(field sealed_retry_verifier_sha256)
after_status_fsync_response_loss_armed=$AFTER_STATUS_FSYNC_RESPONSE_LOSS
EOF
chmod 0600 "$RETRY_ROOT/FINAL.receipt.pending"
sync -f "$RETRY_ROOT/FINAL.receipt.pending"
ln "$RETRY_ROOT/FINAL.receipt.pending" "$RETRY_ROOT/FINAL.receipt"
sync -f "$RETRY_ROOT"
unlink "$RETRY_ROOT/FINAL.receipt.pending"
sync -f "$RETRY_ROOT"
python3 - "$RETRY_ROOT/FINAL.receipt" "$RUN_ID" "$EVIDENCE_ROOT_DEVICE_INODE" "$RETRY_ROOT_DEVICE_INODE" \
    "$RETRY_MANIFEST_SHA" "$RETRY_RECEIPT_SHA" "$SOURCE_FINAL_SEAL_SHA" "$STATUS_PASS_SHA" \
    "$(field sealed_retry_verifier_sha256)" "$AFTER_STATUS_FSYNC_RESPONSE_LOSS" <<'PY'
import sys
path,run,evidence,retry_root,manifest,retry,source,status,verifier,fault=sys.argv[1:]
expected={'schema','run_id','verdict','evidence_root_device_inode','retry_root_device_inode','retry_manifest_sha256',
          'retry_manifest_readback','retry_receipt_sha256','source_final_seal_sha256',
          'status_pass_receipt_sha256','verifier_sha256','after_status_fsync_response_loss_armed'}
values={}; raw=open(path,'rb').read(); text=raw.decode(); assert text.endswith('\n')
for line in text.splitlines():
    key,value=line.split('=',1); assert key in expected and key not in values and value and '=' not in value
    values[key]=value
assert set(values)==expected
assert values=={'schema':'1','run_id':run,'verdict':'VERIFIED_AWAITING_STATUS',
                'evidence_root_device_inode':evidence,'retry_root_device_inode':retry_root,
                'retry_manifest_sha256':manifest,
                'retry_manifest_readback':'verified','retry_receipt_sha256':retry,
                'source_final_seal_sha256':source,'status_pass_receipt_sha256':status,
                'verifier_sha256':verifier,'after_status_fsync_response_loss_armed':fault}
PY

[[ $(find "$RETRY_ROOT" -type f -name '*.pending' | wc -l) == 0 ]]
python3 - "$RETRY_ROOT" <<'PY'
import os,stat,sys
root=sys.argv[1]
expected={'attempt.receipt','before.inventory','after.inventory','runner-retry.log','collector-retry.log',
          'retry.receipt','SHA256SUMS','FINAL.receipt'}
actual=set(os.listdir(root)); assert actual==expected,(actual,expected)
for name in actual:
    info=os.lstat(os.path.join(root,name))
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600
    assert info.st_uid==0 and info.st_gid==0 and info.st_nlink==1
PY
find "$RETRY_ROOT" -type f -exec chmod 0400 {} \;
chmod 0500 "$RETRY_ROOT"
sync -f "$RETRY_ROOT"
verify_retry_root
ln "$TERMINAL/status-pass.receipt" "$EVIDENCE_ROOT/status.pass.pending"
sync -f "$EVIDENCE_ROOT"
[[ $(cat "$EVIDENCE_ROOT/status.pass.pending") == PASS ]]
[[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT/status.pass.pending") == "$(stat -Lc '%d:%i' "$TERMINAL/status-pass.receipt")" ]]
mv -T "$EVIDENCE_ROOT/status.pass.pending" "$EVIDENCE_ROOT/status"
sync -f "$EVIDENCE_ROOT"
if [[ $AFTER_STATUS_FSYNC_RESPONSE_LOSS == 1 ]]; then
    exit 74
fi
