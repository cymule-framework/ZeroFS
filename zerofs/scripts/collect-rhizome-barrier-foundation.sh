#!/usr/bin/env bash
set -euo pipefail

[[ $(id -u) == 0 ]] || { echo "collector must execute as root" >&2; exit 2; }
[[ $# == 1 ]] || { echo "usage: $0 RUN_ID" >&2; exit 2; }
RUN_ID=$1
python3 - "$RUN_ID" <<'PY'
import sys,uuid
value=uuid.UUID(sys.argv[1]); assert value.version == 4 and str(value) == sys.argv[1]
PY

UNIT="zerofs-barrier-fault-$RUN_ID.service"
RUN_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/runs/$RUN_ID"
EVIDENCE_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/evidence/$RUN_ID"
[[ $(stat -c '%a:%U:%G' "$RUN_ROOT") == 700:root:root ]]
[[ $(stat -c '%a:%U:%G' "$EVIDENCE_ROOT") == 700:root:root ]]
python3 - "$RUN_ROOT" "$EVIDENCE_ROOT" <<'PY'
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
exec {COLLECTOR_OWNER_FD}<"$EVIDENCE_ROOT"
flock -n "$COLLECTOR_OWNER_FD"
COLLECTOR_OWNER_FD_PATH="/proc/self/fd/$COLLECTOR_OWNER_FD"
EVIDENCE_ROOT_DEVICE_INODE=$(stat -Lc '%d:%i' "$COLLECTOR_OWNER_FD_PATH")
[[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT") == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
python3 - "$EVIDENCE_ROOT" <<'PY'
import os,stat,sys
root=sys.argv[1]
expected={'attempt.receipt','preflight.receipt','toolchain-tree.sha256','test.log','exit-code',
          'status','RUN-SHA256SUMS','SHA256SUMS'}
actual=set(os.listdir(root)); assert actual==expected,(actual,expected)
for name in actual:
    info=os.lstat(os.path.join(root,name))
    assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0
    assert stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
assert open(os.path.join(root,'status')).read()=='BEHAVIOR_PASS_AWAITING_TERMINAL_COLLECTION\n'
PY
COLLECTOR=$(readlink -f "$0")
exec {COLLECTOR_FD}<"$COLLECTOR"
COLLECTOR_FD_PATH="/proc/self/fd/$COLLECTOR_FD"
python3 - "$COLLECTOR" <<'PY'
import os,stat,sys
path=sys.argv[1]; assert os.path.isabs(path) and os.path.realpath(path)==path
current='/'
for part in (part for part in path.split('/') if part):
    current=os.path.join(current,part); info=os.lstat(current)
    assert info.st_uid==0 and info.st_gid==0 and info.st_mode & 0o022 == 0
    assert not stat.S_ISLNK(info.st_mode)
final=os.lstat(path); assert stat.S_ISREG(final.st_mode) and final.st_nlink==1
PY
COLLECTOR_SHA=$(sha256sum "$COLLECTOR_FD_PATH" | cut -d' ' -f1)
COLLECTOR_IDENTITY=$(stat -Lc '%d:%i:%s' "$COLLECTOR_FD_PATH")
COLLECTOR_START=$(python3 - $$ <<'PY'
import sys
text=open(f'/proc/{sys.argv[1]}/stat').read()
print(text[text.rfind(')') + 2:].split()[19])
PY
)
COLLECTOR_BOOT=$(tr -d '\n' </proc/sys/kernel/random/boot_id)
COLLECTOR_ATTEMPT="$EVIDENCE_ROOT/collector-attempt.receipt"
COLLECTOR_ATTEMPTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$COLLECTOR_ATTEMPT.pending" "$RUN_ID" "$$" "$COLLECTOR_START" "$COLLECTOR_BOOT" "$COLLECTOR_SHA" "$COLLECTOR_IDENTITY" "$EVIDENCE_ROOT_DEVICE_INODE" "$COLLECTOR_ATTEMPTED_AT" <<'PY'
import os,sys
path,run,pid,start,boot,digest,identity,evidence,when=sys.argv[1:]
data=f'schema=1\nrun_id={run}\ncollector_pid={pid}\ncollector_pid_start_time_ticks={start}\nlinux_boot_id={boot}\ncollector_sha256={digest}\ncollector_device_inode_size={identity}\nevidence_root_device_inode={evidence}\nattempted_at_utc={when}\n'.encode()
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    view=memoryview(data)
    while view:
        written=os.write(fd,view); assert written>0; view=view[written:]
    os.fsync(fd)
finally:
    os.close(fd)
PY
ln "$COLLECTOR_ATTEMPT.pending" "$COLLECTOR_ATTEMPT"
sync -f "$EVIDENCE_ROOT"
unlink "$COLLECTOR_ATTEMPT.pending"
sync -f "$EVIDENCE_ROOT"
exec {COLLECTOR_ATTEMPT_FD}<"$COLLECTOR_ATTEMPT"
COLLECTOR_ATTEMPT_FD_PATH="/proc/self/fd/$COLLECTOR_ATTEMPT_FD"
COLLECTOR_ATTEMPT_IDENTITY=$(stat -Lc '%d:%i:%s' "$COLLECTOR_ATTEMPT_FD_PATH")
COLLECTOR_ATTEMPT_SHA=$(sha256sum "$COLLECTOR_ATTEMPT_FD_PATH" | cut -d' ' -f1)

# The durable attempt above is the collector PONR. Any later error burns the run.
TERMINAL="$EVIDENCE_ROOT/terminal"
umask 077
mkdir -m 0700 "$TERMINAL"
chown root:root "$TERMINAL"
sync -f "$EVIDENCE_ROOT"
[[ $(stat -c '%a:%U:%G' "$TERMINAL") == 700:root:root ]]
[[ $(find "$TERMINAL" -mindepth 1 -maxdepth 1 | wc -l) == 0 ]]

[[ -n ${AWS_ACCESS_KEY_ID:-} && -n ${AWS_SECRET_ACCESS_KEY:-} && -n ${SSL_CERT_FILE:-} && -n ${AWS_DEFAULT_REGION:-} && -n ${RHIZOME_BARRIER_S3_BUCKET:-} ]] || {
    echo "standard AWS credentials, region, bucket, and process-scoped trust are required" >&2
    exit 2
}

exec {PREFLIGHT_FD}<"$EVIDENCE_ROOT/preflight.receipt"
exec {RUN_ATTEMPT_FD}<"$EVIDENCE_ROOT/attempt.receipt"
PREFLIGHT_FD_PATH="/proc/self/fd/$PREFLIGHT_FD"
RUN_ATTEMPT_FD_PATH="/proc/self/fd/$RUN_ATTEMPT_FD"
PREFLIGHT_IDENTITY=$(stat -Lc '%d:%i:%s' "$PREFLIGHT_FD_PATH")
RUN_ATTEMPT_IDENTITY=$(stat -Lc '%d:%i:%s' "$RUN_ATTEMPT_FD_PATH")
RUN_ATTEMPT_SHA=$(sha256sum "$RUN_ATTEMPT_FD_PATH" | cut -d' ' -f1)
python3 - "$PREFLIGHT_FD_PATH" "$RUN_ATTEMPT_FD_PATH" "$TERMINAL/preflight-selection" "$RUN_ID" <<'PY'
import hashlib,re,sys
source,attempt,output,run=sys.argv[1:]
import os,stat
for path in (source,attempt):
    info=os.stat(path)
    assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0
    assert stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
expected={
'schema','run_id','attempt_receipt_sha256','evidence_root_device_inode','source_commit','source_tree','source_clean','test_executable_sha256',
'test_executable_device_inode_size','test_executable_fd_number','build_record_sha256','build_record_device_inode_size','rustc_version','rustc_sha256',
'rustc_device_inode_size','cargo_version','cargo_sha256','cargo_device_inode_size','toolchain_tree_sha256',
'runner_sha256','runner_device_inode_size','runner_pid','runner_pid_start_time_ticks',
'terminal_collector_sha256','terminal_collector_device_inode_size','sealed_retry_verifier_sha256',
'sealed_retry_verifier_device_inode_size','linux_boot_id','supervisor_unit','supervisor_cgroup',
'supervisor_invocation_id','supervisor_main_pid','backend_unit','backend_main_pid','backend_pid_start_time_ticks',
'backend_linux_boot_id','backend_invocation_id','backend_cgroup','backend_fragment_path',
'backend_executable_device_inode','backend_listener_socket_inode','backend_active_enter_monotonic',
'backend_binary_sha256','backend_binary_device_inode_size','backend_unit_file_sha256',
'backend_unit_file_device_inode_size','backend_config_revision','endpoint_origin',
'region','addressing','bucket','prefix','ca_sha256','ca_device_inode_size','credential_values_recorded','started_at_utc'}
d={}; raw=open(source,'rb').read(); text=raw.decode(); assert text.endswith('\n')
for line in text.splitlines():
    key,value=line.split('=',1); assert key in expected and key not in d and value and '\n' not in value
    d[key]=value
assert set(d)==expected
attempt_fields={}; attempt_raw=open(attempt,'rb').read(); attempt_text=attempt_raw.decode(); assert attempt_text.endswith('\n')
for line in attempt_text.splitlines():
    key,value=line.split('=',1)
    assert key in {'schema','run_id','runner_pid','runner_pid_start_time_ticks','linux_boot_id','supervisor_unit','evidence_root_device_inode','attempted_at_utc'}
    assert key not in attempt_fields and value and '=' not in value
    attempt_fields[key]=value
assert set(attempt_fields)=={'schema','run_id','runner_pid','runner_pid_start_time_ticks','linux_boot_id','supervisor_unit','evidence_root_device_inode','attempted_at_utc'}
assert d['schema']=='1' and d['run_id']==run and d['source_clean']=='true'
assert attempt_fields['schema']=='1' and attempt_fields['run_id']==run
assert attempt_fields['runner_pid']==d['runner_pid'] and attempt_fields['runner_pid_start_time_ticks']==d['runner_pid_start_time_ticks']
assert attempt_fields['linux_boot_id']==d['linux_boot_id'] and attempt_fields['supervisor_unit']==d['supervisor_unit']
assert attempt_fields['evidence_root_device_inode']==d['evidence_root_device_inode']
assert re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',attempt_fields['attempted_at_utc'])
assert hashlib.sha256(attempt_raw).hexdigest()==d['attempt_receipt_sha256']
assert d['supervisor_unit']==f'zerofs-barrier-fault-{run}.service'
assert int(d['test_executable_fd_number']) > 2
assert re.fullmatch(r'[0-9a-f]{32}',d['supervisor_invocation_id'])
assert d['supervisor_main_pid']==d['runner_pid'] and int(d['runner_pid']) > 1
assert d['supervisor_cgroup'].startswith('/') and '..' not in d['supervisor_cgroup'] and '//' not in d['supervisor_cgroup']
assert d['supervisor_cgroup'].endswith('/'+d['supervisor_unit'])
assert re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*',d['evidence_root_device_inode'])
assert d['endpoint_origin']=='https://127.0.0.1:19000' and d['addressing']=='path'
assert d['prefix']==f'rhizome/zerofs-barrier-fault/{run}' and d['credential_values_recorded']=='false'
for key in ('attempt_receipt_sha256','test_executable_sha256','build_record_sha256','rustc_sha256','cargo_sha256',
            'toolchain_tree_sha256','runner_sha256','terminal_collector_sha256','sealed_retry_verifier_sha256','backend_binary_sha256',
            'backend_unit_file_sha256','ca_sha256'):
    assert re.fullmatch(r'[0-9a-f]{64}',d[key]),(key,d[key])
for key in ('test_executable_device_inode_size','build_record_device_inode_size','rustc_device_inode_size',
            'cargo_device_inode_size','runner_device_inode_size','terminal_collector_device_inode_size','sealed_retry_verifier_device_inode_size',
            'backend_binary_device_inode_size','backend_unit_file_device_inode_size','ca_device_inode_size'):
    assert re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*',d[key]),(key,d[key])
open(output,'x').write('\n'.join(f'{key}={d[key]}' for key in (
'run_id','attempt_receipt_sha256','supervisor_unit','supervisor_cgroup','supervisor_invocation_id',
'evidence_root_device_inode',
'terminal_collector_sha256','terminal_collector_device_inode_size','backend_unit','backend_main_pid',
'backend_pid_start_time_ticks','backend_linux_boot_id','backend_invocation_id','backend_cgroup',
'backend_fragment_path','backend_executable_device_inode','backend_listener_socket_inode',
'backend_binary_sha256','backend_binary_device_inode_size','backend_unit_file_sha256',
'backend_unit_file_device_inode_size','endpoint_origin','region','bucket','prefix','ca_sha256',
'ca_device_inode_size'))+'\n')
PY
chmod 0600 "$TERMINAL/preflight-selection"
sync -f "$TERMINAL/preflight-selection"
sync -f "$TERMINAL"
field() { awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2) }' "$TERMINAL/preflight-selection"; }
INVOCATION_ID=$(field supervisor_invocation_id)
SUPERVISOR_CGROUP=$(field supervisor_cgroup)
EXPECTED_HASH=$(field terminal_collector_sha256)
[[ $(field evidence_root_device_inode) == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
[[ $COLLECTOR_SHA == "$EXPECTED_HASH" ]]
[[ $(stat -Lc '%d:%i:%s' "$COLLECTOR_FD_PATH") == "$(field terminal_collector_device_inode_size)" ]]
[[ $(stat -Lc '%d:%i:%s' "$COLLECTOR") == "$(field terminal_collector_device_inode_size)" ]]
[[ $(sha256sum "$COLLECTOR_ATTEMPT_FD_PATH" | cut -d' ' -f1) == "$COLLECTOR_ATTEMPT_SHA" ]]
[[ $(stat -Lc '%d:%i:%s' "$COLLECTOR_ATTEMPT_FD_PATH") == "$COLLECTOR_ATTEMPT_IDENTITY" ]]
[[ $(stat -Lc '%d:%i:%s' "$COLLECTOR_ATTEMPT") == "$COLLECTOR_ATTEMPT_IDENTITY" ]]
python3 - "$COLLECTOR_ATTEMPT_FD_PATH" "$RUN_ID" "$$" "$COLLECTOR_START" "$COLLECTOR_BOOT" "$COLLECTOR_SHA" "$COLLECTOR_IDENTITY" "$EVIDENCE_ROOT_DEVICE_INODE" <<'PY'
import re,sys
path,run,pid,start,boot,digest,identity,evidence=sys.argv[1:]
expected={'schema','run_id','collector_pid','collector_pid_start_time_ticks','linux_boot_id',
          'collector_sha256','collector_device_inode_size','evidence_root_device_inode','attempted_at_utc'}
values={}; raw=open(path,'rb').read(); text=raw.decode(); assert text.endswith('\n')
for line in text.splitlines():
    key,value=line.split('=',1); assert key in expected and key not in values and value and '=' not in value
    values[key]=value
assert set(values)==expected and values['schema']=='1' and values['run_id']==run
assert values['collector_pid']==pid and values['collector_pid_start_time_ticks']==start
assert values['linux_boot_id']==boot and values['collector_sha256']==digest
assert values['collector_device_inode_size']==identity
assert values['evidence_root_device_inode']==evidence
assert re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',values['attempted_at_utc'])
PY
[[ $RUN_ATTEMPT_SHA == "$(field attempt_receipt_sha256)" ]]
CA_FILE=$(readlink -f "$SSL_CERT_FILE")
exec {CA_FD}<"$CA_FILE"
CA_FD_PATH="/proc/self/fd/$CA_FD"
[[ $(sha256sum "$CA_FD_PATH" | cut -d' ' -f1) == "$(field ca_sha256)" ]]
[[ $(stat -Lc '%d:%i:%s' "$CA_FD_PATH") == "$(field ca_device_inode_size)" ]]
[[ $(stat -Lc '%d:%i:%s' "$CA_FILE") == "$(field ca_device_inode_size)" ]]
export SSL_CERT_FILE=$CA_FD_PATH
[[ $AWS_DEFAULT_REGION == "$(field region)" ]]
[[ $RHIZOME_BARRIER_S3_BUCKET == "$(field bucket)" ]]

BACKEND_PID=$(field backend_main_pid)
[[ $BACKEND_PID =~ ^[1-9][0-9]*$ ]]
[[ $(tr -d '\n' </proc/sys/kernel/random/boot_id) == "$(field backend_linux_boot_id)" ]]
BACKEND_START=$(python3 - "$BACKEND_PID" <<'PY'
import sys
text=open(f'/proc/{sys.argv[1]}/stat').read()
print(text[text.rfind(')') + 2:].split()[19])
PY
)
[[ $BACKEND_START == "$(field backend_pid_start_time_ticks)" ]]
[[ $(awk -F: '$1 == "0" { print $3 }' "/proc/$BACKEND_PID/cgroup") == "$(field backend_cgroup)" ]]
[[ $(systemctl show "$(field backend_unit)" -p MainPID --value) == "$BACKEND_PID" ]]
[[ $(systemctl show "$(field backend_unit)" -p InvocationID --value) == "$(field backend_invocation_id)" ]]
[[ $(systemctl show "$(field backend_unit)" -p ControlGroup --value) == "$(field backend_cgroup)" ]]
[[ $(systemctl show "$(field backend_unit)" -p FragmentPath --value) == "$(field backend_fragment_path)" ]]
exec {BACKEND_EXE_FD}<"/proc/$BACKEND_PID/exe"
BACKEND_EXE_FD_PATH="/proc/self/fd/$BACKEND_EXE_FD"
[[ $(stat -Lc '%d:%i' "$BACKEND_EXE_FD_PATH") == "$(field backend_executable_device_inode)" ]]
[[ $(stat -Lc '%d:%i:%s' "$BACKEND_EXE_FD_PATH") == "$(field backend_binary_device_inode_size)" ]]
[[ $(sha256sum "$BACKEND_EXE_FD_PATH" | cut -d' ' -f1) == "$(field backend_binary_sha256)" ]]
BACKEND_FRAGMENT=$(field backend_fragment_path)
exec {BACKEND_UNIT_FD}<"$BACKEND_FRAGMENT"
BACKEND_UNIT_FD_PATH="/proc/self/fd/$BACKEND_UNIT_FD"
[[ $(stat -Lc '%d:%i:%s' "$BACKEND_UNIT_FD_PATH") == "$(field backend_unit_file_device_inode_size)" ]]
[[ $(sha256sum "$BACKEND_UNIT_FD_PATH" | cut -d' ' -f1) == "$(field backend_unit_file_sha256)" ]]
python3 - "$BACKEND_PID" "$(field backend_listener_socket_inode)" <<'PY'
import os,sys
pid,inode=sys.argv[1:]; owners=[]
for proc in os.listdir('/proc'):
    if not proc.isdigit(): continue
    try: names=os.listdir(f'/proc/{proc}/fd')
    except (FileNotFoundError,PermissionError): continue
    for name in names:
        try: target=os.readlink(f'/proc/{proc}/fd/{name}')
        except (FileNotFoundError,PermissionError): continue
        if target==f'socket:[{inode}]': owners.append((proc,name))
assert owners and {owner for owner,_ in owners}=={pid},owners
PY
python3 - "$RUN_ROOT" "$EVIDENCE_ROOT" "$TERMINAL" "$COLLECTOR" "$CA_FILE" "$BACKEND_FRAGMENT" <<'PY'
import os,stat,sys
for path in sys.argv[1:]:
    assert os.path.isabs(path) and os.path.realpath(path)==path
    current='/'
    for part in (part for part in path.split('/') if part):
        current=os.path.join(current,part); info=os.lstat(current)
        assert info.st_uid==0 and info.st_gid==0 and info.st_mode & 0o022 == 0
        assert not stat.S_ISLNK(info.st_mode)
    final=os.lstat(path)
    if stat.S_ISREG(final.st_mode): assert final.st_nlink==1
    else: assert stat.S_ISDIR(final.st_mode)
PY

journalctl -u "$UNIT" --no-pager -o json >"$TERMINAL/unit-journal.jsonl"
journalctl _SYSTEMD_INVOCATION_ID="$INVOCATION_ID" --no-pager -o json >"$TERMINAL/invocation-journal.jsonl"
python3 - "$TERMINAL/unit-journal.jsonl" "$TERMINAL/invocation-journal.jsonl" "$UNIT" "$INVOCATION_ID" "$SUPERVISOR_CGROUP" "$RUN_ID" "$PREFLIGHT_FD_PATH" "$TERMINAL/journal-validation" <<'PY'
import json,sys
unit_path,inv_path,unit,inv,cgroup,run,preflight,output=sys.argv[1:]
unit_rows=[json.loads(line) for line in open(unit_path) if line.strip()]
inv_rows=[json.loads(line) for line in open(inv_path) if line.strip()]
assert unit_rows and inv_rows
seen=set()
for row in unit_rows:
    for key in ('_SYSTEMD_INVOCATION_ID','INVOCATION_ID'):
        if row.get(key): seen.add(row[key])
assert seen=={inv},seen
assert all(row.get('_SYSTEMD_INVOCATION_ID')==inv for row in inv_rows)
assert all(row.get('_SYSTEMD_UNIT')==unit for row in inv_rows)
import hashlib
preflight_sha=hashlib.sha256(open(preflight,'rb').read()).hexdigest()
start=f'RHIZOME_BARRIER_RUNNER_START run_id={run} invocation_id={inv} cgroup={cgroup} preflight_sha256={preflight_sha}'
end=f'RHIZOME_BARRIER_RUNNER_END run_id={run} invocation_id={inv} cgroup={cgroup} exit_code=0'
starts=[row for row in inv_rows if row.get('MESSAGE')==start]
ends=[row for row in inv_rows if row.get('MESSAGE')==end]
assert len(starts)==1,starts
assert len(ends)==1,ends
assert int(starts[0]['__MONOTONIC_TIMESTAMP']) < int(ends[0]['__MONOTONIC_TIMESTAMP'])
open(output,'x').write(f'schema=1\nunit={unit}\ninvocation_id={inv}\ncgroup={cgroup}\nunit_rows={len(unit_rows)}\ninvocation_rows={len(inv_rows)}\nrunner_start_records=1\nrunner_end_records=1\n')
PY

UNIT_STATE=$(systemctl show "$UNIT" -p LoadState --value 2>/dev/null || printf not-found)
[[ $UNIT_STATE == not-found ]]
[[ ! -e "/sys/fs/cgroup$SUPERVISOR_CGROUP" ]]
[[ $(cat "$EVIDENCE_ROOT/exit-code") == 0 ]]
python3 - "$RUN_ROOT" "$PREFLIGHT_FD_PATH" "$SUPERVISOR_CGROUP" <<'PY'
import hashlib,os,re,stat,sys,uuid
root,preflight,cgroup=sys.argv[1:]
preflight_sha=hashlib.sha256(open(preflight,'rb').read()).hexdigest()
scenarios=['before-data-cut','after-0x0d-apply','manifest-applied-before-response','after-manifest-publish']
expected={f'{scenario}.{suffix}' for scenario in scenarios for suffix in ('context','claim','handshake','exit','recovery')}
actual=set(os.listdir(root)); assert actual==expected,(actual,expected)
for name in actual:
    info=os.lstat(os.path.join(root,name))
    assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0
    assert stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
def record(name, fields):
    raw=open(os.path.join(root,name),'rb').read(); assert raw.endswith(b'\n')
    result={}
    for line in raw.decode().splitlines():
        key,value=line.split('=',1)
        assert key in fields and key not in result and value and '=' not in value,(name,key)
        result[key]=value
    assert set(result)==set(fields),(name,set(result),set(fields))
    return result,raw
context_fields=('schema','run_id','scenario','context_payload_hex','context_payload_sha256')
claim_fields=('schema','scenario','context_record_digest','request_digest','barrier_id','effect_claim_hex',
              'effect_claim_digest','included_write_sequence')
handshake_fields=('schema','run_id','scenario','point','pid','preflight_receipt_sha256','context_record_digest',
                  'request_digest','barrier_id','effect_claim_digest','claim_record_digest',
                  'included_write_sequence','receipt_digest')
exit_fields=('schema','run_id','scenario','pid','pid_start_time_ticks','linux_boot_id','signal',
             'joined_at_unix_seconds','joined_at_unix_nanos','joined_at_boot_millis','supervisor_unit',
             'supervisor_cgroup','preflight_receipt_sha256','context_record_digest','request_digest','barrier_id',
             'effect_claim_digest','claim_record_digest','handshake_digest','included_write_sequence','receipt_digest')
recovery_fields=('schema','run_id','scenario','recovery_pid','recovery_pid_start_time_ticks',
                 'recovery_linux_boot_id','recovery_cgroup','preflight_receipt_sha256','context_record_digest',
                 'request_digest','barrier_id','effect_claim_digest','claim_record_digest','handshake_digest',
                 'exit_receipt_digest','outcome','included_write_sequence','receipt_digest','payload','recovery_puts')
run=os.path.basename(root); assert uuid.UUID(run).version==4 and str(uuid.UUID(run))==run
hex64=lambda value: bool(re.fullmatch(r'[0-9a-f]{64}',value))
boot=open('/proc/sys/kernel/random/boot_id').read().strip()
for scenario in scenarios:
    context,context_raw=record(scenario+'.context',context_fields)
    claim,claim_raw=record(scenario+'.claim',claim_fields)
    handshake,handshake_raw=record(scenario+'.handshake',handshake_fields)
    values,exit_raw=record(scenario+'.exit',exit_fields)
    recovery,_=record(scenario+'.recovery',recovery_fields)
    assert context['schema']=='1' and context['run_id']==run and context['scenario']==scenario
    assert context['context_payload_hex'] and len(context['context_payload_hex'])<=262144 and len(context['context_payload_hex'])%2==0
    assert re.fullmatch(r'[0-9a-f]+',context['context_payload_hex'])
    assert hex64(context['context_payload_sha256'])
    assert hashlib.sha256(bytes.fromhex(context['context_payload_hex'])).hexdigest()==context['context_payload_sha256']
    assert claim['schema']=='1' and claim['scenario']==scenario and claim['included_write_sequence']=='1'
    assert claim['context_record_digest']==hashlib.sha256(context_raw).hexdigest()
    assert hex64(claim['request_digest']) and hex64(claim['effect_claim_digest'])
    assert claim['effect_claim_hex'] and len(claim['effect_claim_hex'])<=262144 and len(claim['effect_claim_hex'])%2==0
    assert re.fullmatch(r'[0-9a-f]+',claim['effect_claim_hex'])
    assert hashlib.sha256(bytes.fromhex(claim['effect_claim_hex'])).hexdigest()==claim['effect_claim_digest']
    assert uuid.UUID(claim['barrier_id']).version==4 and str(uuid.UUID(claim['barrier_id']))==claim['barrier_id']
    assert handshake['schema']=='1' and handshake['run_id']==run and handshake['scenario']==scenario
    assert handshake['point']==scenario and handshake['included_write_sequence']=='1'
    assert handshake['preflight_receipt_sha256']==preflight_sha
    assert handshake['context_record_digest']==claim['context_record_digest']
    assert handshake['request_digest']==claim['request_digest']
    assert handshake['barrier_id']==claim['barrier_id']
    assert handshake['effect_claim_digest']==claim['effect_claim_digest']
    assert handshake['claim_record_digest']==hashlib.sha256(claim_raw).hexdigest()
    assert values['schema']=='1' and values['run_id']==run and values['scenario']==scenario
    assert values['signal']=='9' and values['preflight_receipt_sha256']==preflight_sha
    assert values['supervisor_unit']==f'zerofs-barrier-fault-{run}.service'
    assert values['supervisor_cgroup']==cgroup and values['linux_boot_id']==boot
    assert values['context_record_digest']==handshake['context_record_digest']
    assert values['pid']==handshake['pid'] and int(values['pid'])>1
    assert values['request_digest']==handshake['request_digest']
    assert values['barrier_id']==handshake['barrier_id']
    assert values['effect_claim_digest']==handshake['effect_claim_digest']
    assert values['claim_record_digest']==handshake['claim_record_digest']
    assert values['handshake_digest']==hashlib.sha256(handshake_raw).hexdigest()
    assert values['included_write_sequence']=='1' and values['receipt_digest']==handshake['receipt_digest']
    assert int(values['pid_start_time_ticks'])>0 and int(values['joined_at_unix_seconds'])>0
    assert 0 <= int(values['joined_at_unix_nanos']) < 1_000_000_000
    assert int(values['joined_at_boot_millis']) >= int(values['pid_start_time_ticks'])*1000//os.sysconf('SC_CLK_TCK')
    assert not os.path.exists('/proc/'+values['pid'])
    assert recovery['schema']=='1' and recovery['run_id']==run and recovery['scenario']==scenario
    assert recovery['recovery_puts']=='0' and recovery['recovery_linux_boot_id']==boot
    assert recovery['recovery_cgroup']==cgroup and int(recovery['recovery_pid'])>1
    assert int(recovery['recovery_pid_start_time_ticks'])>0
    assert not os.path.exists('/proc/'+recovery['recovery_pid'])
    assert recovery['preflight_receipt_sha256']==preflight_sha
    assert recovery['context_record_digest']==claim['context_record_digest']
    assert recovery['request_digest']==claim['request_digest']
    assert recovery['barrier_id']==claim['barrier_id']
    assert recovery['effect_claim_digest']==claim['effect_claim_digest']
    assert recovery['claim_record_digest']==handshake['claim_record_digest']
    assert recovery['handshake_digest']==hashlib.sha256(handshake_raw).hexdigest()
    assert recovery['exit_receipt_digest']==hashlib.sha256(exit_raw).hexdigest()
    if scenario=='before-data-cut':
        assert values['receipt_digest']=='none'
        assert recovery['outcome']=='unknown' and recovery['included_write_sequence']=='0'
        assert recovery['receipt_digest']=='none' and recovery['payload']=='absent'
    elif scenario=='after-0x0d-apply':
        assert hex64(values['receipt_digest'])
        assert recovery['outcome']=='unknown' and recovery['included_write_sequence']=='0'
        assert recovery['receipt_digest']=='none' and recovery['payload']=='durable'
    else:
        assert hex64(values['receipt_digest'])
        assert recovery['outcome']=='materialized' and recovery['included_write_sequence']=='1'
        assert recovery['receipt_digest']==values['receipt_digest'] and recovery['payload']=='durable'
PY

python3 - "$RUN_ID" "$TERMINAL/post-terminal-inventory" <<'PY'
import os,sys,boto3
from botocore.config import Config
run,output=sys.argv[1:]
c=boto3.client('s3',endpoint_url='https://127.0.0.1:19000',region_name=os.environ['AWS_DEFAULT_REGION'],verify=os.environ['SSL_CERT_FILE'],config=Config(s3={'addressing_style':'path'}))
base=f'rhizome/zerofs-barrier-fault/{run}'; rows=['schema=1']
for prefix in [base]+[f'{base}/{s}' for s in ('before-data-cut','after-0x0d-apply','manifest-applied-before-response','after-manifest-publish')]:
    objects=[]; total=0
    for page in c.get_paginator('list_objects_v2').paginate(Bucket=os.environ['RHIZOME_BARRIER_S3_BUCKET'],Prefix=prefix+'/'):
        for item in page.get('Contents',[]): objects.append(item['Key']); total+=item['Size']
    assert not objects
    rows.extend((f'{prefix}.objects=0',f'{prefix}.bytes={total}',f'{prefix}.empty=true'))
open(output,'x').write('\n'.join(rows)+'\n')
PY

# Close every stable input and backend generation after the final S3 read.
[[ $(stat -Lc '%d:%i' "$COLLECTOR_OWNER_FD_PATH") == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
[[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT") == "$EVIDENCE_ROOT_DEVICE_INODE" ]]
[[ $(sha256sum "$COLLECTOR_FD_PATH" | cut -d' ' -f1) == "$EXPECTED_HASH" ]]
[[ $(stat -Lc '%d:%i:%s' "$COLLECTOR_FD_PATH") == "$(field terminal_collector_device_inode_size)" ]]
[[ $(stat -Lc '%d:%i:%s' "$COLLECTOR") == "$(field terminal_collector_device_inode_size)" ]]
[[ $(stat -Lc '%d:%i:%s' "$PREFLIGHT_FD_PATH") == "$PREFLIGHT_IDENTITY" ]]
[[ $(stat -Lc '%d:%i:%s' "$EVIDENCE_ROOT/preflight.receipt") == "$PREFLIGHT_IDENTITY" ]]
[[ $(stat -Lc '%d:%i:%s' "$RUN_ATTEMPT_FD_PATH") == "$RUN_ATTEMPT_IDENTITY" ]]
[[ $(stat -Lc '%d:%i:%s' "$EVIDENCE_ROOT/attempt.receipt") == "$RUN_ATTEMPT_IDENTITY" ]]
[[ $(sha256sum "$RUN_ATTEMPT_FD_PATH" | cut -d' ' -f1) == "$RUN_ATTEMPT_SHA" ]]
[[ $(sha256sum "$CA_FD_PATH" | cut -d' ' -f1) == "$(field ca_sha256)" ]]
[[ $(stat -Lc '%d:%i:%s' "$CA_FD_PATH") == "$(field ca_device_inode_size)" ]]
[[ $(stat -Lc '%d:%i:%s' "$CA_FILE") == "$(field ca_device_inode_size)" ]]
[[ $(systemctl show "$(field backend_unit)" -p MainPID --value) == "$BACKEND_PID" ]]
[[ $(systemctl show "$(field backend_unit)" -p InvocationID --value) == "$(field backend_invocation_id)" ]]
[[ $(systemctl show "$(field backend_unit)" -p ControlGroup --value) == "$(field backend_cgroup)" ]]
[[ $(systemctl show "$(field backend_unit)" -p FragmentPath --value) == "$BACKEND_FRAGMENT" ]]
[[ $(stat -Lc '%d:%i' "/proc/$BACKEND_PID/exe") == "$(field backend_executable_device_inode)" ]]
[[ $(stat -Lc '%d:%i:%s' "$BACKEND_EXE_FD_PATH") == "$(field backend_binary_device_inode_size)" ]]
[[ $(sha256sum "$BACKEND_EXE_FD_PATH" | cut -d' ' -f1) == "$(field backend_binary_sha256)" ]]
[[ $(stat -Lc '%d:%i:%s' "$BACKEND_UNIT_FD_PATH") == "$(field backend_unit_file_device_inode_size)" ]]
[[ $(stat -Lc '%d:%i:%s' "$BACKEND_FRAGMENT") == "$(field backend_unit_file_device_inode_size)" ]]
[[ $(sha256sum "$BACKEND_UNIT_FD_PATH" | cut -d' ' -f1) == "$(field backend_unit_file_sha256)" ]]
python3 - "$BACKEND_PID" "$(field backend_listener_socket_inode)" <<'PY'
import os,sys
pid,inode=sys.argv[1:]; owners=[]
for proc in os.listdir('/proc'):
    if not proc.isdigit(): continue
    try: names=os.listdir(f'/proc/{proc}/fd')
    except (FileNotFoundError,PermissionError): continue
    for name in names:
        try: target=os.readlink(f'/proc/{proc}/fd/{name}')
        except (FileNotFoundError,PermissionError): continue
        if target==f'socket:[{inode}]': owners.append((proc,name))
assert owners and {owner for owner,_ in owners}=={pid},owners
PY

cd "$EVIDENCE_ROOT"
sha256sum -c SHA256SUMS >"$TERMINAL/pre-exit-manifest-check"
sha256sum -c RUN-SHA256SUMS >"$TERMINAL/run-manifest-check"
if grep -R -F -q -- "$AWS_ACCESS_KEY_ID" "$EVIDENCE_ROOT" "$RUN_ROOT" || \
   grep -R -F -q -- "$AWS_SECRET_ACCESS_KEY" "$EVIDENCE_ROOT" "$RUN_ROOT"
then
    echo "credential material detected in terminal evidence" >&2
    exit 126
fi
find "$TERMINAL" -maxdepth 1 -type f -exec chmod 0600 {} \; -exec sync -f {} \;
sync -f "$TERMINAL"

cat >"$TERMINAL/receipt.pending" <<EOF
schema=1
run_id=$RUN_ID
evidence_root_device_inode=$EVIDENCE_ROOT_DEVICE_INODE
invocation_id=$INVOCATION_ID
unit=$UNIT
unit_load_state=$UNIT_STATE
supervisor_cgroup=$SUPERVISOR_CGROUP
cgroup_absent=true
surviving_run_processes=0
scenario_exit_receipts=4
verdict=BEHAVIOR_PASS_AWAITING_FINAL_SEAL
runner_exit=$(cat "$EVIDENCE_ROOT/exit-code")
preflight_receipt_sha256=$(sha256sum "$PREFLIGHT_FD_PATH" | cut -d' ' -f1)
pre_exit_manifest_sha256=$(sha256sum "$EVIDENCE_ROOT/SHA256SUMS" | cut -d' ' -f1)
run_manifest_sha256=$(sha256sum "$EVIDENCE_ROOT/RUN-SHA256SUMS" | cut -d' ' -f1)
collector_sha256=$EXPECTED_HASH
collector_attempt_receipt_sha256=$COLLECTOR_ATTEMPT_SHA
collected_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
chmod 0600 "$TERMINAL/receipt.pending"
sync -f "$TERMINAL/receipt.pending"
ln "$TERMINAL/receipt.pending" "$TERMINAL/receipt"
sync -f "$TERMINAL"
unlink "$TERMINAL/receipt.pending"
sync -f "$TERMINAL"
printf 'PASS\n' >"$TERMINAL/status-pass.receipt.pending"
chmod 0600 "$TERMINAL/status-pass.receipt.pending"
sync -f "$TERMINAL/status-pass.receipt.pending"
ln "$TERMINAL/status-pass.receipt.pending" "$TERMINAL/status-pass.receipt"
sync -f "$TERMINAL"
unlink "$TERMINAL/status-pass.receipt.pending"
sync -f "$TERMINAL"
find "$TERMINAL" -maxdepth 1 -type f ! -name SHA256SUMS ! -name '*.pending' -print0 | sort -z | xargs -0 sha256sum >"$TERMINAL/SHA256SUMS"
chmod 0600 "$TERMINAL/SHA256SUMS"
sync -f "$TERMINAL/SHA256SUMS"
sync -f "$TERMINAL"
python3 - "$EVIDENCE_ROOT" "$TERMINAL" "$RUN_ROOT" <<'PY'
import os,stat,sys
evidence,terminal,run=sys.argv[1:]
expected_evidence={'attempt.receipt','preflight.receipt','toolchain-tree.sha256','test.log','exit-code',
                   'status','RUN-SHA256SUMS','SHA256SUMS','collector-attempt.receipt','terminal'}
actual_evidence=set(os.listdir(evidence)); assert actual_evidence==expected_evidence,(actual_evidence,expected_evidence)
expected_terminal={'preflight-selection','unit-journal.jsonl','invocation-journal.jsonl','journal-validation',
                   'post-terminal-inventory','pre-exit-manifest-check','run-manifest-check','receipt',
                   'status-pass.receipt','SHA256SUMS'}
actual_terminal=set(os.listdir(terminal)); assert actual_terminal==expected_terminal,(actual_terminal,expected_terminal)
for root in (evidence,terminal,run):
    for current,dirs,files in os.walk(root,followlinks=False):
        assert not any(name.endswith('.pending') for name in dirs+files),(current,dirs,files)
        for name in dirs+files:
            info=os.lstat(os.path.join(current,name)); assert not stat.S_ISLNK(info.st_mode)
PY
[[ $(cat "$EVIDENCE_ROOT/status") == BEHAVIOR_PASS_AWAITING_TERMINAL_COLLECTION ]]
cd "$EVIDENCE_ROOT"
find . -type f ! -name status ! -name FINAL-SHA256SUMS ! -name 'FINAL-SHA256SUMS.pending' \
    ! -name FINAL-SEAL.receipt ! -name 'FINAL-SEAL.receipt.pending' -print0 | \
    sort -z | xargs -0 sha256sum >FINAL-SHA256SUMS.pending
chmod 0600 FINAL-SHA256SUMS.pending
sync -f FINAL-SHA256SUMS.pending
ln FINAL-SHA256SUMS.pending FINAL-SHA256SUMS
sync -f "$EVIDENCE_ROOT"
unlink FINAL-SHA256SUMS.pending
sync -f "$EVIDENCE_ROOT"
sha256sum -c FINAL-SHA256SUMS >/dev/null
FINAL_MANIFEST_SHA=$(sha256sum FINAL-SHA256SUMS | cut -d' ' -f1)
STATUS_PASS_SHA=$(sha256sum "$TERMINAL/status-pass.receipt" | cut -d' ' -f1)
TERMINAL_MANIFEST_SHA=$(sha256sum "$TERMINAL/SHA256SUMS" | cut -d' ' -f1)
cat >FINAL-SEAL.receipt.pending <<EOF
schema=1
run_id=$RUN_ID
verdict=SEALED_AWAITING_STATUS
evidence_root_device_inode=$EVIDENCE_ROOT_DEVICE_INODE
mode_profile=root-read-only-v1
final_manifest_sha256=$FINAL_MANIFEST_SHA
final_manifest_readback=verified
terminal_manifest_sha256=$TERMINAL_MANIFEST_SHA
status_pass_receipt_sha256=$STATUS_PASS_SHA
collector_attempt_receipt_sha256=$COLLECTOR_ATTEMPT_SHA
EOF
chmod 0600 FINAL-SEAL.receipt.pending
sync -f FINAL-SEAL.receipt.pending
ln FINAL-SEAL.receipt.pending FINAL-SEAL.receipt
sync -f "$EVIDENCE_ROOT"
unlink FINAL-SEAL.receipt.pending
sync -f "$EVIDENCE_ROOT"
python3 - FINAL-SEAL.receipt "$RUN_ID" "$EVIDENCE_ROOT_DEVICE_INODE" "$FINAL_MANIFEST_SHA" "$TERMINAL_MANIFEST_SHA" "$STATUS_PASS_SHA" "$COLLECTOR_ATTEMPT_SHA" <<'PY'
import sys
path,run,evidence,manifest,terminal,status,attempt=sys.argv[1:]
expected={'schema','run_id','verdict','evidence_root_device_inode','mode_profile','final_manifest_sha256','final_manifest_readback',
          'terminal_manifest_sha256','status_pass_receipt_sha256','collector_attempt_receipt_sha256'}
values={}; raw=open(path,'rb').read(); text=raw.decode(); assert text.endswith('\n')
for line in text.splitlines():
    key,value=line.split('=',1); assert key in expected and key not in values and value and '=' not in value
    values[key]=value
assert set(values)==expected
assert values=={'schema':'1','run_id':run,'verdict':'SEALED_AWAITING_STATUS','evidence_root_device_inode':evidence,
                'mode_profile':'root-read-only-v1','final_manifest_sha256':manifest,
                'final_manifest_readback':'verified','terminal_manifest_sha256':terminal,
                'status_pass_receipt_sha256':status,'collector_attempt_receipt_sha256':attempt}
PY
find "$RUN_ROOT" -type f -exec chmod 0400 {} \;
find "$EVIDENCE_ROOT" -type f -exec chmod 0400 {} \;
find "$RUN_ROOT" "$TERMINAL" -type d -exec chmod 0500 {} \;
sync -f "$RUN_ROOT"
sync -f "$TERMINAL"
ln "$TERMINAL/status-pass.receipt" "$EVIDENCE_ROOT/status.pass.pending"
sync -f "$EVIDENCE_ROOT"
[[ $(cat "$EVIDENCE_ROOT/status.pass.pending") == PASS ]]
[[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT/status.pass.pending") == "$(stat -Lc '%d:%i' "$TERMINAL/status-pass.receipt")" ]]
python3 - "$RUN_ROOT" "$EVIDENCE_ROOT" "$TERMINAL" <<'PY'
import os,stat,sys
run,evidence,terminal=sys.argv[1:]
for root in (run,evidence):
    for current,dirs,files in os.walk(root,followlinks=False):
        for name in files:
            path=os.path.join(current,name); info=os.lstat(path)
            assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o400
            expected_links=2 if path in (os.path.join(terminal,'status-pass.receipt'),
                                         os.path.join(evidence,'status.pass.pending')) else 1
            assert info.st_uid==0 and info.st_gid==0 and info.st_nlink==expected_links
for path in (run,terminal):
    info=os.lstat(path); assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o500
    assert info.st_uid==0 and info.st_gid==0
assert stat.S_IMODE(os.lstat(evidence).st_mode)==0o700
PY
chmod 0500 "$EVIDENCE_ROOT"
sync -f "$EVIDENCE_ROOT"
mv -T "$EVIDENCE_ROOT/status.pass.pending" "$EVIDENCE_ROOT/status"
sync -f "$EVIDENCE_ROOT"
