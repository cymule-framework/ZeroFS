#!/usr/bin/env bash
set -euo pipefail

[[ $(id -u) == 0 ]] || { echo "sealed-retry verifier must execute as root" >&2; exit 2; }
[[ $# == 3 ]] || { echo "usage: $0 RUN_ID RUNNER COLLECTOR" >&2; exit 2; }
RUN_ID=$1
python3 - "$RUN_ID" <<'PY'
import sys,uuid
value=uuid.UUID(sys.argv[1]); assert value.version==4 and str(value)==sys.argv[1]
PY

RUN_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/runs/$RUN_ID"
EVIDENCE_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/evidence/$RUN_ID"
RUNNER=$(readlink -f "$2")
COLLECTOR=$(readlink -f "$3")
SELF=$(readlink -f "$0")
[[ $(stat -c '%a:%U:%G' "$RUN_ROOT") == 500:root:root ]]
[[ $(stat -c '%a:%U:%G' "$EVIDENCE_ROOT") == 500:root:root ]]
[[ $(cat "$EVIDENCE_ROOT/status") == PASS ]]
[[ -f $EVIDENCE_ROOT/FINAL-SEAL.receipt && -f $EVIDENCE_ROOT/FINAL-SHA256SUMS ]]
[[ $(find "$RUN_ROOT" "$EVIDENCE_ROOT" -name '*.pending' | wc -l) == 0 ]]
python3 - "$RUN_ROOT" "$EVIDENCE_ROOT" <<'PY'
import os,sys
run,evidence=sys.argv[1:]
scenarios=('before-data-cut','after-0x0d-apply','manifest-applied-before-response','after-manifest-publish')
expected_run={f'{scenario}.{suffix}' for scenario in scenarios for suffix in ('context','claim','handshake','exit','recovery')}
assert set(os.listdir(run))==expected_run
expected_evidence={'attempt.receipt','preflight.receipt','toolchain-tree.sha256','test.log','exit-code','status',
                   'RUN-SHA256SUMS','SHA256SUMS','collector-attempt.receipt','terminal',
                   'FINAL-SHA256SUMS','FINAL-SEAL.receipt'}
assert set(os.listdir(evidence))==expected_evidence
expected_terminal={'preflight-selection','unit-journal.jsonl','invocation-journal.jsonl','journal-validation',
                   'post-terminal-inventory','pre-exit-manifest-check','run-manifest-check','receipt',
                   'status-pass.receipt','SHA256SUMS'}
assert set(os.listdir(os.path.join(evidence,'terminal')))==expected_terminal
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
        assert info.st_uid==0 and info.st_gid==0 and info.st_mode & 0o022 == 0
        assert not stat.S_ISLNK(info.st_mode)
    final=os.lstat(path); assert stat.S_ISREG(final.st_mode) and final.st_nlink==1
PY

field() { awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2) }' "$PREFLIGHT_FD_PATH"; }
[[ $(sha256sum "$RUNNER_FD_PATH" | cut -d' ' -f1) == "$(field runner_sha256)" ]]
[[ $(sha256sum "$COLLECTOR_FD_PATH" | cut -d' ' -f1) == "$(field terminal_collector_sha256)" ]]
[[ $(sha256sum "$SELF_FD_PATH" | cut -d' ' -f1) == "$(field sealed_retry_verifier_sha256)" ]]
[[ $(field evidence_root_device_inode) == "$(stat -Lc '%d:%i' "$EVIDENCE_ROOT")" ]]
(cd "$EVIDENCE_ROOT" && sha256sum -c FINAL-SHA256SUMS >/dev/null)
(cd "$EVIDENCE_ROOT/terminal" && sha256sum -c SHA256SUMS >/dev/null)
[[ $(stat -Lc '%d:%i' "$EVIDENCE_ROOT/status") == "$(stat -Lc '%d:%i' "$EVIDENCE_ROOT/terminal/status-pass.receipt")" ]]
python3 - "$EVIDENCE_ROOT/FINAL-SEAL.receipt" "$RUN_ID" "$(stat -Lc '%d:%i' "$EVIDENCE_ROOT")" \
    "$(sha256sum "$EVIDENCE_ROOT/FINAL-SHA256SUMS" | cut -d' ' -f1)" \
    "$(sha256sum "$EVIDENCE_ROOT/terminal/SHA256SUMS" | cut -d' ' -f1)" \
    "$(sha256sum "$EVIDENCE_ROOT/terminal/status-pass.receipt" | cut -d' ' -f1)" \
    "$(sha256sum "$EVIDENCE_ROOT/collector-attempt.receipt" | cut -d' ' -f1)" <<'PY'
import sys
path,run,evidence,manifest,terminal,status,attempt=sys.argv[1:]
expected={'schema','run_id','verdict','evidence_root_device_inode','mode_profile','final_manifest_sha256',
          'final_manifest_readback','terminal_manifest_sha256','status_pass_receipt_sha256',
          'collector_attempt_receipt_sha256'}
values={}; raw=open(path,'rb').read(); text=raw.decode(); assert text.endswith('\n')
for line in text.splitlines():
    key,value=line.split('=',1); assert key in expected and key not in values and value and '=' not in value
    values[key]=value
assert set(values)==expected
assert values=={'schema':'1','run_id':run,'verdict':'PASS','evidence_root_device_inode':evidence,
                'mode_profile':'root-read-only-v1','final_manifest_sha256':manifest,
                'final_manifest_readback':'verified','terminal_manifest_sha256':terminal,
                'status_pass_receipt_sha256':status,'collector_attempt_receipt_sha256':attempt}
PY

WORK_ROOT=$(mktemp -d "/run/zerofs-barrier-sealed-retry-$RUN_ID.XXXXXX")
cleanup() {
    local code=$?
    rm -f "$WORK_ROOT/before" "$WORK_ROOT/after" "$WORK_ROOT/runner.log" "$WORK_ROOT/collector.log"
    rmdir "$WORK_ROOT"
    exit "$code"
}
trap cleanup EXIT

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
            info=os.lstat(path); kind='dir' if stat.S_ISDIR(info.st_mode) else 'file'
            digest='-'
            if kind=='file':
                assert stat.S_IMODE(info.st_mode)==0o400 and info.st_uid==0 and info.st_gid==0
                expected_links=2 if path in (os.path.join(sys.argv[2],'status'),
                                             os.path.join(sys.argv[2],'terminal','status-pass.receipt')) else 1
                assert info.st_nlink==expected_links
                with open(path,'rb') as source: digest=hashlib.sha256(source.read()).hexdigest()
            else:
                assert stat.S_IMODE(info.st_mode)==0o500 and info.st_uid==0 and info.st_gid==0
            print('|'.join((path,kind,oct(stat.S_IMODE(info.st_mode)),str(info.st_uid),str(info.st_gid),
                            str(info.st_nlink),str(info.st_dev),str(info.st_ino),str(info.st_size),digest)))
PY
}

inventory "$WORK_ROOT/before"
set +e
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    RHIZOME_BARRIER_FAULT_RUN_ID="$RUN_ID" \
    RHIZOME_BARRIER_FAULT_RUN_ROOT="$RUN_ROOT" \
    RHIZOME_BARRIER_FAULT_EVIDENCE_ROOT="$EVIDENCE_ROOT" \
    "$RUNNER_FD_PATH" >"$WORK_ROOT/runner.log" 2>&1
RUNNER_EXIT=$?
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    "$COLLECTOR_FD_PATH" "$RUN_ID" >"$WORK_ROOT/collector.log" 2>&1
COLLECTOR_EXIT=$?
set -e
[[ $RUNNER_EXIT != 0 && $COLLECTOR_EXIT != 0 ]]
inventory "$WORK_ROOT/after"
cmp -s "$WORK_ROOT/before" "$WORK_ROOT/after"

printf 'schema=1\nrun_id=%s\nverdict=PASS\nrunner_retry_exit=%s\ncollector_retry_exit=%s\nsealed_tree_unchanged=true\nverifier_sha256=%s\n' \
    "$RUN_ID" "$RUNNER_EXIT" "$COLLECTOR_EXIT" "$(sha256sum "$SELF_FD_PATH" | cut -d' ' -f1)"
