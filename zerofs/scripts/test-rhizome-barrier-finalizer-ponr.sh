#!/usr/bin/env bash
set -euo pipefail

[[ $(id -u) == 0 ]] || { echo "finalizer PONR test must execute as root" >&2; exit 2; }
[[ ${RHIZOME_BARRIER_ALLOW_PONR_SELF_TEST:-} == 1 ]] || { echo "explicit PONR self-test opt-in is required" >&2; exit 2; }
[[ $# == 3 ]] || { echo "usage: $0 RUNNER COLLECTOR FINALIZER" >&2; exit 2; }
RUN_ID=$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)
BASE=/opt/rhizome/validation/zerofs-barrier-fault
RUN_ROOT="$BASE/runs/$RUN_ID"
EVIDENCE_ROOT="$BASE/evidence/$RUN_ID"
RETRY_PARENT="$BASE/retry-evidence"
SCRIPT_ROOT="$BASE/ponr-test-scripts-$RUN_ID"

cleanup() {
    local code=$?
    chmod -R u+rwX "$RUN_ROOT" "$EVIDENCE_ROOT" "$RETRY_PARENT/$RUN_ID" "$SCRIPT_ROOT" 2>/dev/null || true
    rm -rf -- "$RUN_ROOT" "$EVIDENCE_ROOT" "$RETRY_PARENT/${RUN_ID:?}" "$SCRIPT_ROOT"
    exit "$code"
}
trap cleanup EXIT

install -d -m 0755 -o root -g root /opt/rhizome /opt/rhizome/validation "$BASE"
install -d -m 0700 -o root -g root "$BASE/runs" "$BASE/evidence" "$RETRY_PARENT" "$SCRIPT_ROOT"
[[ ! -e $RUN_ROOT && ! -e $EVIDENCE_ROOT && ! -e $RETRY_PARENT/$RUN_ID ]]
mkdir -m 0700 "$RUN_ROOT" "$EVIDENCE_ROOT"
install -m 0755 -o root -g root "$1" "$SCRIPT_ROOT/runner"
install -m 0755 -o root -g root "$2" "$SCRIPT_ROOT/collector"
install -m 0755 -o root -g root "$3" "$SCRIPT_ROOT/finalizer"

python3 - "$RUN_ID" "$RUN_ROOT" "$EVIDENCE_ROOT" "$SCRIPT_ROOT/runner" "$SCRIPT_ROOT/collector" "$SCRIPT_ROOT/finalizer" <<'PY'
import hashlib,os,stat,sys
run,run_root,evidence,runner,collector,finalizer=sys.argv[1:]
terminal=os.path.join(evidence,'terminal'); os.mkdir(terminal,0o700)
scenarios=('before-data-cut','after-0x0d-apply','manifest-applied-before-response','after-manifest-publish')
for scenario in scenarios:
    for suffix in ('context','claim','handshake','exit','recovery'):
        open(os.path.join(run_root,f'{scenario}.{suffix}'),'xb').write(f'{scenario}:{suffix}\n'.encode())
def digest(path): return hashlib.sha256(open(path,'rb').read()).hexdigest()
def identity(path):
    info=os.stat(path); return f'{info.st_dev}:{info.st_ino}:{info.st_size}'
preflight=''.join((
    f'evidence_root_device_inode={os.stat(evidence).st_dev}:{os.stat(evidence).st_ino}\n',
    f'runner_sha256={digest(runner)}\nrunner_device_inode_size={identity(runner)}\n',
    f'terminal_collector_sha256={digest(collector)}\nterminal_collector_device_inode_size={identity(collector)}\n',
    f'sealed_retry_verifier_sha256={digest(finalizer)}\nsealed_retry_verifier_device_inode_size={identity(finalizer)}\n'))
base_files={'attempt.receipt':'attempt\n','preflight.receipt':preflight,'toolchain-tree.sha256':'toolchain\n',
            'test.log':'test\n','exit-code':'0\n','RUN-SHA256SUMS':'run-manifest\n',
            'SHA256SUMS':'pre-exit-manifest\n','collector-attempt.receipt':'collector-attempt\n'}
for name,value in base_files.items(): open(os.path.join(evidence,name),'x').write(value)
terminal_files={'preflight-selection':'selection\n','unit-journal.jsonl':'{}\n','invocation-journal.jsonl':'{}\n',
                'journal-validation':'journal\n','post-terminal-inventory':'inventory\n',
                'pre-exit-manifest-check':'pre-exit\n','run-manifest-check':'run\n','receipt':'receipt\n',
                'status-pass.receipt':'PASS\n',
                'status-sealed-awaiting-retry.receipt':'SEALED_AWAITING_RETRY_VERIFICATION\n'}
for name,value in terminal_files.items(): open(os.path.join(terminal,name),'x').write(value)
with open(os.path.join(terminal,'SHA256SUMS'),'x') as output:
    for name in sorted(terminal_files):
        path=os.path.join(terminal,name); output.write(f'{digest(path)}  {path}\n')
status_sealed=os.path.join(terminal,'status-sealed-awaiting-retry.receipt')
os.link(status_sealed,os.path.join(evidence,'status'))
excluded={'status','FINAL-SHA256SUMS','FINAL-SEAL.receipt'}
paths=[]
for current,dirs,files in os.walk(evidence):
    dirs.sort(); files.sort()
    for name in files:
        if name not in excluded: paths.append(os.path.join(current,name))
final_manifest=os.path.join(evidence,'FINAL-SHA256SUMS')
with open(final_manifest,'x') as output:
    for path in sorted(paths): output.write(f'{digest(path)}  {path}\n')
pass_path=os.path.join(terminal,'status-pass.receipt')
collector_attempt=os.path.join(evidence,'collector-attempt.receipt')
seal=(f'schema=1\nrun_id={run}\nverdict=SEALED_AWAITING_RETRY_VERIFICATION\n'
      f'evidence_root_device_inode={os.stat(evidence).st_dev}:{os.stat(evidence).st_ino}\n'
      f'mode_profile=root-read-only-v1\nfinal_manifest_sha256={digest(final_manifest)}\n'
      f'final_manifest_readback=verified\nterminal_manifest_sha256={digest(os.path.join(terminal,"SHA256SUMS"))}\n'
      f'status_pass_receipt_sha256={digest(pass_path)}\nstatus_sealed_receipt_sha256={digest(status_sealed)}\n'
      f'collector_attempt_receipt_sha256={digest(collector_attempt)}\n')
open(os.path.join(evidence,'FINAL-SEAL.receipt'),'x').write(seal)
for root in (run_root,evidence):
    for current,dirs,files in os.walk(root):
        for name in files: os.chmod(os.path.join(current,name),0o400)
        for name in dirs: os.chmod(os.path.join(current,name),0o500)
    os.chmod(root,0o500)
PY

# A same-inode, same-size locator rewrite must be rejected by content readback,
# even though every device/inode/size comparison still matches preflight.
RUNNER_IDENTITY=$(stat -Lc '%d:%i:%s' "$SCRIPT_ROOT/runner")
cp -p "$SCRIPT_ROOT/runner" "$SCRIPT_ROOT/runner.saved"
python3 - "$SCRIPT_ROOT/runner" <<'PY'
import os,sys
path=sys.argv[1]
with open(path,'r+b',buffering=0) as target:
    first=target.read(1); assert first
    target.seek(0); target.write(bytes([first[0]^1])); target.flush(); os.fsync(target.fileno())
PY
[[ $(stat -Lc '%d:%i:%s' "$SCRIPT_ROOT/runner") == "$RUNNER_IDENTITY" ]]
set +e
"$SCRIPT_ROOT/finalizer" "$RUN_ID" "$SCRIPT_ROOT/runner" "$SCRIPT_ROOT/collector"
MUTATION_EXIT=$?
set -e
[[ $MUTATION_EXIT != 0 ]]
[[ ! -e $RETRY_PARENT/$RUN_ID ]]
[[ $(cat "$EVIDENCE_ROOT/status") == SEALED_AWAITING_RETRY_VERIFICATION ]]
python3 - "$SCRIPT_ROOT/runner" "$SCRIPT_ROOT/runner.saved" <<'PY'
import os,sys
path,source=sys.argv[1:]; data=open(source,'rb').read()
with open(path,'r+b',buffering=0) as target:
    target.seek(0); target.write(data); target.truncate(); target.flush(); os.fsync(target.fileno())
PY
rm -f "$SCRIPT_ROOT/runner.saved"
[[ $(stat -Lc '%d:%i:%s' "$SCRIPT_ROOT/runner") == "$RUNNER_IDENTITY" ]]

set +e
RHIZOME_BARRIER_FINALIZER_TEST_POST_RENAME_FSYNC_ERROR=1 \
    "$SCRIPT_ROOT/finalizer" "$RUN_ID" "$SCRIPT_ROOT/runner" "$SCRIPT_ROOT/collector"
FIRST_EXIT=$?
set -e
[[ $FIRST_EXIT == 74 ]]
[[ $(cat "$EVIDENCE_ROOT/status") == PASS ]]
"$SCRIPT_ROOT/finalizer" "$RUN_ID" "$SCRIPT_ROOT/runner" "$SCRIPT_ROOT/collector"
[[ $(cat "$EVIDENCE_ROOT/status") == PASS ]]
[[ $(stat -c '%a:%U:%G' "$RETRY_PARENT/$RUN_ID") == 500:root:root ]]
[[ $(find "$RUN_ROOT" "$EVIDENCE_ROOT" "$RETRY_PARENT/$RUN_ID" -name '*.pending' | wc -l) == 0 ]]
