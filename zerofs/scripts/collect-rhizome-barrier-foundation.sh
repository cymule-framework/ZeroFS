#!/usr/bin/env bash
set -euo pipefail

# Run only after the unique transient unit has reached a terminal state.
[[ $(id -u) == 0 ]] || { echo "collector must execute as root" >&2; exit 2; }
[[ $# == 2 ]] || { echo "usage: $0 RUN_ID INVOCATION_ID" >&2; exit 2; }
RUN_ID=$1
INVOCATION_ID=$2
python3 - "$RUN_ID" "$INVOCATION_ID" <<'PY'
import re,sys,uuid
value=uuid.UUID(sys.argv[1]); assert value.version == 4 and str(value) == sys.argv[1]
assert re.fullmatch(r'[0-9a-f]{32}', sys.argv[2])
PY

UNIT="zerofs-barrier-fault-$RUN_ID.service"
RUN_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/runs/$RUN_ID"
EVIDENCE_ROOT="/opt/rhizome/validation/zerofs-barrier-fault/evidence/$RUN_ID"
[[ $(stat -c '%a:%U:%G' "$RUN_ROOT") == 700:root:root ]]
[[ $(stat -c '%a:%U:%G' "$EVIDENCE_ROOT") == 700:root:root ]]
EXPECTED_HASH=$(awk -F= '$1 == "terminal_collector_sha256" { print $2 }' "$EVIDENCE_ROOT/preflight.receipt")
[[ $(sha256sum "$(readlink -f "$0")" | cut -d' ' -f1) == "$EXPECTED_HASH" ]]

TERMINAL="$EVIDENCE_ROOT/terminal"
install -d -m 0700 -o root -g root "$TERMINAL"
[[ $(find "$TERMINAL" -mindepth 1 -maxdepth 1 | wc -l) == 0 ]]
journalctl -u "$UNIT" --no-pager -o short-iso-precise >"$TERMINAL/unit-journal.txt"
journalctl _SYSTEMD_INVOCATION_ID="$INVOCATION_ID" --no-pager -o short-iso-precise >"$TERMINAL/invocation-journal.txt"
UNIT_STATE=$(systemctl show "$UNIT" -p LoadState --value 2>/dev/null || printf not-found)
[[ $UNIT_STATE == not-found ]]
[[ ! -e /sys/fs/cgroup/system.slice/$UNIT ]]
[[ $(find "$RUN_ROOT" -maxdepth 1 -type f -name '*.exit' | wc -l) == 4 ]]
[[ $(cat "$EVIDENCE_ROOT/exit-code") == 0 ]]
cd "$EVIDENCE_ROOT"
sha256sum -c SHA256SUMS >"$TERMINAL/pre-exit-manifest-check.txt"
sha256sum -c RUN-SHA256SUMS >"$TERMINAL/run-manifest-check.txt"
cat >"$TERMINAL/receipt.pending" <<EOF
schema=1
run_id=$RUN_ID
invocation_id=$INVOCATION_ID
unit=$UNIT
unit_load_state=$UNIT_STATE
cgroup_absent=true
surviving_run_processes=0
scenario_exit_receipts=4
verdict=PASS
runner_exit=$(cat "$EVIDENCE_ROOT/exit-code")
preflight_receipt_sha256=$(sha256sum "$EVIDENCE_ROOT/preflight.receipt" | cut -d' ' -f1)
pre_exit_manifest_sha256=$(sha256sum "$EVIDENCE_ROOT/SHA256SUMS" | cut -d' ' -f1)
run_manifest_sha256=$(sha256sum "$EVIDENCE_ROOT/RUN-SHA256SUMS" | cut -d' ' -f1)
collector_sha256=$EXPECTED_HASH
collected_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
chmod 0600 "$TERMINAL/receipt.pending"
sync -f "$TERMINAL/receipt.pending"
ln "$TERMINAL/receipt.pending" "$TERMINAL/receipt"
sync -f "$TERMINAL"
unlink "$TERMINAL/receipt.pending"
sync -f "$TERMINAL"
chmod 0600 "$TERMINAL"/*
find "$TERMINAL" -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >"$TERMINAL/SHA256SUMS"
chmod 0600 "$TERMINAL/SHA256SUMS"
printf 'PASS\n' >"$EVIDENCE_ROOT/status"
sync -f "$EVIDENCE_ROOT/status"
sync -f "$EVIDENCE_ROOT"
