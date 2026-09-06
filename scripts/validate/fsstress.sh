#!/usr/bin/env bash
# Multi-process metadata and data stress with xfstests' fsstress. It verifies nothing itself and exits non-zero only on a setup failure or an EIO from its own directory, so the assertions are ours: it finishes inside the deadline and exits 0, the mount is still there, enough operations succeeded, the tree through the mount matches the export, and the teardown is clean.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

FSSTRESS=$TOOLS/xfstests/ltp/fsstress
need_tool "$FSSTRESS"
ops=${FSSTRESS_OPS:-1000}
procs=${FSSTRESS_PROCS:-4}
seed=${FSSTRESS_SEED:-1}

fs_start fsstress
log "fsstress: $procs processes, $ops operations each, seed $seed"
rc=0
fs_run "$TOOL_TIMEOUT" "$RESULTS/fsstress.log" "$FSSTRESS" -d "$MNT/stress" -p "$procs" -n "$ops" -s "$seed" -v || rc=$?
if [ "$rc" != 0 ]; then
    tail -20 "$RESULTS/fsstress.log"
    fail "fsstress exited with status $rc"
fi
mountpoint -q "$MNT" || fail "the mount is gone after fsstress"

# Verbose lines read `<proc>/<op#>: <op> <args…> <errno>`; an op with no target to act on ends in words instead of an errno and counts as neither.
ok=$(awk '/^[0-9]+\/[0-9]+: / && $NF == 0' "$RESULTS/fsstress.log" | wc -l)
floor=$(( procs * ops / 5 ))
log "$ok operations succeeded (floor $floor)"
[ "$ok" -ge "$floor" ] || fail "too few operations succeeded"
log "failed operations by op and errno:"
awk '/^[0-9]+\/[0-9]+: / && $NF ~ /^[0-9]+$/ && $NF != 0 { print $2, $NF }' "$RESULTS/fsstress.log" | sort | uniq -c | sort -rn | head -30
fs_check_consistent $(( ATTR_TTL + 1 )) 20 1
