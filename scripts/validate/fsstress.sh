#!/usr/bin/env bash
# Multi-process metadata and data stress with xfstests' fsstress. It verifies nothing itself and exits non-zero only on a setup failure or an EIO from its own directory, so the assertions are ours: it finishes inside the deadline and exits 0, the mount is still there, enough operations succeeded, the tree through the mount matches the export, and the teardown is clean.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
source "$VALIDATE_DIR/tap.sh"
source "$VALIDATE_DIR/fsstress-parse.sh"

FSSTRESS=$TOOLS/xfstests/ltp/fsstress
need_tool "$FSSTRESS"
ops=${FSSTRESS_OPS:-1000}
procs=${FSSTRESS_PROCS:-4}
seed=${FSSTRESS_SEED:-1}
if [ "$(id -u)" = 0 ]; then
    mode=root
else
    mode=user
fi

fs_start fsstress
log "fsstress: $procs processes, $ops operations each, seed $seed"
rc=0
fs_run "$TOOL_TIMEOUT" "$RESULTS/fsstress.log" "$FSSTRESS" -d "$MNT/stress" -p "$procs" -n "$ops" -s "$seed" -v || rc=$?
if [ "$rc" != 0 ]; then
    tail -20 "$RESULTS/fsstress.log"
    fail "fsstress exited with status $rc"
fi
mountpoint -q "$MNT" || fail "the mount is gone after fsstress"

fsstress_parse "$RESULTS/fsstress.log" "$RESULTS"
ok=$(grep -c ' 0$' "$RESULTS/results.txt" || true)
floor=$(( procs * ops / 5 ))
log "$ok operations succeeded (floor $floor)"
[ "$ok" -ge "$floor" ] || fail "too few operations succeeded"
log "failed operations by op and result:"
awk '$2 != "0"' "$RESULTS/results.txt" | sort | uniq -c | sort -rn
status=0
if [ -s "$RESULTS/unparsed.txt" ]; then
    log "lines of fsstress's log the parser does not know ($(wc -l < "$RESULTS/unparsed.txt")); each may be a failure reported in a way it cannot see:"
    head -10 "$RESULTS/unparsed.txt"
    status=1
fi
# Whatever the baseline expects, these are never a filesystem refusing something.
denied=$(fsstress_denied "$RESULTS/failed.txt")
if [ -n "$denied" ]; then
    log "operations failed in a way that means the mount broke:"
    echo "$denied"
    status=1
fi
# The expected failures were recorded for one op sequence on one filesystem, drawn by one build of fsstress (which operations it has depends on the libraries it was built against); anywhere else the comparison decides nothing and is not made.
baseline=$VALIDATE_DIR/fsstress.baseline.$mode
recorded=$(sed -n 's/^# recorded with: //p' "$baseline")
here="seed=$seed procs=$procs ops=$ops export_fs=$(stat -f -c %T "$EXPORT") fsstress=$(sha256sum "$FSSTRESS" | cut -c1-12)"
if [ "$here" != "$recorded" ]; then
    log "$(basename "$baseline") is not held against this run: it was recorded with '$recorded', this is '$here'"
else
    if ! baseline_diff "$RESULTS/failed.txt" "$baseline" "$RESULTS"; then
        log "failing and not in $(basename "$baseline") ($(wc -l < "$RESULTS/regressions.txt")):"
        cat "$RESULTS/regressions.txt"
        status=1
    fi
    if [ -s "$RESULTS/fixed.txt" ]; then
        log "in $(basename "$baseline") and not failing any more; remove:"
        cat "$RESULTS/fixed.txt"
    fi
fi
fs_check_consistent $(( ATTR_TTL + 1 )) 20 1
[ "$status" = 0 ] || fail "fsstress found failures that are not expected"
