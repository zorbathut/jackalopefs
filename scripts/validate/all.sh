#!/usr/bin/env bash
# Every suite that can run at the current privilege, in sequence, each under a deadline, with a summary at the end. Continues past failures and exits non-zero if any failed. Between suites it makes sure nothing of the previous one survived, so a hang cannot poison the next.
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh

suites=(pjdfstest fsx fsstress fio resilience coherence)
[ "$(id -u)" = 0 ] && suites+=(permissions)
# Enough for the longest suite, fsx with three tool runs, plus start-up and teardown; the tool deadline inside a suite therefore always fires first, and that is the one that collects diagnostics.
budget=$(( 3 * TOOL_TIMEOUT + 300 ))
mkdir -p "$RESULTS_ROOT"
declare -A outcome seconds
failed=0
for s in "${suites[@]}"; do
    log "=== $s"
    start=$(date +%s)
    # timeout puts the suite in its own process group so that a deadline reaches everything it started; an interrupt here is forwarded to that group for the same reason, and the suite's own teardown then runs.
    timeout -k 30 "$budget" "./$s.sh" > "$RESULTS_ROOT/$s.txt" 2>&1 &
    child=$!
    trap 'kill -TERM -- "-$child" 2>/dev/null; wait "$child" 2>/dev/null; exit 130' INT TERM
    if wait "$child"; then
        outcome[$s]=pass
    else
        outcome[$s]="FAIL ($?)"
        failed=1
        tail -5 "$RESULTS_ROOT/$s.txt"
    fi
    trap - INT TERM
    seconds[$s]=$(( $(date +%s) - start ))
    # Nothing may outlive its suite. The harness's server and client both carry the results path in their arguments, which one started by hand does not.
    if pgrep -f "jackalopefs-(server|client) .*$RESULTS_ROOT/" > /dev/null; then
        log "processes survived $s; killing them"
        pkill -KILL -f "jackalopefs-(server|client) .*$RESULTS_ROOT/" || true
        outcome[$s]="${outcome[$s]} +leftover processes"
        failed=1
    fi
    while read -r mnt; do
        log "mount survived $s at $mnt; detaching"
        fusermount3 -uz "$mnt" || true
        outcome[$s]="${outcome[$s]} +leftover mount"
        failed=1
    done < <(mounts_under "$RESULTS_ROOT")
done

echo
printf '%-12s %-22s %6s\n' suite outcome seconds
for s in "${suites[@]}"; do
    printf '%-12s %-22s %6s\n' "$s" "${outcome[$s]}" "${seconds[$s]}"
done
echo "logs: $RESULTS_ROOT/<suite>.txt and $RESULTS_ROOT/<suite>/"
exit $failed
