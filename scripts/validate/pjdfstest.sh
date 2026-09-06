#!/usr/bin/env bash
# POSIX conformance with pjdfstest. Unprivileged (the configuration people run): the test files that never switch uid, on a plain mount. As root (scripts/validate/container.sh): every file, with --allow-other --default-permissions so other uids reach the mount and the kernel enforces modes. Each mode has its own expected-failure baseline; the verdict is the diff against it, not prove's exit status.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
source "$VALIDATE_DIR/tap.sh"

TESTS=$TOOLS/pjdfstest/tests
need_tool "$TOOLS/pjdfstest/pjdfstest"
[ -x "$PROVE" ] || fail "prove not found (package perl)"

if [ "$(id -u)" = 0 ]; then
    mode=root
    floor=8000
    fs_start pjdfstest --allow-other --default-permissions
    files=$(cd "$TESTS" && ls -- */*.t)
else
    mode=user
    floor=1000
    fs_start pjdfstest
    # Files that switch uid, whether with a literal uid or one looked up at runtime, cannot pass unprivileged.
    files=$(cd "$TESTS" && grep -L -E -e '-u ([0-9]|\$)' -- */*.t)
fi
baseline=$VALIDATE_DIR/pjdfstest.baseline.$mode
printf '%s\n' $files | sort > "$RESULTS/expected.txt"
log "mode $mode: $(wc -l < "$RESULTS/expected.txt") test files, baseline $(basename "$baseline")"

# shellcheck disable=SC2086
fs_run "$TOOL_TIMEOUT" "$RESULTS/prove.log" env -C "$MNT" "$PROVE" -v --merge $(sed "s|^|$TESTS/|" "$RESULTS/expected.txt") || true
tap_parse "$TESTS" "$RESULTS/expected.txt" "$RESULTS/prove.log" "$RESULTS"
log "$(cat "$RESULTS/counts.txt")"
# A third of the files skip themselves on Linux (chflags, lchmod, birthtime) and count as passes; the floor catches a change that made more of them do so.
checks=$(sed -n 's/.*checks=\([0-9]*\).*/\1/p' "$RESULTS/counts.txt")
[ "${checks:-0}" -ge "$floor" ] || fail "only ${checks:-0} checks ran (floor $floor); see $RESULTS/prove.log"

status=0
if [ -s "$RESULTS/harness.txt" ]; then
    log "test files that did not run to completion (not counted as passing):"
    cat "$RESULTS/harness.txt"
    status=1
fi
if ! baseline_diff "$RESULTS/failed.txt" "$baseline" "$RESULTS"; then
    log "regressions ($(wc -l < "$RESULTS/regressions.txt")), failing and not in $(basename "$baseline"):"
    cat "$RESULTS/regressions.txt"
    status=1
fi
if [ -s "$RESULTS/fixed.txt" ]; then
    log "now passing ($(wc -l < "$RESULTS/fixed.txt")); remove from $(basename "$baseline"):"
    cat "$RESULTS/fixed.txt"
fi
exit $status
