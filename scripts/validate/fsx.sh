#!/usr/bin/env bash
# Single-file data integrity with xfstests' fsx: random reads, writes, truncates and mapped I/O checked against a shadow copy after every operation. Three passes with fixed seeds: mapped I/O on, mapped I/O off, and a small file re-read in full after every operation, the pass that catches a stale page cache.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

FSX=$TOOLS/xfstests/ltp/fsx
need_tool "$FSX"
ops=${FSX_OPS:-20000}
# The client implements nothing in the fallocate family, nor clone, dedupe or exchange; disabling them explicitly keeps a run deterministic instead of relying on the probe's errno. copy_file_range stays on because the kernel falls back to a read/write copy for FUSE.
disable=(-F -H -z -Y -C -I -J -B -0)

fs_start fsx
mkdir "$MNT/fsx"

# pass <name> <fsx options…>: one fsx run on its own file; the shadow image and log go to the results dir, not the mount.
pass() {
    local name=$1 rc=0
    shift
    log "fsx $name: $*"
    fs_run "$TOOL_TIMEOUT" "$RESULTS/$name.out" "$FSX" -P "$RESULTS" "${disable[@]}" "$@" "$MNT/fsx/$name" || rc=$?
    if [ "$rc" != 0 ]; then
        tail -20 "$RESULTS/$name.out"
        fail "fsx $name exited with status $rc; reproduce with the same seed, log in $RESULTS/$name.fsxlog"
    fi
    tail -1 "$RESULTS/$name.out"
}

pass mapped -N "$ops" -S 1 -l 4194304
pass unmapped -N "$ops" -S 2 -l 4194304 -R -W
pass reread -N $(( ops / 4 )) -S 3 -X
log "operations fsx disabled on its own:"
grep -h disabling "$RESULTS"/*.out | sort -u || true
fs_check_consistent $(( ATTR_TTL + 1 )) 3 1
