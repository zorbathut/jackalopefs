#!/usr/bin/env bash
# Runs the workloads behind the known slow cases against a live jackalopefs mount, with a UTC-timestamped banner around each so the client's and server's perf reports can be matched to them.
#
#   scripts/perf/workload.sh <mountpoint> [client-pid]
#
# Run the client (and, where you can, the server) with `--perf-interval 5s`, or give the client's pid here and a report is requested with SIGUSR1 at every step boundary so each report is exactly one workload. Loopback tells you nothing about round trips: run this against the mount you actually use. Verified I/O under load is scripts/validate/fio.sh's job, not this script's.
set -euo pipefail

MNT=${1:?usage: workload.sh <mountpoint> [client-pid]}
CLIENT_PID=${2:-}
SIZE_MB=${JFS_PERF_SIZE_MB:-256}
ENTRIES=${JFS_PERF_ENTRIES:-5000}
WORK=$MNT/.jackalopefs-perf
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

mountpoint -q "$MNT" || { echo "$MNT is not a mount point" >&2; exit 1; }
if [ -n "$CLIENT_PID" ] && ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "no process with pid $CLIENT_PID; is that the client?" >&2
    exit 1
fi

banner() { printf '\n==== %s  %s\n' "$(date -u +%T.%N | cut -c1-12)" "$*"; }
report() { [ -z "$CLIENT_PID" ] || kill -USR1 "$CLIENT_PID"; }
step() {
    local name=$1
    shift
    banner "start $name"
    local t0=$(date +%s%N)
    "$@"
    local t1=$(date +%s%N)
    banner "end $name ($(( (t1 - t0) / 1000000 )) ms)"
    report
}
drop_page_cache() {
    # Only root can drop the page cache. Without that a re-read may be served locally; today the client never sets FOPEN_KEEP_CACHE, so every open drops it anyway, but that is what the "read again" step exists to check.
    if [ "$(id -u)" = 0 ]; then
        sync
        echo 3 > /proc/sys/vm/drop_caches
    else
        echo "(not root: page cache not dropped)"
    fi
}

mkdir -p "$WORK"
banner "preparing ${SIZE_MB} MiB file and ${ENTRIES}-entry directory under $WORK (not timed)"
dd if=/dev/urandom of="$SCRATCH/big" bs=1M count="$SIZE_MB" status=none
[ -f "$WORK/big" ] || cp "$SCRATCH/big" "$WORK/big"
if [ ! -d "$WORK/many" ]; then
    mkdir "$WORK/many"
    (cd "$WORK/many" && seq 1 "$ENTRIES" | xargs -I{} sh -c 'echo {} > f{}')
fi
report

drop_page_cache
step "read bs=128k" dd if="$WORK/big" of=/dev/null bs=128k status=none
drop_page_cache
step "read bs=1M" dd if="$WORK/big" of=/dev/null bs=1M status=none
step "read again (same file, no cache drop)" dd if="$WORK/big" of=/dev/null bs=1M status=none
step "write bs=128k" dd if="$SCRATCH/big" of="$WORK/out-128k" bs=128k status=none conv=fsync
step "write bs=1M" dd if="$SCRATCH/big" of="$WORK/out-1M" bs=1M status=none conv=fsync
step "cp into the mount" cp "$SCRATCH/big" "$WORK/out-cp"
step "cp out of the mount" cp "$WORK/big" "$SCRATCH/copy"
step "ls -l cold" sh -c "ls -l '$WORK/many' | wc -l"
step "ls -l again (inside the attr TTL)" sh -c "ls -l '$WORK/many' | wc -l"
step "find" sh -c "find '$WORK/many' | wc -l"
step "stat loop" sh -c "for f in '$WORK'/many/f1*; do stat -c %s \"\$f\"; done | wc -l"
rm -f "$WORK/out-128k" "$WORK/out-1M" "$WORK/out-cp"
banner "done; $WORK/big and $WORK/many are left for the next run"
