#!/usr/bin/env bash
# Measures what each request costs in CPU on a local server and mount: starts both in a temporary directory, runs one workload, and prints each side's CPU and context switches per request and per MiB, from their counters before and after.
#
#   scripts/perf/bench.sh torrent [seconds] [threads] [blocks-per-second]
#   scripts/perf/bench.sh seq [MiB]
#
# Binaries come from target/release (build it first) or $JFS_BIN. SERVER_ENV and CLIENT_ENV are space-separated environment assignments for each binary (no spaces within a value), e.g. SERVER_ENV=TOKIO_WORKER_THREADS=4, for A/B runs. Loopback measures CPU, not round trips: scripts/perf/workload.sh against the real mount is for those.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
BIN=${JFS_BIN:-$REPO/target/release}
WORKLOAD=${1:?usage: bench.sh torrent|seq [args…]}
shift
for b in jackalopefs-server jackalopefs-client jackalopefs-ctl; do
    [ -x "$BIN/$b" ] || { echo "$BIN/$b is missing; cargo build --release --workspace" >&2; exit 1; }
done

# On the repository's filesystem rather than /tmp, which is often tmpfs.
WORK=$(mktemp -d "$REPO/target/bench.XXXXXX")
SERVER_PID=
CLIENT_PID=
# Stop a process, by force if it has not gone within five seconds.
stop() {
    local pid=$1
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 0
    kill "$pid" 2>/dev/null || return 0
    for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.1; done
    echo "pid $pid ignored SIGTERM; killing it" >&2
    kill -KILL "$pid" 2>/dev/null || true
}
cleanup() {
    # The client exits by itself once its mount is gone.
    if mountpoint -q "$WORK/mnt"; then fusermount3 -u "$WORK/mnt" || fusermount3 -uz "$WORK/mnt"; fi
    stop "$CLIENT_PID"
    stop "$SERVER_PID"
    rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK/export" "$WORK/mnt" "$WORK/state"

PORT=$((20000 + RANDOM % 20000))
env ${SERVER_ENV:-} "$BIN/jackalopefs-server" --export "$WORK/export" --listen "127.0.0.1:$PORT" --state-dir "$WORK/state" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 50); do grep -q "exporting" "$WORK/server.log" && break; sleep 0.1; done
env ${CLIENT_ENV:-} "$BIN/jackalopefs-client" "127.0.0.1:$PORT" "$WORK/mnt" --insecure > "$WORK/client.log" 2>&1 &
CLIENT_PID=$!
for _ in $(seq 50); do mountpoint -q "$WORK/mnt" && break; sleep 0.1; done
mountpoint -q "$WORK/mnt" || { cat "$WORK/server.log" "$WORK/client.log" >&2; exit 1; }
# Each control socket comes up just after its process is serving.
for pid in "$SERVER_PID" "$CLIENT_PID"; do
    for _ in $(seq 50); do "$BIN/jackalopefs-ctl" counters --pid "$pid" > /dev/null 2>&1 && break; sleep 0.1; done
done

counters() { "$BIN/jackalopefs-ctl" counters --pid "$1"; }
# Datagrams the two processes' UDP sockets dropped for a full receive buffer, from the per-socket counter in /proc/net/udp*, so other traffic on the host does not count.
udp_drops() {
    local inodes
    inodes=$(for pid in "$SERVER_PID" "$CLIENT_PID"; do ls -l "/proc/$pid/fd" 2>/dev/null; done | sed -n 's/.*socket:\[\([0-9]*\)\]$/\1/p' | tr '\n' ' ')
    cat /proc/net/udp /proc/net/udp6 | awk -v inodes=" $inodes" 'index(inodes, " " $10 " ") { n += $NF } END { print n + 0 }'
}
drops_before=$(udp_drops)
counters "$SERVER_PID" > "$WORK/server.before"
counters "$CLIENT_PID" > "$WORK/client.before"

case "$WORKLOAD" in
    torrent)
        python3 "$REPO/scripts/perf/torrent.py" "$WORK/mnt/torrent" "${1:-10}" "${2:-8}" "${3:-0}"
        # The writes are in the kernel's cache until the file is closed; the flush is part of the work.
        sync "$WORK/mnt/torrent"
        ;;
    seq)
        mib=${1:-2048}
        dd if=/dev/zero of="$WORK/mnt/seq" bs=1M count="$mib" conv=fsync 2>&1 | tail -1
        # A fresh open drops the client's cached pages, so this reads from the server.
        dd if="$WORK/mnt/seq" of=/dev/null bs=1M 2>&1 | tail -1
        ;;
    *)
        echo "unknown workload $WORKLOAD" >&2
        exit 1
        ;;
esac

counters "$SERVER_PID" > "$WORK/server.after"
drops_after=$(udp_drops)
counters "$CLIENT_PID" > "$WORK/client.after"

# Per side: the outermost level's requests and bytes (the kernel's on the client, the clients' on the server), and the CPU and switches spent meanwhile.
report() {
    local side=$1 level=$2
    awk -v side="$side" -v level="$level" '
        FNR == NR { before[$1] = $2; next }
        { after[$1] = $2 }
        END {
            for (k in after) delta[k] = after[k] - before[k]
            requests = 0; bytes = 0
            for (k in delta) {
                if (k ~ "^op\\." level "\\..*\\.count$") requests += delta[k]
                if (k ~ "^op\\." level "\\..*\\.bytes$") bytes += delta[k]
            }
            seconds = delta["uptime_ns"] / 1e9
            cpu = delta["resources.user_ns"] + delta["resources.sys_ns"]
            switches = delta["resources.voluntary_switches"] + delta["resources.involuntary_switches"]
            printf "%-6s %8.2fs %9d requests %8.0f/s  CPU %5.2f cores (user %4.2f sys %4.2f)  busy %4.2f", side, seconds, requests, requests / seconds, cpu / 1e9 / seconds, delta["resources.user_ns"] / 1e9 / seconds, delta["resources.sys_ns"] / 1e9 / seconds, delta["resources.busy_ns"] / 1e9 / seconds
            if (requests > 0) printf "  per request %6.1fus %5.1f switches", cpu / 1e3 / requests, switches / requests
            if (bytes > 0) printf "  per MiB %6.2fms", cpu / 1e6 / (bytes / 1048576)
            printf "\n"
        }' "$WORK/$side.before" "$WORK/$side.after"
}
report server request
report client fuse
echo "both   UDP datagrams dropped for a full receive buffer: $((drops_after - drops_before))"
