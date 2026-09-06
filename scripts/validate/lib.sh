# Sourced by every validation suite: a server plus mount with deadlines on every step, hang diagnostics, teardown that reports what it had to force, and the checks the suites share.
set -euo pipefail

# Physical paths, because they are compared with the mount table, which has symlinks resolved.
VALIDATE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO=$(cd "$VALIDATE_DIR/../.." && pwd -P)
TOOLS=${JFS_TOOLS:-$REPO/validation/tools}
BIN=${JFS_BIN:-$REPO/target/debug}
RESULTS_ROOT=${JFS_RESULTS:-$REPO/validation/results}
PROVE=$(command -v prove 2>/dev/null || echo /usr/bin/core_perl/prove)
# The client's default attribute TTL; a consistency check on a default mount waits it out.
ATTR_TTL=1
# Deadline on every external tool run (fs_run); all.sh derives its per-suite budget from it.
TOOL_TIMEOUT=${JFS_TOOL_TIMEOUT:-600}
export JFS_OP_TIMEOUT=${JFS_OP_TIMEOUT:-15s}

SERVER_PID=
PORT=
# "pid mountpoint" per running client.
CLIENT_PIDS=()
STOP_RC=0

log() { printf '[%s] %s\n' "$(date +%T)" "$*"; }
fail() { log "FAIL: $*"; exit 1; }

# wait_for <seconds> cmd…: poll until the command succeeds; false once the deadline passes.
wait_for() {
    local deadline=$(( $(date +%s%N) / 1000000 + $1 * 1000 ))
    shift
    until "$@"; do
        (( $(date +%s%N) / 1000000 < deadline )) || return 1
        sleep 0.1
    done
}

need_tool() { [ -x "$1" ] || fail "$1 is missing; run scripts/validate/tools.sh $TOOLS"; }

# mounts_under <dir> [mountinfo]: the FUSE mount points below a directory. The optional fields before the "-" separator vary in number (none inside a container), so the filesystem type is found from the separator; a space in a mount point is written \\040 there.
mounts_under() {
    awk -v root="$1/" '{ for (i = 7; i <= NF && $i != "-"; i++) {} p = $5; gsub(/\\040/, " ", p); if (index(p, root) == 1 && $(i + 1) ~ /^fuse/) print p }' "${2:-/proc/self/mountinfo}"
}

# fs_start <suite> [client options…]: a fresh export, server and mount under validation/results/<suite>/, torn down by an exit trap.
fs_start() {
    SUITE=$1
    shift
    RESULTS=$RESULTS_ROOT/$SUITE
    EXPORT=$RESULTS/export
    MNT=$RESULTS/mnt
    STATE=$RESULTS/state
    local stale
    # A suite killed mid-run can leave its server and client behind and a mount (coherence has two) under the results tree, which rm -rf would otherwise walk.
    if pkill -KILL -f "jackalopefs-(server|client) .*$RESULTS/" 2>/dev/null; then
        log "stale server or client from an earlier run of $SUITE killed"
    fi
    while read -r stale; do
        log "stale mount from an earlier run at $stale; detaching"
        fusermount3 -uz "$stale"
    done < <(mounts_under "$RESULTS")
    rm -rf "$RESULTS"
    mkdir -p "$EXPORT" "$MNT" "$STATE"
    # The host runs whatever the working tree says; the container gets binaries built outside (JFS_BIN) and has no cargo.
    [ -n "${JFS_BIN:-}" ] || (cd "$REPO" && cargo build --workspace --quiet)
    [ -x "$BIN/jackalopefs-server" ] && [ -x "$BIN/jackalopefs-client" ] || fail "binaries missing in $BIN; run cargo build --workspace"
    # The client uses the server's st_ino as the FUSE node id, so the export must sit on a filesystem with stable inode numbers, which overlayfs is not.
    local fstype
    fstype=$(stat -f -c %T "$EXPORT")
    case "$fstype" in overlay*|fuse*) fail "export on $fstype; put the repository on a real filesystem" ;; esac
    [ "$(getconf NAME_MAX "$EXPORT")" = 255 ] || fail "NAME_MAX on the export is $(getconf NAME_MAX "$EXPORT"), the protocol assumes 255"
    {
        echo "suite $SUITE"
        echo "date $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "kernel $(uname -r)"
        echo "uid $(id -u)"
        echo "export_fs $fstype"
        for k in protected_hardlinks protected_symlinks protected_regular protected_fifos; do echo "fs.$k $(cat /proc/sys/fs/$k)"; done
        echo "commit $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)$(git -C "$REPO" diff --quiet 2>/dev/null || echo -dirty)"
        echo "client_options $*"
        echo
        cat "$TOOLS/versions.txt" 2>/dev/null || echo "no versions.txt in $TOOLS"
    } > "$RESULTS/env.txt"
    trap fs_teardown_trap EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    server_start
    client_start "$MNT" "$@"
}

# server_start: on the port already chosen, or on a free one the first time (the port is read back from the log). A restart appends to the same log, so it waits for a new "exporting" line rather than the first.
server_start() {
    local before
    before=$(grep -c "exporting .* on 127.0.0.1:" "$RESULTS/server.log" 2>/dev/null || true)
    before=${before:-0}
    # Descriptors 3-9 are closed for the child: a suite that holds a file on the mount open while restarting the server would otherwise hand that file to the server, which then pins the mount.
    RUST_LOG=${RUST_LOG:-info} "$BIN/jackalopefs-server" --export "$EXPORT" --listen "127.0.0.1:${PORT:-0}" --state-dir "$STATE" >> "$RESULTS/server.log" 2>&1 3<&- 4<&- 5<&- 6<&- 7<&- 8<&- 9<&- &
    SERVER_PID=$!
    wait_for 15 sh -c "[ \"\$(grep -c 'exporting .* on 127.0.0.1:' '$RESULTS/server.log')\" -gt $before ]" || fail "server did not start: $(tail -5 "$RESULTS/server.log")"
    PORT=$(grep -o 'on 127.0.0.1:[0-9]*' "$RESULTS/server.log" | tail -1 | cut -d: -f2)
}

# client_start <mountpoint> [options…]: mount and wait for it to appear.
client_start() {
    local mnt=$1
    shift
    mkdir -p "$mnt"
    RUST_LOG=${RUST_LOG:-info} "$BIN/jackalopefs-client" "127.0.0.1:$PORT" "$mnt" --insecure --op-timeout "$JFS_OP_TIMEOUT" "$@" >> "$RESULTS/client-$(basename "$mnt").log" 2>&1 3<&- 4<&- 5<&- 6<&- 7<&- 8<&- 9<&- &
    CLIENT_PIDS+=("$! $mnt")
    wait_for 15 mountpoint -q "$mnt" || fail "mount did not appear at $mnt: $(tail -5 "$RESULTS/client-$(basename "$mnt").log")"
}

# client_stop <pid> <mountpoint>: orderly unmount on SIGTERM; anything forced is a failure.
client_stop() {
    local pid=$1 mnt=$2 st=0
    kill -TERM "$pid" 2>/dev/null || true
    if ! wait_for 30 sh -c "! kill -0 $pid 2>/dev/null"; then
        log "client $pid did not exit within 30 s of SIGTERM; detaching and killing"
        fs_hang_dump
        fusermount3 -uz "$mnt" || true
        kill -KILL "$pid" 2>/dev/null || true
        STOP_RC=1
    fi
    wait "$pid" 2>/dev/null || st=$?
    if [ "$st" != 0 ]; then
        log "client $pid exited with status $st"
        STOP_RC=1
    fi
    if mountpoint -q "$mnt" 2>/dev/null; then
        log "$mnt still mounted after the client exited; detaching"
        fusermount3 -uz "$mnt" || true
        STOP_RC=1
    fi
}

server_stop() {
    local st=0
    [ -n "$SERVER_PID" ] || return 0
    kill -CONT "$SERVER_PID" 2>/dev/null || true
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    if ! wait_for 30 sh -c "! kill -0 $SERVER_PID 2>/dev/null"; then
        log "server did not exit within 30 s of SIGTERM; killing"
        kill -KILL "$SERVER_PID" 2>/dev/null || true
        STOP_RC=1
    fi
    wait "$SERVER_PID" 2>/dev/null || st=$?
    if [ "$st" != 0 ]; then
        log "server exited with status $st"
        STOP_RC=1
    fi
    SERVER_PID=
}

# log_check: an ERROR or a panic in either side's log fails the run; warnings are counted because inotify saturation only warns.
log_check() {
    local f n errs
    : > "$RESULTS/errors.txt"
    for f in "$RESULTS"/server.log "$RESULTS"/client-*.log; do
        [ -e "$f" ] || continue
        # The binaries colour only a terminal, but colour codes around the level would hide it from the pattern, so they are stripped regardless. Streamed, because a debug-level log after a stress run is large.
        errs=$(sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -E '(^| )ERROR |panicked' || true)
        if [ -n "$errs" ]; then
            log "errors in $(basename "$f"):"
            printf '%s\n' "$errs" | tee -a "$RESULTS/errors.txt"
            STOP_RC=1
        fi
        n=$(sed 's/\x1b\[[0-9;]*m//g' "$f" | grep WARN | grep -vc 'Not Implemented' || true)
        [ "${n:-0}" = 0 ] || log "$n warnings in $(basename "$f") beyond fuser's not-implemented notices (see the log)"
    done
}

# fs_stop: clients first, then the server, then the logs; returns non-zero if anything had to be forced or logged an error.
fs_stop() {
    local entry
    for entry in "${CLIENT_PIDS[@]}"; do
        # shellcheck disable=SC2086
        client_stop $entry
    done
    CLIENT_PIDS=()
    server_stop
    log_check
    return $STOP_RC
}

fs_teardown_trap() {
    local status=$?
    trap - EXIT TERM INT
    fs_stop || status=1
    [ "$status" = 0 ] && log "PASS: $SUITE" || log "FAIL: $SUITE (status $status)"
    exit "$status"
}

# fs_run <seconds> <log> cmd…: run a tool under a deadline with its output in <log>; a timeout dumps diagnostics and fails the suite, on the suite's own output rather than in the tool's log.
fs_run() {
    local secs=$1 out=$2 rc=0
    shift 2
    timeout -k 10 "$secs" "$@" > "$out" 2>&1 || rc=$?
    if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
        fs_hang_dump
        fail "timed out after ${secs}s: $*"
    fi
    return "$rc"
}

# fs_hang_dump: what every thread was waiting on, the mounts, and the log tails, into results/<suite>/hang/.
fs_hang_dump() {
    local d=$RESULTS/hang entry pid t
    mkdir -p "$d"
    log "collecting hang diagnostics into $d"
    ps -eLo pid,tid,stat,wchan:40,comm > "$d/ps.txt" 2>&1 || true
    for entry in "${CLIENT_PIDS[@]}" "$SERVER_PID x"; do
        pid=${entry%% *}
        [ -n "$pid" ] || continue
        for t in /proc/"$pid"/task/*; do
            echo "== $t $(cat "$t/comm" 2>/dev/null) state $(awk '{print $3}' "$t/stat" 2>/dev/null) wchan $(cat "$t/wchan" 2>/dev/null) syscall $(cat "$t/syscall" 2>/dev/null)"
            cat "$t/stack" 2>/dev/null || echo "(stack not readable)"
        done > "$d/stacks-$pid.txt"
    done
    cat /proc/self/mountinfo > "$d/mountinfo.txt"
    # Whatever still holds a file, cwd or root on a mount keeps a lazily detached FUSE superblock, and with it the session thread, alive.
    find /proc/[0-9]*/cwd /proc/[0-9]*/root /proc/[0-9]*/fd -maxdepth 1 -lname "$RESULTS_ROOT/*" -printf '%p -> %l\n' 2>/dev/null > "$d/holders.txt" || true
    tail -50 "$RESULTS"/server.log "$RESULTS"/client-*.log > "$d/log-tails.txt" 2>&1 || true
}

# fs_check_consistent <settle> <min_files> <min_bytes> [mount]: after <settle> seconds (the attribute TTL plus one on a default mount; on a mount with long TTLs the time server push is allowed, which is then what is being asserted), the tree through the mount must equal the export in names, types, sizes, links, modes, mtimes, symlink targets and regular-file contents. Block counts and xattrs are not compared. The floors keep an empty tree from passing.
fs_check_consistent() {
    local settle=$1 min_files=$2 min_bytes=$3 mnt=${4:-$MNT} fmt='%P %y %s %n %m %T@ %l\n' files bytes p
    sleep "$settle"
    (cd "$mnt" && find . -mindepth 1 -printf "$fmt" | sort) > "$RESULTS/tree-mnt.txt"
    (cd "$EXPORT" && find . -mindepth 1 -printf "$fmt" | sort) > "$RESULTS/tree-export.txt"
    diff -u "$RESULTS/tree-export.txt" "$RESULTS/tree-mnt.txt" > "$RESULTS/tree-diff.txt" || fail "the mount and the export disagree; see $RESULTS/tree-diff.txt"
    files=$(awk '$2 == "f"' "$RESULTS/tree-export.txt" | wc -l)
    bytes=$(awk '$2 == "f" { s += $3 } END { print s + 0 }' "$RESULTS/tree-export.txt")
    [ "$files" -ge "$min_files" ] && [ "$bytes" -ge "$min_bytes" ] || fail "tree too small to mean anything: $files files, $bytes bytes"
    while IFS= read -r p; do
        cmp -s "$mnt/$p" "$EXPORT/$p" || fail "contents differ through the mount: $p"
    done < <(cd "$EXPORT" && find . -type f -printf '%P\n')
    log "consistent: $files files, $bytes bytes"
}
