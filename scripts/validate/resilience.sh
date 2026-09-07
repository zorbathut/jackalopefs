#!/usr/bin/env bash
# What no external suite tests: a server that stops answering, dies, and comes back, under load through a real mount. Operations must fail with ETIMEDOUT inside the deadline instead of hanging, resume when the server does, survive a server restart with contents and open files intact, and a lazy detach must free the mount at once.
set -euo pipefail
export JFS_OP_TIMEOUT=3s
source "$(dirname "$0")/lib.sh"

fs_start resilience
# The fixture is renamed into place: anything listing the mount root while it is written (the desktop probes a new mount) would instantiate the file empty, and the kernel keeps that size for the attribute TTL.
head -c 1048576 /dev/urandom > "$EXPORT/.fixed.tmp"
mv "$EXPORT/.fixed.tmp" "$EXPORT/fixed"
: > "$EXPORT/log.txt"
cmp -s "$MNT/fixed" "$EXPORT/fixed" || fail "cannot read through the mount"

# Background load: a writer appending numbered lines and a reader comparing a file, both tolerating errors so the assertions below are made explicitly. Every operation is bounded on its own, so the loops end once stop-load appears and the waits on them cannot hang; a timeout shows up as err 124.
(
    i=0
    while [ ! -e "$RESULTS/stop-load" ]; do
        if timeout 10 sh -c 'printf "line %06d\n" "$1" >> "$2"' _ "$i" "$MNT/log.txt" 2>/dev/null; then echo ok; else echo "err $?"; fi
        i=$(( i + 1 ))
        sleep 0.02
    done > "$RESULTS/writer.log"
) &
WRITER=$!
(
    while [ ! -e "$RESULTS/stop-load" ]; do
        if timeout 10 cmp -s "$MNT/fixed" "$EXPORT/fixed"; then echo ok; else echo "err $?"; fi
        sleep 0.02
    done > "$RESULTS/reader.log"
) &
READER=$!
stop_load() {
    touch "$RESULTS/stop-load"
    wait "$WRITER" "$READER" 2>/dev/null || true
}
sleep 1

# probe_timeout <what> cmd…: must fail with ETIMEDOUT, and within the 3 s deadline plus a margin for the kernel round trip.
probe_timeout() {
    local what=$1 t0 t1 ms out
    shift
    t0=$(date +%s%N)
    if out=$(LC_ALL=C "$@" 2>&1); then fail "$what succeeded while the server was stopped"; fi
    t1=$(date +%s%N)
    ms=$(( (t1 - t0) / 1000000 ))
    log "$what: ${ms} ms, $out"
    case "$out" in *"timed out"*) ;; *) fail "$what did not fail with ETIMEDOUT" ;; esac
    [ "$ms" -le 6000 ] || fail "$what took ${ms} ms against a 3 s deadline"
}

log "server stopped: operations must time out"
exec 3< "$MNT/fixed"
kill -STOP "$SERVER_PID"
probe_timeout "lookup" stat "$MNT/never-$RANDOM"
probe_timeout "create" sh -c "echo x > '$MNT/new-$RANDOM'"
probe_timeout "lookup again" stat "$MNT/never-$RANDOM"

log "server continued: operations must resume"
kill -CONT "$SERVER_PID"
wait_for 15 cmp -s "$MNT/fixed" "$EXPORT/fixed" || fail "reads did not resume after SIGCONT"

log "server killed and restarted: the mount must recover with open files intact"
kill -KILL "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=
sleep 1
server_start
wait_for 30 cmp -s "$MNT/fixed" "$EXPORT/fixed" || fail "reads did not recover after the restart"
head -c 4096 <&3 | cmp -s - <(head -c 4096 "$EXPORT/fixed") || fail "a file opened before the restart does not read correctly after it"
exec 3<&-
sleep 1
stop_load
cmp -s "$MNT/log.txt" "$EXPORT/log.txt" || fail "the appended log differs through the mount"
# Failed appends leave gaps; a torn or duplicated line would be corruption.
awk 'BEGIN { last = -1 } { n = substr($2, 1, 6) + 0; if ($1 != "line" || n <= last) { print "bad line " NR ": " $0; exit 1 }; last = n }' "$EXPORT/log.txt" || fail "the appended log is not a clean increasing sequence"
log "writer: $(grep -c ok "$RESULTS/writer.log") ok, $(grep -c err "$RESULTS/writer.log") errors; reader: $(grep -c ok "$RESULTS/reader.log") ok, $(grep -c err "$RESULTS/reader.log") errors; $(wc -l < "$EXPORT/log.txt") lines landed"

log "server stopped again: a lazy detach must free the mount at once"
kill -STOP "$SERVER_PID"
( timeout 10 cat "$MNT/fixed" > /dev/null 2>&1 || true ) &
BLOCKED=$!
sleep 0.5
t0=$(date +%s%N)
fusermount3 -uz "$MNT"
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
log "detach took ${ms} ms"
[ "$ms" -le 2000 ] || fail "detach took ${ms} ms"
mountpoint -q "$MNT" && fail "still a mountpoint after the detach"
wait "$BLOCKED"
ps -o pid=,stat= -p "$$" "${CLIENT_PIDS[0]%% *}" "$SERVER_PID" "$WRITER" "$READER" 2>/dev/null | awk '$2 ~ /D/ { print; bad = 1 } END { exit bad }' || fail "a process is stuck in uninterruptible sleep"
kill -CONT "$SERVER_PID"
