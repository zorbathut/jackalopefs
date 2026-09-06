#!/usr/bin/env bash
# Root only (through container.sh): the checks --allow-other --default-permissions exist for. On a mount shared with other users the kernel must enforce mode bits and sticky directories against the attributes the server reports, and an unprivileged write must strip the setuid bit. Also makes the uid-forwarding gap visible: a file created by uid 65534 belongs to the server user.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

[ "$(id -u)" = 0 ] || fail "needs root; run it through container.sh"
command -v setpriv >/dev/null || fail "setpriv not found (package util-linux)"
fs_start permissions --allow-other --default-permissions

as_nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }
# expect <ok|error text> cmd…: the command must succeed, or fail with that text in its (C-locale) message.
expect() {
    local want=$1 out rc=0
    shift
    out=$(LC_ALL=C "$@" 2>&1) || rc=$?
    if [ "$want" = ok ]; then
        [ "$rc" = 0 ] || fail "$*: expected success, got status $rc: $out"
    else
        [ "$rc" != 0 ] || fail "$*: expected '$want', succeeded"
        case "$out" in *"$want"*) ;; *) fail "$*: expected '$want', got: $out" ;; esac
    fi
    log "ok: $* -> $want"
}

echo secret > "$MNT/private"
chmod 600 "$MNT/private"
echo public > "$MNT/public"
chmod 644 "$MNT/public"
mkdir "$MNT/shared"
chmod 1777 "$MNT/shared"
touch "$MNT/shared/root-file"
echo x > "$MNT/suid"
chmod 4666 "$MNT/suid"

expect "Permission denied" as_nobody cat "$MNT/private"
expect ok as_nobody cat "$MNT/public"
expect "Permission denied" as_nobody sh -c "echo x > '$MNT/public'"
expect "Operation not permitted" as_nobody chmod 600 "$MNT/public"
expect "Permission denied" as_nobody touch "$MNT/new-in-root-owned-dir"
expect ok as_nobody sh -c "echo mine > '$MNT/shared/nobody-file'"
expect "Operation not permitted" as_nobody rm -f "$MNT/shared/root-file"
expect ok as_nobody sh -c "echo y >> '$MNT/suid'"
mode=$(stat -c %a "$EXPORT/suid")
[ "$mode" = 666 ] || fail "an unprivileged write left the setuid bit: mode $mode"
log "setuid stripped by an unprivileged write: mode $mode"
owner=$(stat -c %u "$EXPORT/shared/nobody-file")
# The protocol carries no requester uid, so the server (root here) owns what uid 65534 creates; when identity forwarding lands, this is the check to turn around.
[ "$owner" = 0 ] || fail "a file created by uid 65534 belongs to uid $owner on the export; without a requester uid in the protocol it should belong to the server, uid 0"
log "a file created by uid 65534 belongs to the server user on the export (the protocol carries no requester uid)"
