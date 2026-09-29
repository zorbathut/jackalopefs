#!/usr/bin/env bash
# The default owner modes through a real kernel, which every other suite leaves out by running both sides with --ids direct: a server that lets only its own owners cross (--ids flatten) under a mount that shows its user as this one (--ids owned), then a second mount of the same server that passes owners through (--ids direct), which the server refuses by itself. Harness server and mount run as the same user, so the owned mapping is the identity here; what shows it translating is the client's tests. The ACL checks need setfacl and a results filesystem and kernel that carry POSIX ACLs through the mount, and are skipped, saying why, otherwise.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

JFS_SERVER_IDS=flatten
JFS_CLIENT_IDS=owned
fs_start ids
JFS_CLIENT_IDS=direct
client_start "$RESULTS/direct"
DIRECT=$RESULTS/direct
me="$(id -u):$(id -g)"

# refused <errno text> cmd…: the command fails with that error.
refused() {
    local want=$1 out
    shift
    if out=$("$@" 2>&1); then
        fail "$* succeeded; expected $want"
    fi
    [[ "$out" == *"$want"* ]] || fail "$* failed with '$out'; expected $want"
}

touch "$EXPORT/theirs" "$MNT/mine"
[ "$(stat -c %u:%g "$MNT/mine")" = "$me" ] || fail "a file this mount created shows as $(stat -c %u:%g "$MNT/mine"), not $me"
refused "Invalid argument" chown 4242 "$MNT/mine"
# A group the user is in besides their own: their kernel would let them give it the file, so a refusal through the direct mount is the server's.
other_group=$(id -G | tr ' ' '\n' | grep -vx "$(id -g)" | head -1 || true)
if [ -n "$other_group" ]; then
    refused "Invalid argument" chgrp "$other_group" "$MNT/mine"
    refused "Operation not permitted" chgrp "$other_group" "$DIRECT/mine"
else
    log "SKIPPED the chgrp checks: $(id -un) is in no group but their own"
fi
if [ "$(id -u)" = 0 ]; then
    chown 4242:4242 "$EXPORT/theirs"
    [ "$(stat -c %u:%g "$MNT/theirs")" = "65534:65534" ] || fail "another user's file shows as $(stat -c %u:%g "$MNT/theirs") on the owned mount"
    [ "$(stat -c %u:%g "$DIRECT/theirs")" = "65534:65534" ] || fail "the flattening server sent another user's owner to a direct mount: $(stat -c %u:%g "$DIRECT/theirs")"
fi
log "owners: this user's pass, anyone else's are refused, by the client on the owned mount and by the server on the direct one"

command -v setfacl > /dev/null && command -v getfacl > /dev/null || { log "SKIPPED the ACL checks: setfacl or getfacl missing (package acl)"; exit 0; }
if ! setfacl -m u:4242:r "$EXPORT/theirs" 2> /dev/null; then
    log "SKIPPED the ACL checks: $(stat -f -c %T "$EXPORT") takes no POSIX ACLs"
    exit 0
fi
# The kernel refuses POSIX ACLs on a FUSE mount outside the initial user namespace unless the daemon asks for FUSE_POSIX_ACL, which this one does not (a rootless container, for one).
if ! out=$(setfacl -m "u:$(id -u):r" "$MNT/mine" 2>&1); then
    [[ "$out" == *"Operation not supported"* ]] || fail "an ACL naming this user was refused: $out"
    log "SKIPPED the ACL checks: this kernel passes no POSIX ACLs through the mount ($out)"
    exit 0
fi
acl=$(getfacl -np "$EXPORT/mine")
grep -qx "user:$(id -u):r--" <<< "$acl" || fail "the ACL naming this user did not land on the export: $acl"
for mnt in "$MNT" "$DIRECT"; do
    acl=$(getfacl -np "$mnt/theirs")
    grep -qx 'user:65534:r--' <<< "$acl" || fail "an ACL entry for another user does not read as nobody through $mnt: $acl"
    if grep -q '4242' <<< "$acl"; then
        fail "another user's id reached $mnt: $acl"
    fi
done
refused "Invalid argument" setfacl -m u:65534:r "$MNT/mine"
refused "Operation not permitted" setfacl -m u:4242:r "$DIRECT/mine"
log "ACLs: this user's entries pass, anyone else's read as nobody and are refused"
