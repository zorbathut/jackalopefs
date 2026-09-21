#!/usr/bin/env bash
# A recycled inode number: a file this mount's kernel has cached is deleted on the export and another created that the filesystem gives the same inode number (ext4 does at once, as long as nothing holds the old file open). Through the mount the name must lead to the new file, contents and size, and never to what was cached for the old one. Whether numbers are recycled is the results filesystem's business, not ours: where they are not (tmpfs), the suite says so and checks nothing.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

fs_start recycle
shows() { [ "$(cat "$MNT/f" 2>/dev/null)" = "$1" ]; }

printf 'the first file' > "$EXPORT/f"
shows 'the first file' || fail "the mount does not show the file"
ino=$(stat -c %i "$EXPORT/f")
[ "$(stat -c %i "$MNT/f")" = "$ino" ] || fail "an ordinary file goes by inode number $(stat -c %i "$MNT/f") through the mount, $ino on the export"

rm "$EXPORT/f"
second='the second file, and longer'
recycled=
for _ in $(seq 1 200); do
    printf '%s' "$second" > "$EXPORT/f"
    if [ "$(stat -c %i "$EXPORT/f")" = "$ino" ]; then
        recycled=yes
        break
    fi
    rm "$EXPORT/f"
done
if [ -z "$recycled" ]; then
    log "SKIPPED: $(stat -f -c %T "$EXPORT") did not reuse inode number $ino in 200 tries, so there is nothing to check here"
    exit 0
fi
log "inode number $ino reused for another file"

wait_for $(( ATTR_TTL + 3 )) shows "$second" || fail "the name still leads to the old file: $(cat "$MNT/f")"
[ "$(stat -c %s "$MNT/f")" = "${#second}" ] || fail "the new file has the size $(stat -c %s "$MNT/f") through the mount"
log "the new file goes by inode number $(stat -c %i "$MNT/f") through the mount"
fs_check_consistent $(( ATTR_TTL + 1 )) 1 1
