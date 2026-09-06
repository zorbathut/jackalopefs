#!/usr/bin/env bash
# Two mounts of one export with 60 s cache TTLs: what one changes, the other must see within 2 s, which only server push can deliver. Then fsstress on one mount while the other reads everything it can find, to shake the invalidation path under load.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

FSSTRESS=$TOOLS/xfstests/ltp/fsstress
need_tool "$FSSTRESS"
ttl=(--entry-timeout 60s --attr-timeout 60s)
fs_start coherence "${ttl[@]}"
A=$MNT
B=$RESULTS/mnt-b
client_start "$B" "${ttl[@]}"

log "create on A, visible on B"
ls "$B" > /dev/null
echo hello > "$A/f"
wait_for 2 cmp -s "$B/f" "$EXPORT/f" || fail "B did not see the new file within 2 s"
log "append on A after B cached the file"
cat "$B/f" > /dev/null
echo more >> "$A/f"
wait_for 2 cmp -s "$B/f" "$EXPORT/f" || fail "B did not see the appended data within 2 s"
log "rename and delete on A"
mv "$A/f" "$A/g"
wait_for 2 sh -c "[ ! -e '$B/f' ] && cmp -s '$B/g' '$EXPORT/g'" || fail "B did not see the rename within 2 s"
rm "$A/g"
wait_for 2 sh -c "[ ! -e '$B/g' ]" || fail "B did not see the delete within 2 s"
log "change made directly on the export"
echo direct > "$EXPORT/h"
wait_for 2 cmp -s "$B/h" "$EXPORT/h" || fail "B did not see a server-side change within 2 s"

log "fsstress on A while B reads"
(
    while [ ! -e "$RESULTS/stop-load" ]; do
        timeout 30 find "$B/stress" -type f -print0 2>/dev/null | timeout 30 xargs -0 -r cat > /dev/null 2>> "$RESULTS/reader.err" || true
        sleep 0.1
    done
) &
READER=$!
rc=0
fs_run "$TOOL_TIMEOUT" "$RESULTS/fsstress.log" "$FSSTRESS" -d "$A/stress" -p 2 -n "${FSSTRESS_OPS:-500}" -s 7 -v || rc=$?
touch "$RESULTS/stop-load"
wait "$READER" 2>/dev/null || true
[ "$rc" = 0 ] || fail "fsstress exited with status $rc"
# Names vanish under the reader's feet, which is expected; anything else is not.
if grep -v -e 'No such file' -e 'Is a directory' "$RESULTS/reader.err" | grep -q .; then
    grep -v -e 'No such file' -e 'Is a directory' "$RESULTS/reader.err" | sort | uniq -c | sort -rn | head
    fail "the reader on B saw errors other than ENOENT"
fi
log "B matches the export after the load"
# B's TTLs are 60 s, so this asserts push: everything fsstress changed must have been invalidated on B within 5 s of it stopping.
fs_check_consistent 5 10 1 "$B"
