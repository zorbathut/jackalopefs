#!/usr/bin/env bash
# Attribution aid for the pjdfstest baselines, not a suite: pjdfstest.sh over a copy of the tests in which block and character devices are replaced by regular files, then a comparison with the last real run. A check that fails in the real run and not here, or here with a different detail, failed because the server refuses devices; one that fails here with the same detail has another cause (docs/validation.md).
set -euo pipefail
source "$(dirname "$0")/lib.sh"

real=$RESULTS_ROOT/pjdfstest
[ -s "$real/counts.txt" ] || fail "no real run to compare with in $real; run pjdfstest.sh first"
copy=$RESULTS_ROOT/nodev/tools
rm -rf "$copy"
mkdir -p "$copy"
cp -r "$TOOLS/pjdfstest" "$copy/"
cp "$TOOLS/versions.txt" "$copy/"
# The type is a literal word in the type loops and in create_file calls; an explicit mknod names it literally or, in mknod/11.t, through its loop variable. misc.sh holds create_file's own device branches.
files=("$copy"/pjdfstest/tests/*/*.t "$copy"/pjdfstest/tests/misc.sh)
sed -i -E 's/\bblock\b/regular/g; s/\bchar\b/regular/g; s/mknod ([^ ]+) ([bc]|\$\{?type\}?) ([0-7]+) [0-9]+ [0-9]+/create \1 \3/g' "${files[@]}"
! grep -l -E 'mknod [^ ]+ ([bc]|\$)' "${files[@]}" || fail "device creations survived the substitution (listed above)"

# The baseline verdict means nothing here, so the suite's own output is kept rather than shown; only its completion is checked.
JFS_TOOLS=$copy JFS_RESULTS=$RESULTS_ROOT/nodev "$VALIDATE_DIR/pjdfstest.sh" > "$RESULTS_ROOT/nodev/pjdfstest.txt" 2>&1 || true
nodev=$RESULTS_ROOT/nodev/pjdfstest
[ -s "$nodev/counts.txt" ] && [ ! -s "$nodev/harness.txt" ] || fail "the run without devices did not complete; see $nodev and $RESULTS_ROOT/nodev/pjdfstest.txt"

# Sort the real run's failures by what happened to them without devices.
: > "$nodev/vanished.txt"
: > "$nodev/changed.txt"
: > "$nodev/persisting.txt"
awk -v out="$nodev" '
    NR == FNR { detail[$1] = substr($0, length($1) + 2); next }
    !($1 in detail) { print > (out "/vanished.txt"); next }
    detail[$1] == substr($0, length($1) + 2) { print > (out "/persisting.txt"); next }
    { print > (out "/changed.txt") }' "$nodev/failed.txt" "$real/failed.txt"
log "of $(wc -l < "$real/failed.txt") failures in the real run: $(wc -l < "$nodev/vanished.txt") vanished without devices (device cascades), $(wc -l < "$nodev/changed.txt") fail differently (expectations only a device meets), $(wc -l < "$nodev/persisting.txt") persist unchanged (another cause); lists in $nodev"
