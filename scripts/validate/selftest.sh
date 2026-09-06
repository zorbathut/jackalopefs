#!/usr/bin/env bash
# Fixture tests for the parts of the harness that have logic of their own: the TAP parser and the baseline diff (tap.sh), the log check and the mount table parse (lib.sh).
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=lib.sh
source ./lib.sh
# shellcheck source=tap.sh
source ./tap.sh

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="/tmp/my tests/tests"

cat > "$work/prove.log" <<LOG
$root/clean/00.t ....
1..3
ok 1
ok 2 # skip not here
ok 3
ok
$root/fails/01.t ...
1..11
ok 1
not ok 2 - tried 'mknod pjdfstest_6099ecdf32fcbd08fd5a5e0d09d19b2c b 0644 1 2', expected 0, got EPERM
stat returned -1
not ok 3
not ok 4 - tried 'stat 0123456789abcdef0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210fedcba9876543210 type', expected char, got ENOENT
ok 5 # TODO known
foo: not ok really
not ok 6 - tried 'lstat pjdfstest_6099ecdf32fcbd08fd5a5e0d09d19b2c/pjdfstest_1099ecdf32fcbd08fd5a5e0d09d19b2c inode', expected 48913404, got 48914406
not ok 7 - tried 'stat pjdfstest_6099ecdf32fcbd08fd5a5e0d09d19b2c type,inode,mode,nlink', expected regular,48913404,0644,1, got ENOENT
not ok 11 - tried 'stat pjdfstest_6099ecdf32fcbd08fd5a5e0d09d19b2c type,inode,mode,nlink', expected regular,48913404,0644,1, got regular,48913404,0644,2
not ok 8 - tried 'stat pjdfstest_6099ecdf32fcbd08fd5a5e0d09d19b2c mode,uid,gid', expected 0644,65534,65534, got 0644,$(id -u),$(id -g)
not ok 9 - tried 'lstat pjdfstest_6099ecdf32fcbd08fd5a5e0d09d19b2c uid,gid', expected $(id -u),$(id -g), got 65534,65534
not ok 10 - tried '-u 65534 -g 65534 chown pjdfstest_6099ecdf32fcbd08fd5a5e0d09d19b2c $(id -u) $(id -g)', expected 0, got EPERM
Failed 8/10 subtests
$root/todo/02.t ....
1..2
not ok 1 # TODO Linux quirk
ok 2
ok
$root/cut/03.t ....
1..5
ok 1
ok 2
not ok 3
ok 4
Dubious, test returned 1 (wstat 256, 0x100)
Failed 1/5 subtests

Test Summary Report
-------------------
Files=4, Tests=20, 1 wallclock secs
Result: FAIL
LOG
printf '%s\n' clean/00.t fails/01.t todo/02.t cut/03.t gone/04.t > "$work/expected.txt"

tap_parse "$root" "$work/expected.txt" "$work/prove.log" "$work"

diff -u - "$work/failed.txt" <<EXPECT
cut/03.t:3
fails/01.t:10 tried '-u 65534 -g 65534 chown NAME $(id -u) $(id -g)', expected 0, got EPERM
fails/01.t:11 tried 'stat NAME type,inode,mode,nlink', expected regular,INODE_A,0644,1, got regular,INODE_A,0644,2
fails/01.t:2 tried 'mknod NAME b 0644 1 2', expected 0, got EPERM
fails/01.t:3
fails/01.t:4 tried 'stat NAME type', expected char, got ENOENT
fails/01.t:6 tried 'lstat NAME/NAME inode', expected INODE_A, got INODE_B
fails/01.t:7 tried 'stat NAME type,inode,mode,nlink', expected regular,INODE_A,0644,1, got ENOENT
fails/01.t:8 tried 'stat NAME mode,uid,gid', expected 0644,65534,65534, got 0644,SERVER_UID,SERVER_GID
fails/01.t:9 tried 'lstat NAME uid,gid', expected $(id -u),$(id -g), got 65534,65534
EXPECT
diff -u - "$work/harness.txt" <<EXPECT
cut/03.t planned 5 ran 4; Dubious, test returned 1 (wstat 256, 0x100)
gone/04.t missing from the log
EXPECT
[ "$(cat "$work/counts.txt")" = "files=4 checks=20 failed=10 harness=2" ] || { cat "$work/counts.txt"; exit 1; }

cat > "$work/baseline" <<BASE
# a reason
fails/01.t:2 tried 'mknod NAME b 0644 1 2', expected 0, got EPERM

# another reason
fails/01.t:9 was fixed
BASE
if baseline_diff "$work/failed.txt" "$work/baseline" "$work"; then echo "regressions not detected"; exit 1; fi
diff -u - "$work/regressions.txt" <<EXPECT
cut/03.t:3
fails/01.t:10 tried '-u 65534 -g 65534 chown NAME $(id -u) $(id -g)', expected 0, got EPERM
fails/01.t:11 tried 'stat NAME type,inode,mode,nlink', expected regular,INODE_A,0644,1, got regular,INODE_A,0644,2
fails/01.t:3
fails/01.t:4 tried 'stat NAME type', expected char, got ENOENT
fails/01.t:6 tried 'lstat NAME/NAME inode', expected INODE_A, got INODE_B
fails/01.t:7 tried 'stat NAME type,inode,mode,nlink', expected regular,INODE_A,0644,1, got ENOENT
fails/01.t:8 tried 'stat NAME mode,uid,gid', expected 0644,65534,65534, got 0644,SERVER_UID,SERVER_GID
fails/01.t:9 tried 'lstat NAME uid,gid', expected $(id -u),$(id -g), got 65534,65534
EXPECT
diff -u - "$work/fixed.txt" <<EXPECT
fails/01.t:9 was fixed
EXPECT
cp "$work/failed.txt" "$work/baseline"
baseline_diff "$work/failed.txt" "$work/baseline" "$work" || { echo "clean diff reported regressions"; exit 1; }
[ ! -s "$work/fixed.txt" ] || { echo "clean diff reported fixes"; exit 1; }

# log_check: a coloured ERROR line (as a binary on a terminal would write it) must fail the run and land in errors.txt; warnings are counted without fuser's not-implemented notices.
RESULTS=$work/logs
mkdir -p "$RESULTS"
printf '\033[2m2026-09-06T06:18:22.690831Z\033[0m \033[31mERROR\033[0m \033[2mjackalopefs_server\033[0m\033[2m:\033[0m boom\n2026-09-06T06:18:23.000000Z  WARN fuser: Not Implemented\n2026-09-06T06:18:24.000000Z  WARN jackalopefs_server::watch: inotify queue overflowed\n' > "$RESULTS/server.log"
STOP_RC=0
log_check > "$work/log_check.out"
[ "$STOP_RC" = 1 ] || { echo "log_check missed the ERROR line"; exit 1; }
grep -q 'ERROR jackalopefs_server: boom' "$RESULTS/errors.txt" || { echo "errors.txt lacks the stripped ERROR line:"; cat "$RESULTS/errors.txt"; exit 1; }
grep -q '1 warnings' "$work/log_check.out" || { echo "warning count wrong:"; cat "$work/log_check.out"; exit 1; }
printf '2026-09-06T06:18:22.690831Z  INFO jackalopefs_server: exporting\n' > "$RESULTS/server.log"
STOP_RC=0
log_check > /dev/null
[ "$STOP_RC" = 0 ] || { echo "log_check failed a clean log"; exit 1; }

# mounts_under: mountinfo lines with and without optional fields before the separator; only FUSE mounts below the directory count.
cat > "$work/mountinfo" <<MI
100 50 0:60 / /repo/validation/results/fsx/mnt rw,nosuid,nodev,relatime shared:70 - fuse.jackalopefs jackalopefs rw,user_id=1000
101 50 0:61 / /repo/validation/results/coherence/mnt-b rw,nosuid,nodev,relatime - fuse.jackalopefs jackalopefs rw,user_id=0
102 50 8:1 / /repo/validation/results/other rw,relatime shared:1 master:2 - ext4 /dev/sda1 rw
103 50 0:62 / /elsewhere/mnt rw,relatime shared:2 - fuse.sshfs sshfs rw
104 50 0:63 / /repo/validation/results-root/pjdfstest/mnt rw,relatime - fuse.jackalopefs jackalopefs rw
105 50 0:64 / /repo/validation/results/with\040space/mnt rw,relatime shared:3 - fuse.jackalopefs jackalopefs rw
MI
diff -u - <(mounts_under /repo/validation/results "$work/mountinfo") <<EXPECT
/repo/validation/results/fsx/mnt
/repo/validation/results/coherence/mnt-b
/repo/validation/results/with space/mnt
EXPECT
echo "selftest ok"
