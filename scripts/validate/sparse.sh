#!/usr/bin/env bash
# Holes through the mount: lseek(SEEK_DATA/SEEK_HOLE) must draw the same map of a sparse file as the export's filesystem does, and a copy that skips holes must never skip data, least of all data the kernel has cached and the server has not seen yet.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

command -v xfs_io >/dev/null || fail "xfs_io not found (package xfsprogs)"
command -v perl >/dev/null || fail "perl not found"
fs_start sparse

# 64 MiB with data at the start, in the middle and at the end.
size=$(( 64 << 20 ))
truncate -s "$size" "$EXPORT/sparse"
for at in 0 24 63; do
    dd if=/dev/urandom of="$EXPORT/sparse" bs=1M seek="$at" count=1 conv=notrunc status=none
done
sync "$EXPORT/sparse"

# seek_map <file>: every data and hole segment, as xfs_io walks them with lseek.
seek_map() { xfs_io -r -c "seek -a -r 0" "$1"; }
seek_map "$EXPORT/sparse" > "$RESULTS/map-export.txt"
seek_map "$MNT/sparse" > "$RESULTS/map-mnt.txt"
cat "$RESULTS/map-mnt.txt"
grep -q HOLE "$RESULTS/map-export.txt" || fail "the export's filesystem reports no hole in a sparse file, so this run proves nothing"
diff -u "$RESULTS/map-export.txt" "$RESULTS/map-mnt.txt" || fail "the mount maps the file differently from the export"

log "copy off the mount, skipping holes"
cp --sparse=auto "$MNT/sparse" "$RESULTS/copy"
cmp "$EXPORT/sparse" "$RESULTS/copy" || fail "the copy differs from the file"

# A process has just written into a hole, and the data is in this kernel's cache and nowhere else. The server would call that range a hole, so a seek through a descriptor opened before the write (opening a file flushes it) must find the data or be refused, never skip it; and a copy made meanwhile must have it.
log "seek and copy while a writer's data is still cached"
perl -e '
    use Fcntl qw(O_RDONLY O_RDWR SEEK_SET);
    use Errno qw(EINVAL);
    my ($src, $dst) = @ARGV;
    my $at = 40 << 20;
    sysopen(my $reader, $src, O_RDONLY) or die "open: $!";
    sysopen(my $writer, $src, O_RDWR) or die "open: $!";
    sysseek($writer, $at, SEEK_SET) or die "seek: $!";
    syswrite($writer, "written into a hole") or die "write: $!";
    my $found = sysseek($reader, $at, 3); # SEEK_DATA
    if (defined $found) {
        $found == $at or die "SEEK_DATA skipped cached data: found " . ($found + 0) . ", the data is at $at\n";
    } else {
        $! == EINVAL or die "SEEK_DATA: $!";
    }
    system("cp", "--sparse=auto", $src, $dst) == 0 or die "cp failed";
    system("cmp", $src, $dst) == 0 or die "the copy lost cached data";
' "$MNT/sparse" "$RESULTS/copy-cached" || fail "holes are wrong while the file is being written"

fs_check_consistent $(( ATTR_TTL + 1 )) 1 "$size"
