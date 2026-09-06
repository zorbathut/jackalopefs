#!/usr/bin/env bash
# Fetch and build the external validation tools at pinned revisions: pjdfstest, and fsx and fsstress from xfstests.
# Usage: tools.sh <dir>   (the host uses validation/tools, the container image /opt/tools). Idempotent: a tool whose binary exists is skipped.
set -euo pipefail

PJDFSTEST_REV=85a8aea9e685999ef0540392fd80535f873d7ff7
PJDFSTEST_SHA256=2005cdd83b76204177cf136792b1f2058a7418b4fc5b203f51274a698547d754
XFSTESTS_TAG=v2026.09.02
XFSTESTS_SHA256=4a8a4414e191c179bc9dd3cb0bebd7ad7d58828f985290b347c2db3e7a6ec721

dest=${1:?usage: tools.sh <dir>}
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)

# Prerequisites, each named by the Arch package that provides it so the message is actionable; other distros map the names themselves.
missing=()
need() { command -v "$1" >/dev/null 2>&1 || missing+=("$2"); }
need_header() { [ -e "$1" ] || missing+=("$2"); }
need gcc base-devel
need make base-devel
need autoreconf base-devel
need libtoolize base-devel
need pkg-config base-devel
need curl curl
need perl perl
need fio fio
need fusermount3 fuse3
need_header /usr/include/xfs/xfs.h xfsprogs
need_header /usr/include/acl/libacl.h acl
need_header /usr/include/uuid/uuid.h util-linux-libs
need_header /usr/include/libaio.h libaio
need_header /usr/include/liburing.h liburing
need_header /usr/include/gdbm.h gdbm
need_header /usr/include/sys/capability.h libcap
if [ ${#missing[@]} -gt 0 ]; then
    echo "missing prerequisites; on Arch: pacman -S $(printf '%s\n' "${missing[@]}" | sort -u | tr '\n' ' ')" >&2
    exit 1
fi

# Download a tarball, check it against its pinned digest (a tag can move and an archive can be regenerated; the digest cannot), and unpack it into $3 without its top-level directory.
fetch() {
    local url=$1 sha=$2 dir=$3
    rm -rf "$dir" "$dir.tar.gz"
    mkdir -p "$dir"
    echo "fetching $url"
    curl -fsSL --retry 3 -o "$dir.tar.gz" "$url"
    echo "$sha  $dir.tar.gz" | sha256sum -c --quiet || { echo "$url does not match the pinned digest: the download is corrupt or upstream regenerated the archive; check it by hand and update the pin in tools.sh" >&2; exit 1; }
    tar -xz -C "$dir" --strip-components=1 -f "$dir.tar.gz"
    rm -f "$dir.tar.gz"
}

# Run a build, keeping the full log and showing its tail only when it fails.
build() {
    local log=$1
    shift
    if ! "$@" > "$log" 2>&1; then
        tail -30 "$log" >&2
        echo "build failed; full log in $log" >&2
        exit 1
    fi
}

if [ ! -x "$dest/pjdfstest/pjdfstest" ]; then
    fetch "https://github.com/pjd/pjdfstest/archive/$PJDFSTEST_REV.tar.gz" "$PJDFSTEST_SHA256" "$dest/pjdfstest"
    build "$dest/pjdfstest-build.log" sh -c "cd '$dest/pjdfstest' && autoreconf -ifs && ./configure && make pjdfstest"
    # tests/conf otherwise takes the name from `df -PT`, which says fuse.jackalopefs on the host and plain fuse under a direct root mount; pin it so both modes run the same checks.
    grep -q '^#fs="UFS"$' "$dest/pjdfstest/tests/conf" || { echo "tests/conf no longer has the #fs=\"UFS\" line to pin; look at what the new pjdfstest expects" >&2; exit 1; }
    sed -i 's/^#fs="UFS"$/fs="FUSE"/' "$dest/pjdfstest/tests/conf"
fi

if [ ! -x "$dest/xfstests/ltp/fsx" ] || [ ! -x "$dest/xfstests/ltp/fsstress" ]; then
    fetch "https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/snapshot/xfstests-dev-$XFSTESTS_TAG.tar.gz" "$XFSTESTS_SHA256" "$dest/xfstests"
    # The snapshot ships no configure script, and ltp/ links lib/, so this goes through the top-level make.
    build "$dest/xfstests-build.log" sh -c "cd '$dest/xfstests' && make configure && ./configure && make -j\"\$(nproc)\" ltp"
    # fsstress's only internal check (the cwd inode never changes) is compiled in by the configure default DEBUG=-DDEBUG.
    grep -q '^DEBUG = -DDEBUG' "$dest/xfstests/include/builddefs" || { echo "xfstests' configure no longer defaults DEBUG to -DDEBUG, which fsstress's cwd check needs" >&2; exit 1; }
fi

{
    echo "pjdfstest $PJDFSTEST_REV"
    echo "xfstests $XFSTESTS_TAG"
    echo "fio $(fio --version)"
    echo "kernel $(uname -r)"
    echo "built $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    if command -v pacman >/dev/null 2>&1; then pacman -Q; elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W; fi
} > "$dest/versions.txt"
echo "tools ready in $dest"
