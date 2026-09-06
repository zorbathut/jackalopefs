#!/usr/bin/env bash
# Deep mode: run suites as root inside a rootless podman container with /dev/fuse, which is what pjdfstest's uid-switching checks and permissions.sh need. Builds the image on first use; the binaries come from the host's target/debug and the results land in validation/results-root/.
# Usage: container.sh [suite.sh …]   (default: all.sh)
set -euo pipefail
cd "$(dirname "$0")"
REPO=$(cd ../.. && pwd)
IMAGE=localhost/jackalopefs-validate

command -v podman >/dev/null || { echo "podman is required for the deep mode" >&2; exit 1; }
podman image exists "$IMAGE" || podman build -t "$IMAGE" -f Dockerfile .
(cd "$REPO" && cargo build --workspace)
mkdir -p "$REPO/validation/results-root"
[ $# -gt 0 ] || set -- all.sh

# Every tunable crosses into the container except the three that name host paths, which are set below for the container's layout.
env_args=()
while IFS= read -r kv; do env_args+=(-e "$kv"); done < <(env | grep -E '^(JFS_|FSX_|FSSTRESS_|RUST_LOG=)' | grep -Ev '^JFS_(TOOLS|BIN|RESULTS)=' || true)
# --cap-add SYS_ADMIN is what lets mount(2) through the seccomp filter as well as granting the capability; the export and results stay on the host's filesystem through the bind mount.
exec podman run --rm --device /dev/fuse --cap-add SYS_ADMIN --network none \
    -v "$REPO:/repo" -e JFS_TOOLS=/opt/tools -e JFS_BIN=/repo/target/debug -e JFS_RESULTS=/repo/validation/results-root "${env_args[@]}" \
    "$IMAGE" bash -c 'cd /repo/scripts/validate && rc=0; for s in "$@"; do "./$s" || rc=1; done; exit $rc' _ "$@"
