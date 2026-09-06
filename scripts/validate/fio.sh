#!/usr/bin/env bash
# Concurrent verified I/O with fio: eight processes write their own files and read every block back against a checksum. fio runs from the results directory so its state files stay off the mount.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

command -v fio >/dev/null || fail "fio not found (package fio)"
fs_start fio
mkdir "$MNT/fio"
rc=0
fs_run "$TOOL_TIMEOUT" "$RESULTS/fio.out" env -C "$RESULTS" fio --directory="$MNT/fio" --eta=never --output="$RESULTS/fio.log" "$VALIDATE_DIR/verify.fio" || rc=$?
grep -E '^\s*(randwrite|seqwrite):|err=' "$RESULTS/fio.log" | head -8
[ "$rc" = 0 ] || fail "fio exited with status $rc; see $RESULTS/fio.log"
fs_check_consistent $(( ATTR_TTL + 1 )) 8 $(( 8 * 32 * 1024 * 1024 ))
