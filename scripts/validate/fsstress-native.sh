#!/usr/bin/env bash
# The control for attributing fsstress.sh's expected failures: the same fsstress, seed and counts, run directly on the filesystem the export lives on, with no mount. What fails here too is the environment's or fsstress's own doing, not ours. The target directory must not exist beforehand, as it does not through the mount: fsstress probes it for btrfs before creating it and keeps its btrfs operations only when the probe fails.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
source "$VALIDATE_DIR/fsstress-parse.sh"

FSSTRESS=$TOOLS/xfstests/ltp/fsstress
need_tool "$FSSTRESS"
out=$RESULTS_ROOT/fsstress-native
rm -rf "$out"
mkdir -p "$out"
"$FSSTRESS" -d "$out/stress" -p "${FSSTRESS_PROCS:-4}" -n "${FSSTRESS_OPS:-1000}" -s "${FSSTRESS_SEED:-1}" -v > "$out/fsstress.log" 2>&1 || fail "fsstress exited with status $?"
fsstress_parse "$out/fsstress.log" "$out"
[ ! -s "$out/unparsed.txt" ] || { head -10 "$out/unparsed.txt"; fail "lines the parser does not know"; }
log "failed natively on $(stat -f -c %T "$out"), by op and result:"
awk '$2 != "0"' "$out/results.txt" | sort | uniq -c | sort -rn
