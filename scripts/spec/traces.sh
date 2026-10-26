#!/usr/bin/env bash
# Trace validation (spec/README.md, "Trace validation"): runs the fault tests with the client and server recording what they do in the session model's terms, then replays every trace against the model (spec/replay.qnt) with `quint test`. Arguments are passed to the test binaries as a filter (`scripts/spec/traces.sh write::`), so one case can be replayed alone. A pass says those interleavings, the ones the runs happened to take, are behaviours of the model.
#
# With REPLAY_ONLY=1 the traces recorded last are replayed again, as after a change to spec/replay.qnt or the model.
#
# Needs Node, as check.sh does. Each trace's events are kept in target/spec-traces/<run>.log, and the assembled modules in target/spec-traces/traces-<n>.qnt with quint's output in traces-<n>.out, for reading a failure: quint names the run and the step it stopped at, and the script shows the events around it: step n is event n - 1, or a little earlier where replay took a loss as a step of its own.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SPEC=$ROOT/spec
OUT=$ROOT/target/spec-traces
BATCH=30
export NO_COLOR=1

if [[ ! -x $SPEC/node_modules/.bin/quint ]]; then
  echo "installing quint into spec/node_modules"
  (cd "$SPEC" && npm ci --silent --no-fund --no-audit)
fi
QUINT=$SPEC/node_modules/.bin/quint

if [[ ${REPLAY_ONLY:-0} != 1 ]]; then
  rm -rf "${OUT:?}"
  mkdir -p "$OUT"
  echo "== recording"
  # A test that fails writes no trace, so a failure here fails the validation.
  if ! tests=$(JACKALOPEFS_SPEC_TRACES=$OUT cargo test --manifest-path "$ROOT/Cargo.toml" -p jackalopefs-client --features spec-trace,jackalopefs-server/spec-trace --test disconnect --test roundtrip -- "$@" 2>&1); then
    echo "$tests" >&2
    echo "the tests failed while recording" >&2
    exit 1
  fi
  grep -E '^test result' <<<"$tests"
fi

shopt -s nullglob
parts=("$OUT"/*.qnt.part)
if [[ ${#parts[@]} -eq 0 ]]; then
  echo "no traces were recorded" >&2
  exit 1
fi
# In batches, which quint replays apart and four at a time: one module of every trace runs Node out of heap.
rm -f "$OUT"/traces-*.qnt "$OUT"/traces-*.out
batch=0
for ((i = 0; i < ${#parts[@]}; i += BATCH)); do
  {
    echo "// Traces the fault tests recorded, assembled by scripts/spec/traces.sh."
    echo "module traces {"
    echo "  import replay.* from \"../../spec/replay\""
    cat "${parts[@]:i:BATCH}"
    echo "}"
  } > "$OUT/traces-$batch.qnt"
  batch=$((batch + 1))
done

echo "== replaying ${#parts[@]} traces in $batch batches"
# A batch's output, and whether it passed, go to traces-N.out.
printf '%s\n' "$OUT"/traces-*.qnt | xargs -P 4 -I{} sh -c '"$1" test "$2" > "${2%.qnt}.out" 2>&1; echo "exit $?" >> "${2%.qnt}.out"' _ "$QUINT" {}
out=$(cat "$OUT"/traces-*.out)
passing=$(grep -oE '[0-9]+ passing' <<<"$out" | awk '{n += $1} END {print n + 0}')
if ! grep -q '^exit [^0]' <<<"$out" && [[ $passing -eq ${#parts[@]} ]]; then
  echo "$passing passing"
  exit 0
fi
echo "$passing of ${#parts[@]} traces replayed" >&2
# Each failure as its run, the step it stopped at, and the events recorded around that step; anything else quint said is shown whole.
failures=$(grep -oE '^\s+[0-9]+\) [A-Za-z0-9_]+Test:|iteration #[0-9]+' <<<"$out" | paste - - || true)
if [[ -z $failures ]]; then
  echo "$out" >&2
fi
while read -r _ run _ step; do
  [[ -z $run ]] && continue
  run=${run%Test:}
  # Steps count from 1 and events from 0, and the log's line n + 1 is event n.
  event=$((${step#\#} - 1))
  echo "-- $run, stopped at event $event:" >&2
  sed -n "$((event > 1 ? event - 1 : 1)),$((event + 3))p" "$OUT/$run.log" | cut -c1-240 >&2
done <<<"$failures"
exit 1
