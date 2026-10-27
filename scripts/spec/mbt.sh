#!/usr/bin/env bash
# Model-based testing of the server's and the client's session machines (spec/README.md, "Model-based testing").
#
#   scripts/spec/mbt.sh          replays random runs of the model's small instance against the server's code and the client's: JACKALOPEFS_MBT_TRACES of them (default 2000, in batches of 200), each up to JACKALOPEFS_MBT_STEPS steps (default 40), from JACKALOPEFS_MBT_SEED (default: a fresh one, printed); a failure names the seed, the run and the step
#   scripts/spec/mbt.sh corpus   remakes spec/mbt/corpus.json.gz, which every `cargo test` replays: the scenario runs of spec/session_small.qnt and spec/session_mbt.qnt, and for each of the model's witnesses a run reaching it, from fixed seeds; check.sh fails while the corpus is older than the model
#
# Needs Node, as check.sh does, which installs Quint.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SPEC=$ROOT/spec
export NO_COLOR=1
QUINT=$SPEC/node_modules/.bin/quint
# The model's witnesses, and the wrapper's own states the corpus must pass through (spec/session_mbt.qnt).
WITNESSES="neverChangeWaitsForCancels neverPublishable neverLostTwice neverFenced neverSuperseded neverResendRan neverTakeover neverReleaseHeld neverOrphanRan neverReopenSettled neverOwedSettled neverQuiescentHolding"

# What the corpus is made from; check.sh compares it with the corpus's.
model_hash() {
  cat "$SPEC/session.qnt" "$SPEC/session_small.qnt" "$SPEC/session_mbt.qnt" | sha256sum | cut -d' ' -f1
}

if [[ ${1:-} == hash ]]; then
  model_hash
  exit 0
fi

[[ -x $QUINT ]] || { echo "run scripts/spec/check.sh once first, which installs quint" >&2; exit 1; }

if [[ ${1:-} == corpus ]]; then
  WORK=$(mktemp -d -t jackalopefs-mbt.XXXXXX)
  trap 'rm -rf "$WORK"' EXIT
  (cd "$SPEC" && "$QUINT" test session_small.qnt --main session_small --out-itf "$WORK/{test}.itf.json" --verbosity 0 >/dev/null)
  (cd "$SPEC" && "$QUINT" test session_mbt.qnt --main session_mbt --out-itf "$WORK/{test}.itf.json" --verbosity 0 >/dev/null)
  missing=()
  for w in $WITNESSES; do
    # The seed is fixed, so the corpus is the same each time it is made from the same model.
    out=$(cd "$SPEC" && "$QUINT" run session_mbt.qnt --main session_mbt --init mbtInit --step mbtStep --mbt --invariant "$w" --max-samples 200000 --max-steps 40 --seed 11 --out-itf "$WORK/$w.itf.json" --verbosity 1 2>&1 || true)
    if grep -q '^\[violation\]' <<<"$out"; then
      echo "ok         $w"
    else
      rm -f "$WORK/$w.itf.json"
      missing+=("$w")
      echo "missing    $w: no run of 200000 reached it"
    fi
  done
  node - "$WORK" "$SPEC/mbt/corpus.json.gz" "$(model_hash)" "${missing[*]:-}" <<'EOF'
const fs = require('fs'), path = require('path'), zlib = require('zlib');
const [dir, out, hash, missing] = process.argv.slice(2);
const lines = [JSON.stringify({ hash, missing: missing ? missing.split(' ') : [] })];
for (const file of fs.readdirSync(dir).sort()) {
  lines.push(JSON.stringify({ name: path.basename(file, '.itf.json'), trace: JSON.parse(fs.readFileSync(path.join(dir, file))) }));
}
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, zlib.gzipSync(lines.join('\n') + '\n', { level: 9 }));
console.log(`${lines.length - 1} traces in ${path.relative(process.cwd(), out)}`);
EOF
  exit 0
fi

total=${JACKALOPEFS_MBT_TRACES:-2000}
seed=${JACKALOPEFS_MBT_SEED:-$RANDOM$RANDOM}
batch=200
echo "replaying $total random runs from seed $seed"
for ((done_ = 0; done_ < total; done_ += batch)); do
  n=$((total - done_ < batch ? total - done_ : batch))
  for crate in server client; do
    if ! out=$(JACKALOPEFS_MBT_TRACES=$n JACKALOPEFS_MBT_SEED=$((seed + done_)) cargo test --manifest-path "$ROOT/Cargo.toml" -p "jackalopefs-$crate" --lib mbt::random_runs_replay -- --ignored --nocapture 2>&1); then
      echo "$out" >&2
      echo "the $crate stopped at seed $((seed + done_)); JACKALOPEFS_MBT_SEED=$((seed + done_)) JACKALOPEFS_MBT_TRACES=$n scripts/spec/mbt.sh runs that batch again" >&2
      exit 1
    fi
  done
  echo "ok         $((done_ + n)) of $total"
done
