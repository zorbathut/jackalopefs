#!/usr/bin/env bash
# Checks the Quint model of the session protocol (spec/) as spec/README.md describes: typecheck, the scenario runs, and TLC on the tiny instance finding each gap's trace and each reachability witness. With FULL=1 it also has TLC explore the tiny instance's whole state space for the invariants that must hold (about twenty minutes) and simulates the small instance. Every outcome is asserted: a gap that stops being reachable fails the script, which is the cue to move it out of design.md's gap list and out of S3's allowances.
#
# Needs Node and a JDK. The first run installs the pinned Quint into spec/node_modules (from spec/package-lock.json) and downloads the pinned Apalache, which carries TLC, into ~/.quint; `quint run` under FULL=1 also fetches its own evaluator binary. TLC is given an 8 GB heap.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SPEC=$ROOT/spec
APALACHE_VERSION=0.62.1
MUST_HOLD="S1 S1strong S2 S3 S3identity owedNeverStuck countsConsistent poolConsistent aliveIsCurrent"
MUST_FAIL="S3noG4"
WITNESSES="neverFenced neverSuperseded neverResendRan neverTakeover neverRefused neverOrphanRan neverReopenSettled neverOwedSettled neverQuiescentHolding"
# The fewest states TLC may report for the tiny instance: a model change that collapses the state space would otherwise pass as "no violation".
TINY_STATES_AT_LEAST=10000000
export NO_COLOR=1
# TLC spills its state queue into the temp directory, tens of gigabytes for a full exploration, which a tmpfs /tmp cannot take; quint puts it wherever TMPDIR points.
export TMPDIR=${XDG_CACHE_HOME:-$HOME/.cache}/jackalopefs-spec/tmp
mkdir -p "$TMPDIR"

if [[ ! -x $SPEC/node_modules/.bin/quint ]]; then
  echo "installing quint into spec/node_modules"
  (cd "$SPEC" && npm ci --silent --no-fund --no-audit)
fi
QUINT=$SPEC/node_modules/.bin/quint

# quint reuses any Apalache server already answering at its endpoint, whatever that server's version or state, so each run gets a port nothing listens on.
port=$((20000 + RANDOM % 20000))
while (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do port=$((20000 + RANDOM % 20000)); done
ENDPOINT=localhost:$port

# Apalache writes _apalache-out under the working directory, so work from a scratch one.
WORK=$(mktemp -d -t jackalopefs-spec.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
section() { echo; echo "== $*"; }

# Runs a quint command; prints "ok" or "violation" from its verdict line, else "error" with the output. A violation and an error both exit 1, so the verdict line is what tells them apart.
outcome() {
  local out
  if out=$("$@" 2>&1); then
    if grep -q '^\[ok\]' <<<"$out"; then echo ok; return; fi
  else
    if grep -q '^\[violation\]' <<<"$out"; then echo violation; return; fi
  fi
  echo "$out" >&2
  echo error
}

# Asserts a check's outcome, timing it.
expect() {
  local want=$1 what=$2; shift 2
  local started=$SECONDS got
  got=$(outcome "$@")
  printf '%-10s %-64s %5ds\n' "$got" "$what" $((SECONDS - started))
  [[ $got == "$want" ]] || fail "$what: expected $want, got $got"
}

tlc() { "$QUINT" verify --backend=tlc --apalache-version="$APALACHE_VERSION" --server-endpoint="$ENDPOINT" "$@"; }

section "typecheck"
for f in session session_small session_tiny; do
  "$QUINT" typecheck "$SPEC/$f.qnt" >/dev/null && echo "ok         $f.qnt" || fail "typecheck $f.qnt"
done

section "scenario runs"
if out=$("$QUINT" test "$SPEC/session_small.qnt" 2>&1); then echo "ok         session_small.qnt: $(grep -o '[0-9]* passing' <<<"$out")"; else echo "$out" >&2; fail "quint test session_small.qnt"; fi

section "TLC on session_tiny: each gap's trace, and each witness, must be found"
for inv in $MUST_FAIL; do
  expect violation "session_tiny: $inv must fail" tlc "$SPEC/session_tiny.qnt" --invariant="$inv"
done
for inv in $WITNESSES; do
  expect violation "session_tiny: $inv must fail" tlc "$SPEC/session_tiny.qnt" --invariant="$inv"
done

if [[ ${FULL:-0} == 1 ]]; then
  section "TLC on session_tiny: the whole state space, every invariant that must hold"
  started=$SECONDS
  # shellcheck disable=SC2086
  out=$(tlc "$SPEC/session_tiny.qnt" --invariants $MUST_HOLD 2>&1) || true
  states=$(grep -o '[0-9]* distinct states found' <<<"$out" | tail -1 | grep -o '^[0-9]*' || echo 0)
  if grep -q '^\[ok\]' <<<"$out"; then
    printf '%-10s %-64s %5ds\n' ok "session_tiny: $MUST_HOLD ($states distinct states)" $((SECONDS - started))
    [[ $states -ge $TINY_STATES_AT_LEAST ]] || fail "session_tiny has only $states distinct states; the model has shrunk"
  else
    echo "$out" >&2; fail "session_tiny: an invariant that must hold failed, or TLC did not finish"
  fi

  section "random simulation on session_small, ${SAMPLES:-20000} traces of 40 steps"
  started=$SECONDS
  # shellcheck disable=SC2086
  out=$("$QUINT" run "$SPEC/session_small.qnt" --invariants $MUST_HOLD --max-samples="${SAMPLES:-20000}" --max-steps=40 --seed=11 --verbosity=1 2>&1) || true
  if grep -q '^\[ok\]' <<<"$out"; then printf '%-10s %-64s %5ds\n' ok "session_small: $MUST_HOLD" $((SECONDS - started)); else echo "$out" >&2; fail "simulation found a violation or failed"; fi
else
  echo
  echo "FULL=1 adds TLC over session_tiny's whole state space and the simulation of session_small."
fi

echo
if [[ $failures -eq 0 ]]; then echo "all checks passed"; else echo "$failures check(s) failed"; exit 1; fi
