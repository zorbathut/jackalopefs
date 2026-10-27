#!/usr/bin/env bash
# Breaks the model of spec/ in the ways a real bug did or could, one at a time on a scratch copy, and checks that TLC on the tiny instance finds the violation of the invariant named for each. This is what shows the invariants are not vacuous; spec/README.md lists the mutations. Same prerequisites as check.sh, which installs them.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SPEC=$ROOT/spec
APALACHE_VERSION=0.62.1
export NO_COLOR=1
# TLC spills its state queue into the temp directory, tens of gigabytes for a full exploration, which a tmpfs /tmp cannot take; quint puts it wherever TMPDIR points.
export TMPDIR=${XDG_CACHE_HOME:-$HOME/.cache}/jackalopefs-spec/tmp
mkdir -p "$TMPDIR"
QUINT=$SPEC/node_modules/.bin/quint
[[ -x $QUINT ]] || { echo "run scripts/spec/check.sh once first, which installs quint" >&2; exit 1; }

# A port nothing listens on for each check, as in check.sh: an Apalache server still shutting down from the previous mutation could answer with that mutation's compiled spec.
endpoint() {
  local port=$((20000 + RANDOM % 20000))
  while (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do port=$((20000 + RANDOM % 20000)); done
  echo "localhost:$port"
}
WORK=$(mktemp -d -t jackalopefs-spec-mut.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

failures=0

# mutate <name> <invariant> <text in session.qnt, occurring once> <its replacement>
mutate() {
  local name=$1 inv=$2 old=$3 new=$4
  local dir=$WORK/$name
  mkdir -p "$dir"
  cp "$SPEC/session.qnt" "$SPEC/session_tiny.qnt" "$dir/"
  python3 - "$dir/session.qnt" "$old" "$new" <<'PY'
import sys, pathlib
path, old, new = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
text = path.read_text()
if text.count(old) != 1:
    sys.exit(f"the mutation's text occurs {text.count(old)} times, not once: {old}")
path.write_text(text.replace(old, new))
PY
  local started=$SECONDS out got
  if out=$("$QUINT" verify --backend=tlc --apalache-version="$APALACHE_VERSION" --server-endpoint="$(endpoint)" --invariant="$inv" "$dir/session_tiny.qnt" 2>&1); then
    got=$(grep -q '^\[ok\]' <<<"$out" && echo "not caught" || echo error)
  else
    got=$(grep -q '^\[violation\]' <<<"$out" && echo caught || echo error)
  fi
  printf '%-11s %-40s %-16s %4ds\n' "$got" "$name" "$inv" $((SECONDS - started))
  [[ $got == caught ]] || { [[ $got == error ]] && echo "$out" >&2; failures=$((failures + 1)); }
}

mutate fence_without_abandoned S1 \
  'if (ses.epoch == epoch) ses.runningOlder + ses.abandoned else 0' \
  'if (ses.epoch == epoch) ses.runningOlder else 0'
mutate send_without_cancels_wait S1 \
  '(not(ordered(call.kind)) or conn.cancels == 0)' \
  'true'
mutate giveup_never_counts S1 \
  "conns' = if (cancels) conns.setBy(q.conn, k => k.with(\"cancels\", k.cancels + 1)) else conns," \
  "conns' = conns,"
mutate resume_keeps_abandoned countsConsistent \
  '.with("running", 0).with("abandoned", 0).with("live", true).with("detached", false).with("handshakeLost", false)' \
  '.with("running", 0).with("live", true).with("detached", false).with("handshakeLost", false)'
mutate resume_forgets_running S1 \
  '.with("runningOlder", ses.runningOlder + ses.running).with("running", 0).with("abandoned", 0).with("live", true).with("detached", false)' \
  '.with("running", 0).with("abandoned", 0).with("live", true).with("detached", false)'
mutate begin_ignores_epoch S2 \
  'if (orderedReq(q) and ses.epoch != q.epoch) all {' \
  'if (false) all {'
mutate opens_unordered S3 \
  'pure def ordered(kind: Kind): bool = match kind { Release(_) => false | _ => true }' \
  'pure def ordered(kind: Kind): bool = match kind { Change => true | _ => false }'
mutate resend_opens_again S3 \
  'if (ses.handles.get(fh).by != 0) Kept' \
  'if (false) Kept'
mutate drop_forgets_living_sessions S1strong \
  'def resumable(s: int): bool = sessions.get(s).live or alive(s)' \
  'def resumable(s: int): bool = sessions.get(s).live'
mutate owed_never_sent owedNeverStuck \
  'client.owed.contains(fh) and not(REQS.exists(x => reqs.get(x).origin == OwedRelease(fh)' \
  'false and not(REQS.exists(x => reqs.get(x).origin == OwedRelease(fh)'
mutate owed_release_unordered S3 \
  'OfCall(c) => ordered(kindOf(c)) | NoOrigin => false | _ => true }' \
  'OfCall(c) => ordered(kindOf(c)) | Reopen(_) => true | _ => false }'
mutate owed_send_ignores_cancels S3 \
  'conn.published and conn.cancels == 0 and client.owed.contains(fh)' \
  'conn.published and client.owed.contains(fh)'
mutate reopen_giveup_uncounted S3 \
  'reqs'"'"' = reqs.set(r, q.with("cancelSent", true).with("counted", true)),
      conns'"'"' = conns.setBy(q.conn, k => k.with("cancels", k.cancels + 1)),
      client'"'"' = {
        val done = client.with("reopening"' \
  'reqs'"'"' = reqs.set(r, q.with("cancelSent", true)),
      conns'"'"' = conns,
      client'"'"' = {
        val done = client.with("reopening"'

echo
if [[ $failures -eq 0 ]]; then echo "every mutation was caught"; else echo "$failures mutation(s) not caught"; exit 1; fi
