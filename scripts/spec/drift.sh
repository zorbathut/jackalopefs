#!/usr/bin/env bash
# Lists the commits that changed modelled code without touching the model or saying why it need not, so a change the model may not have followed is seen (spec/README.md, "Keeping it in sync"). A modelled file is one whose module doc says it is modelled in `spec/session.qnt` (the workspace test spec_refs checks those are the right files); a commit is fine if it also changes something under spec/, or its message has a line starting `Spec:`. Commits from before the files were first marked are not looked at. A report, not a check: it exits 0 unless git fails.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

MARKER='modelled in `spec/session.qnt`'
mapfile -t modelled < <(grep -rlE --include='*.rs' '^//!.*modelled in `spec/session\.qnt`' crates | sort)
if [[ ${#modelled[@]} -eq 0 ]]; then
  echo "no file is marked as modelled; the marker text in scripts/spec/drift.sh and crates/server/tests/spec_refs.rs must agree" >&2
  exit 1
fi
start=$(git log --format=%H -S"$MARKER" -- crates | tail -n 1)
if [[ -z $start ]]; then
  echo "the modelled files are not marked in any commit yet; nothing to report"
  exit 0
fi

drifted=()
while read -r hash subject; do
  if [[ -n $(git diff-tree --no-commit-id --name-only -r "$hash" -- spec) ]]; then continue; fi
  drifted+=("$(git rev-parse --short "$hash") $subject")
done < <(git log --format='%H %s' --invert-grep --grep='^Spec:' "$start..HEAD" -- "${modelled[@]}")

if [[ ${#drifted[@]} -eq 0 ]]; then
  echo "every change to the ${#modelled[@]} modelled files since they were marked ($(git rev-parse --short "$start")) touched the model or said why not"
else
  echo "changed modelled code without touching spec/ or a 'Spec:' line in the message:"
  printf '  %s\n' "${drifted[@]}"
fi
