#!/bin/bash
# lang_batch.sh <tag> <go|rust|ts> "<arm> ..." seed...: the language set's batch (lang_run.py), any harness.
# Same loop as batch.sh: CIGAR_GAUNTLET_JOBS=N sessions at once (default 4); Codex arms get a copy of
# ~/.codex/auth.json for the run and the last batch using an arm removes it. Oh My Pi and Claude Code
# arms use their own logins. Run one tag per language so report.py gives each language its own result.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${CIGAR_GAUNTLET_WORK:-/tmp/cigar-gauntlet}
W=$(cd "$W" && pwd -P) || { echo "no rig at $W; run setup.sh first"; exit 2; }
export CIGAR_GAUNTLET_WORK=$W
tag=${1:?tag} lang=${2:?lang} arms=${3:?arms}; shift 3
seeds=${*:?seeds}
logs="$W/runs/$tag/logs"; mkdir -p "$logs"
users="auth-users.$tag.$$"
# Each arm's login copy is shared by the batches using that arm. auth_lock.py adds and
# removes this batch's marker under a kernel lock, so a finishing batch cannot remove
# the copy another batch has just put in place, and a killed batch leaves no lock behind.
release() {
  for a in $arms; do
    home="$W/arms/$a/codex_home"
    [ -d "$home" ] || continue
    python3 "$HERE/auth_lock.py" "$home" give "$users"
  done
}
trap release EXIT
# Each worker runs in its own process group (set -m), so a cancelled batch stops every worker
# and the harness under it, and waits for them, before release can remove the login copy.
pids=()
stop() {
  trap '' INT TERM HUP
  for p in ${pids[@]+"${pids[@]}"}; do kill -TERM -- "-$p" 2>/dev/null; done
  for p in ${pids[@]+"${pids[@]}"}; do wait "$p" 2>/dev/null; done
  exit 130
}
trap stop INT TERM HUP
for a in $arms; do
  home="$W/arms/$a/codex_home"
  if [ -d "$home" ]; then
    python3 "$HERE/auth_lock.py" "$home" take "$users" || exit 1
  fi
done
jobs_max=${CIGAR_GAUNTLET_JOBS:-4}
set -m
for s in $seeds; do
  for a in $arms; do
    while [ "$jobs_max" -gt 0 ] && [ "$(jobs -rp | wc -l)" -ge "$jobs_max" ]; do sleep 5; done
    python3 "$HERE/lang_run.py" --arm "$a" --seed "$s" --tag "$tag" --lang "$lang" > "$logs/$a-$s.log" 2>&1 &
    pids+=($!)
  done
done
# A session that exits before writing its row fails the batch.
failed=0
for p in ${pids[@]+"${pids[@]}"}; do wait "$p" || failed=$((failed + 1)); done
echo "batch $tag done: $(wc -l < "$W/runs/$tag/results.jsonl" 2>/dev/null || echo 0) sessions"
[ "$failed" -eq 0 ] || { echo "$failed session(s) failed; see $logs"; exit 1; }
