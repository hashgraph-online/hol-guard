#!/bin/bash
# workflow_batch.sh <tag> "<arm> ..." seed...: the workflow set's batch (workflow_run.py), any harness.
# Same loop as batch.sh: CIGAR_GAUNTLET_JOBS=N sessions at once (default 4); Codex arms get a copy of
# ~/.codex/auth.json for the run and the last batch using an arm removes it. Oh My Pi and Claude Code
# arms use their own logins.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${CIGAR_GAUNTLET_WORK:-/tmp/cigar-gauntlet}
W=$(cd "$W" && pwd -P) || { echo "no rig at $W; run setup.sh first"; exit 2; }
export CIGAR_GAUNTLET_WORK=$W
tag=${1:?tag} arms=${2:?arms}; shift 2
seeds=${*:?seeds}
logs="$W/runs/$tag/logs"; mkdir -p "$logs"
users="auth-users.$tag.$$"
# One lock per arm around taking and giving back the login, so a batch that is
# finishing cannot remove the copy another batch has just put in place.
# The lock holds its owner's pid; a lock whose owner has exited is taken over,
# so a batch killed while holding it cannot stall later batches.
held=""
lock() {
  until mkdir "$1/.auth-lock" 2>/dev/null; do
    owner=$(cat "$1/.auth-lock/pid" 2>/dev/null)
    if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
      rm -rf "$1/.auth-lock"
      continue
    fi
    sleep 1
  done
  echo $$ > "$1/.auth-lock/pid"
  held=$1
}
unlock() { rm -rf "$1/.auth-lock"; held=""; }
release() {
  for a in $arms; do
    home="$W/arms/$a/codex_home"
    [ -d "$home" ] || continue
    lock "$home"
    rm -f "$home/.$users"
    if ! compgen -G "$home/.auth-users.*" > /dev/null; then rm -f "$home/auth.json"; fi
    unlock "$home"
  done
}
cleanup() {
  # Give back a lock this batch still holds before release takes each one again.
  if [ -n "$held" ]; then unlock "$held"; fi
  release
}
trap cleanup EXIT
trap 'exit 130' INT TERM
for a in $arms; do
  home="$W/arms/$a/codex_home"
  if [ -d "$home" ]; then
    lock "$home"
    touch "$home/.$users"
    install -m 600 ~/.codex/auth.json "$home/auth.json"
    unlock "$home"
  fi
done
jobs_max=${CIGAR_GAUNTLET_JOBS:-4}
pids=()
for s in $seeds; do
  for a in $arms; do
    while [ "$jobs_max" -gt 0 ] && [ "$(jobs -rp | wc -l)" -ge "$jobs_max" ]; do sleep 5; done
    python3 "$HERE/workflow_run.py" --arm "$a" --seed "$s" --tag "$tag" > "$logs/$a-$s.log" 2>&1 &
    pids+=($!)
  done
done
# A session that exits before writing its row fails the batch.
failed=0
for p in "${pids[@]}"; do wait "$p" || failed=$((failed + 1)); done
echo "batch $tag done: $(wc -l < "$W/runs/$tag/results.jsonl" 2>/dev/null || echo 0) sessions"
[ "$failed" -eq 0 ] || { echo "$failed session(s) failed; see $logs"; exit 1; }
