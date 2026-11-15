#!/bin/bash
# batch.sh <tag> "<arm> ..." [seed ...]: run every arm on every seed at once (default seeds 68-75).
# CIGAR_GAUNTLET_JOBS=N runs at most N sessions at once (default 4; 0 = all). More at once share one
# cached prompt prefix and miss the provider cache more often, which costs ~15% more per run.
# Codex arms get a copy of ~/.codex/auth.json for the run; the last batch using an arm removes it.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${CIGAR_GAUNTLET_WORK:-/tmp/cigar-gauntlet}
W=$(cd "$W" && pwd -P) || { echo "no rig at $W; run setup.sh first"; exit 2; }
export CIGAR_GAUNTLET_WORK=$W
tag=${1:?tag} arms=${2:?arms}; shift 2
seeds=${*:-68 69 70 71 72 73 74 75}
logs="$W/runs/$tag/logs"; mkdir -p "$logs"
# Batches may overlap, so each arm's login copy lists the batches using it; the last one out removes it.
users="auth-users.$tag.$$"
for a in $arms; do
  if [ -d "$W/arms/$a/codex_home" ]; then
    touch "$W/arms/$a/codex_home/.$users"
    install -m 600 ~/.codex/auth.json "$W/arms/$a/codex_home/auth.json"
  fi
done
release() {
  for a in $arms; do
    home="$W/arms/$a/codex_home"
    [ -d "$home" ] || continue
    rm -f "$home/.$users"
    if ! compgen -G "$home/.auth-users.*" > /dev/null; then rm -f "$home/auth.json"; fi
  done
}
trap release EXIT
jobs_max=${CIGAR_GAUNTLET_JOBS:-4}
for s in $seeds; do
  for a in $arms; do
    while [ "$jobs_max" -gt 0 ] && [ "$(jobs -rp | wc -l)" -ge "$jobs_max" ]; do sleep 5; done
    CIGAR_GAUNTLET_WORK=$W python3 "$HERE/run.py" --arm "$a" --seed "$s" --tag "$tag" > "$logs/$a-$s.log" 2>&1 &
  done
done
wait
echo "batch $tag done: $(wc -l < "$W/runs/$tag/results.jsonl" 2>/dev/null || echo 0) sessions"
