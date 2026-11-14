#!/usr/bin/env bash
# Oh My Pi batch: ./batch_omp.sh <tag> "ompbase ompcigar" <seeds...>
# Same loop as batch.sh, but omp arms read omp's own login, so no Codex login is copied or removed
# and a Codex batch running at the same time keeps its own.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${CIGAR_GAUNTLET_WORK:-/tmp/cigar-gauntlet}
W=$(cd "$W" && pwd -P) || { echo "no rig at $W; run setup.sh first"; exit 2; }
export CIGAR_GAUNTLET_WORK=$W
tag=${1:?tag} arms=${2:?arms}; shift 2
seeds=${*:-68 69 70 71 72 73 74 75}
logs="$W/runs/$tag/logs"; mkdir -p "$logs"
for a in $arms; do
  [ "$(cat "$W/arms/$a/harness" 2>/dev/null)" = omp ] || { echo "$a is not an omp arm; run make_omp_arms.py"; exit 2; }
done
jobs_max=${CIGAR_GAUNTLET_JOBS:-4}
for s in $seeds; do
  for a in $arms; do
    while [ "$jobs_max" -gt 0 ] && [ "$(jobs -rp | wc -l)" -ge "$jobs_max" ]; do sleep 5; done
    CIGAR_GAUNTLET_WORK=$W python3 "$HERE/run.py" --arm "$a" --seed "$s" --tag "$tag" > "$logs/$a-$s.log" 2>&1 &
  done
done
wait
echo "batch $tag done: $(wc -l < "$W/runs/$tag/results.jsonl" 2>/dev/null || echo 0) sessions"
