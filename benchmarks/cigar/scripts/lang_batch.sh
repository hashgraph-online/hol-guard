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
    python3 "$HERE/lang_run.py" --arm "$a" --seed "$s" --tag "$tag" --lang "$lang" > "$logs/$a-$s.log" 2>&1 &
  done
done
wait
echo "batch $tag done: $(wc -l < "$W/runs/$tag/results.jsonl" 2>/dev/null || echo 0) sessions"
