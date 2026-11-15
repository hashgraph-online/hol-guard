#!/bin/bash
# cleanup.sh [--all]: stop the rig's Guard daemon and remove login copies and session copies.
# --all also deletes the whole rig ($CIGAR_GAUNTLET_WORK); keep it to rerun later without setup.
set -uo pipefail
W=${CIGAR_GAUNTLET_WORK:-/tmp/cigar-gauntlet}
[ -d "$W" ] || { echo "no rig at $W"; exit 0; }
if [ -x "$W/gvenv/bin/hol-guard" ]; then
  HOME="$W/ghome" "$W/gvenv/bin/hol-guard" daemon stop --home "$W/ghome" --guard-home "$W/ghome/.hol-guard" >/dev/null 2>&1
fi
rm -f "${W:?}"/arms/*/codex_home/auth.json
rm -rf "${W:?}/projects" "${W:?}/notes"
ls "$W"/arms/*/codex_home/auth.json 2>/dev/null && echo "login copy still present" || echo "no login copies left"
pgrep -f "$W/gvenv" >/dev/null && echo "rig processes still running:" && pgrep -fl "$W/gvenv" | cut -c1-120
if [ "${1:-}" = "--all" ]; then rm -rf "${W:?}"; echo "removed $W"; fi
