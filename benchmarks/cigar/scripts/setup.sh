#!/bin/bash
# setup.sh <hol-guard wheel>: build the rig, or move it to another wheel, in $CIGAR_GAUNTLET_WORK
# (default /tmp/cigar-gauntlet). Safe to rerun: each step skips what is already in place.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${CIGAR_GAUNTLET_WORK:-/tmp/cigar-gauntlet}
WHEEL=$(cd "$(dirname "${1:?usage: setup.sh <hol-guard wheel>}")" && pwd)/$(basename "$1")
case "$W" in "$HOME"/.claude*) echo "CIGAR_GAUNTLET_WORK must be outside ~/.claude (Claude Code's sandbox refuses writes there)"; exit 1;; esac
mkdir -p "$W/ghome"
W=$(cd "$W" && pwd -P)  # physical path: Codex trusts the hook by its config file path
export CIGAR_GAUNTLET_WORK=$W
if [ ! -x "$W/gvenv/bin/python" ]; then
  python3 -m venv "$W/gvenv"
  "$W/gvenv/bin/python" -m pip install -q --disable-pip-version-check "$WHEEL"
else
  HOME="$W/ghome" "$W/gvenv/bin/hol-guard" daemon stop --home "$W/ghome" --guard-home "$W/ghome/.hol-guard" >/dev/null 2>&1 || true
  "$W/gvenv/bin/python" -m pip install -q --disable-pip-version-check --force-reinstall --no-deps "$WHEEL"
fi
echo "guard $("$W/gvenv/bin/python" -m pip show hol-guard | sed -n 's/^Version: //p')"
HOME="$W/ghome" USERPROFILE="$W/ghome" "$W/gvenv/bin/python" -I "$HERE/cigar_setup.py" "$W"
HOME="$W/ghome" "$W/gvenv/bin/python" -I "$HERE/make_arms.py" "$W"
HOME="$W/ghome" "$W/gvenv/bin/python" -I "$HERE/make_full_arms.py" "$W"
if command -v omp >/dev/null; then HOME="$W/ghome" "$W/gvenv/bin/python" -I "$HERE/make_omp_arms.py" "$W"; fi
python3 "$HERE/setup_repos.py"
