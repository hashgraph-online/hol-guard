#!/bin/bash
# workflow_setup.sh: puts flit_core (the build backend of the workflow set's repos) in each of their
# venvs, so the build step makes a wheel with no network. Run once after setup.sh.
set -euo pipefail
W=${CIGAR_GAUNTLET_WORK:-/tmp/cigar-gauntlet}
for r in boltons click jinja moreit tomli; do
  "$W/r/$r/venv/bin/python" -m pip install -q 'flit_core>=3.9,<4'
done
echo "flit_core ready in 5 venvs"
