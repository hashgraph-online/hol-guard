"""Seed a shell script whose calls differ only by their options.

Its ``--help`` is rejected as an unknown argument, so Guard has to read the
variations from the script's own source: the usage comment and the ``case``
arms. The custom-extension spec runs it through a hook, loads its commands in
the dashboard, allows one option and blocks another, and checks what the hook
then decides for each.

The script sits under the isolated home, outside the workspace, so a call to it
is a custom extension and not workspace work.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import SeedContext

SCRIPT = """#!/usr/bin/env bash
# Tag and publish a synthetic release.
#
# Usage: release.sh <version> [--repo owner/name] [--notes DIR]
#                   [--skip-billing] [--dry-run]
set -euo pipefail
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO=$2; shift 2 ;;
    --notes) NOTES=$2; shift 2 ;;
    --skip-billing) SKIP=1; shift ;;
    --dry-run) DRY=1; shift ;;
    [0-9]*) VERSION=$1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
echo "release ${VERSION:-none} dry=${DRY:-0} skip=${SKIP:-0} repo=${REPO:-} notes=${NOTES:-}"
"""

OPTIONS = ["--repo", "--notes", "--skip-billing", "--dry-run"]


def seed(context: SeedContext) -> dict[str, Any]:
    del context
    tools = Path.home() / "tools"
    tools.mkdir(mode=0o700, exist_ok=True)
    script = tools / "release.sh"
    script.write_text(SCRIPT, encoding="utf-8")
    script.chmod(0o700)
    return {"script": str(script), "name": script.name, "options": OPTIONS}
