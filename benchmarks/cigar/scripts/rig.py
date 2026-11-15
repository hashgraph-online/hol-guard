"""Shared paths for the CIGAR gauntlet scripts.

CIGAR_GAUNTLET_WORK: rig root (default /tmp/cigar-gauntlet). Keep it outside ~/.claude: Claude Code's
sandbox refuses writes there. HOL_GUARD_SRC: hol-guard checkout whose scripts/ holds the bench helpers
(default: the checkout these scripts live in; read only).
"""

import os
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
REFS = BENCH / "references"
WORK = Path(os.environ.get("CIGAR_GAUNTLET_WORK", "/tmp/cigar-gauntlet")).resolve()
GUARD_SRC = Path(os.environ.get("HOL_GUARD_SRC", BENCH.parent.parent))
REPOS_DIR = WORK / "r"
ARMS = WORK / "arms"
PROJECTS = WORK / "projects"
RUNS = WORK / "runs"
GVENV = WORK / "gvenv"
GHOME = WORK / "ghome"
SEEDS = [68, 69, 70, 71, 72, 73, 74, 75]
ARM_HARNESS = {"base": "codex", "cigar": "codex", "clbase": "claude-code", "clcigar": "claude-code"}


def pool_path(repo):
    return REFS / "pools" / f"{repo}.json"
