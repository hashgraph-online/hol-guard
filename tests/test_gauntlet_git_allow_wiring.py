"""Every git ALLOW scenario has to run with the git ALLOW fixture behind it.

A ``git-allow-*`` case tells the agent that git is allowed and that
``origin/main`` is one commit ahead locally. Only the cases listed in
``GIT_ALLOW_CASES`` get that policy and that origin. A case left out of the
set runs against a checkout with neither, so Guard correctly reviews a
worktree built from a ref that does not exist, and qualification reports a
false positive the product does not have.
"""

from __future__ import annotations

import json
from pathlib import Path

from ci.gauntlet.git_allow_fixtures import (
    ECHO_WORKTREE,
    GIT_ALLOW_CASES,
    GIT_ALLOW_ECHO_WORKTREE_CASE,
    GIT_ORIGIN_SHAPE_CASES,
)


def scenarios() -> list[dict[str, object]]:
    catalog = json.loads((Path(__file__).resolve().parents[1] / "ci/gauntlet/scenarios.json").read_text())
    return catalog["scenarios"]


def test_every_git_allow_scenario_gets_the_git_allow_fixture() -> None:
    ids = {str(case["id"]) for case in scenarios() if str(case["id"]).startswith("git-allow-")}
    assert ids, "the catalog carries no git ALLOW scenarios"
    assert ids - GIT_ALLOW_CASES == set()
    assert ids <= GIT_ORIGIN_SHAPE_CASES


def test_the_echo_case_checks_the_worktree_its_command_creates() -> None:
    (case,) = [case for case in scenarios() if case["id"] == GIT_ALLOW_ECHO_WORKTREE_CASE]
    (command,) = case["commands"]
    assert f"../{ECHO_WORKTREE} " in command
    assert f"cd ../{ECHO_WORKTREE} " in command
