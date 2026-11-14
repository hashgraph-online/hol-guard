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
import os
import shlex
import subprocess
from pathlib import Path

from ci.gauntlet.fixtures import create_fixture, filesystem_checks
from ci.gauntlet.git_allow_fixtures import (
    ECHO_WORKTREE,
    GIT_ALLOW_CASES,
    GIT_ALLOW_ECHO_WORKTREE_CASE,
    GIT_ALLOW_PLUMBING_CASE,
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


def test_the_plumbing_case_chain_runs_under_the_host_git(tmp_path: Path) -> None:
    """Git retires plumbing names over time; a step the host Git refuses never reaches the archive."""
    (case,) = [case for case in scenarios() if case["id"] == GIT_ALLOW_PLUMBING_CASE]
    (command,) = case["commands"]
    fixture = create_fixture(tmp_path / "fx", scenario_id=GIT_ALLOW_PLUMBING_CASE)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(fixture.home),
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    for step in command.split(" && "):
        subprocess.run(
            shlex.split(step), cwd=fixture.workspace, env=environment, check=True, capture_output=True, timeout=30
        )
    checks = filesystem_checks(fixture, str(case["oracle"]), GIT_ALLOW_PLUMBING_CASE)
    assert checks["git-allow-plumbing-reads-ran"] is True
