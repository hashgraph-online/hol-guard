"""The heredoc commit case has a README change to commit, and its checks see the commit."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture, filesystem_checks
from ci.gauntlet.heredoc_commit_fixtures import HEREDOC_COMMIT_CASE, heredoc_commit_checks


# The case command is a POSIX shell command; on Windows this resolves Git for Windows' sh.
SHELL = shutil.which("sh")
pytestmark = pytest.mark.skipif(SHELL is None, reason="the case command needs a POSIX shell")


def _shell(fixture_home: Path, workspace: Path, command: str) -> subprocess.CompletedProcess[str]:
    assert SHELL is not None
    environment = {
        "HOME": str(fixture_home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Gauntlet Fixture",
        "GIT_AUTHOR_EMAIL": "gauntlet@example.invalid",
        "GIT_COMMITTER_NAME": "Gauntlet Fixture",
        "GIT_COMMITTER_EMAIL": "gauntlet@example.invalid",
        "PATH": os.environ.get("PATH", ""),
    }
    if os.name == "nt":
        environment["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    return subprocess.run(
        [SHELL, "-c", command], cwd=workspace, env=environment, capture_output=True, text=True, check=False
    )


def test_the_case_command_commits_the_seeded_readme_change(tmp_path: Path) -> None:
    scenario = next(item for item in load_catalog() if item.id == HEREDOC_COMMIT_CASE)
    assert (scenario.expectation, scenario.oracle) == ("allow", "native-tools")
    (command,) = scenario.commands
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=HEREDOC_COMMIT_CASE)
    before = heredoc_commit_checks(fixture.workspace, HEREDOC_COMMIT_CASE)
    assert before and not any(before.values())
    completed = _shell(fixture.home, fixture.workspace, command)
    # Before the fixture left a change, this command answered "nothing to commit" with exit 1.
    assert completed.returncode == 0, completed.stdout + completed.stderr
    after = filesystem_checks(fixture, scenario.oracle, HEREDOC_COMMIT_CASE)
    assert all(after.values()), {name: ok for name, ok in after.items() if not ok}
    assert set(heredoc_commit_checks(fixture.workspace, HEREDOC_COMMIT_CASE)) <= set(after)


def test_other_cases_keep_an_unchanged_readme(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id="omp-native-git-compound-reads")
    assert heredoc_commit_checks(fixture.workspace, "omp-native-git-compound-reads") == {}
    status = _shell(fixture.home, fixture.workspace, "git status --porcelain -- README.md")
    assert status.returncode == 0 and status.stdout == ""
