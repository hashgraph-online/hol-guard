"""The live cases added for earlier false-positive fixes run cleanly on the fixture.

Each case asks the agent to run its listed commands and report what they
printed. A command that exits non-zero reads to the oracle as a host tool
failure with no Guard deny, so a case whose command cannot succeed on the
fixture could never pass on any build.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.nested_package_fixtures import NESTED_PACKAGE_CASES

SCENARIOS = {scenario.id: scenario for scenario in load_catalog()}
BACKFILLED_CASES = (
    "omp-native-git-stage-then-status-trailing-report",
    "omp-native-git-commit-message-credential-word",
    "omp-native-sed-counted-print-range-sibling-file",
    "omp-native-ls-missing-name-in-sibling-hidden-folder",
    "omp-native-missing-file-fallback-then-cd-subfolder-status",
    "omp-native-route-folder-bracket-name-reads",
    *NESTED_PACKAGE_CASES,
    "omp-native-git-worktree-prune-then-list",
    "omp-native-shell-label-then-stdin-size",
    "omp-native-find-files-newer-than-date",
    "omp-native-find-print0-xargs-grep",
    "omp-native-shell-brace-sequence-loops",
    "omp-native-cd-folder-grep-unmatched-glob",
    "omp-native-tool-version-banners",
)


def _run(command: str, workspace: Path, home: Path) -> subprocess.CompletedProcess[str]:
    environment = {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "PATH": os.environ.get("PATH", ""),
    }
    return subprocess.run(
        ["bash", "-c", command], cwd=workspace, env=environment, capture_output=True, text=True, timeout=60
    )


@pytest.mark.skipif(
    os.name == "nt" or shutil.which("rg") is None or shutil.which("bash") is None,
    reason="needs bash and ripgrep",
)
@pytest.mark.parametrize("scenario_id", BACKFILLED_CASES)
def test_every_listed_command_exits_cleanly(tmp_path: Path, scenario_id: str) -> None:
    # A space in the fixture path checks the quoting the live runner applies.
    fixture = create_fixture(tmp_path / "fixture root", realistic=True, scenario_id=scenario_id)
    scenario = SCENARIOS[scenario_id].render(
        {"home": str(fixture.home), "workspace": str(fixture.workspace), "root": str(fixture.root)}
    )
    for command in scenario.commands:
        completed = _run(command, fixture.workspace, fixture.home)
        assert completed.returncode == 0, (command, completed.stderr)


def test_the_package_layout_is_only_added_for_its_own_cases(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fixture", realistic=True, scenario_id="omp-native-todo-plan")
    assert not (fixture.workspace / "packages" / "app").exists()
    assert not (fixture.workspace / "tsconfig.base.json").exists()
