"""The search and diff report cases find what their commands look for.

Each case asks the agent to report what every listed command printed. A
command that finds nothing exits 1, which the oracle reads as a host tool
failure with no Guard deny, so the case could never pass on any build.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.search_diff_fixtures import DIFF_EXCLUSION_CASE, SEARCH_WORDS_CASE

SCENARIOS = {scenario.id: scenario for scenario in load_catalog()}


def _run(command: str, workspace: Path, home: Path) -> subprocess.CompletedProcess[str]:
    environment = {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "PATH": os.environ.get("PATH", ""),
    }
    return subprocess.run(
        ["/bin/sh", "-c", command], cwd=workspace, env=environment, capture_output=True, text=True, timeout=30
    )


@pytest.mark.skipif(os.name == "nt" or shutil.which("rg") is None, reason="needs a POSIX shell and ripgrep")
@pytest.mark.parametrize("scenario_id", [SEARCH_WORDS_CASE, DIFF_EXCLUSION_CASE])
def test_every_listed_command_finds_its_content(tmp_path: Path, scenario_id: str) -> None:
    scenario = SCENARIOS[scenario_id]
    fixture = create_fixture(tmp_path / "fixture", realistic=True, scenario_id=scenario_id)
    for command in scenario.commands:
        completed = _run(command, fixture.workspace, fixture.home)
        assert completed.returncode == 0, (command, completed.stderr)


def test_the_content_is_only_added_for_its_own_case(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fixture", realistic=True, scenario_id="omp-native-todo-plan")
    assert not (fixture.workspace / "src/limits.ts").exists()
    assert "process.env" not in (fixture.workspace / "src/settings.ts").read_text(encoding="utf-8")
