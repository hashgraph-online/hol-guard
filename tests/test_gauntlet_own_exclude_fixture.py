"""The own-exclude check-ignore case runs in a checkout that names .git/info/exclude."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.git_exclude_fixtures import OWN_EXCLUDE_CASE


def _excludes_file(fixture_home: Path, workspace: Path) -> str:
    environment = {"HOME": str(fixture_home), "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.environ.get("PATH", "")}
    if os.name == "nt":
        environment["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    completed = subprocess.run(
        ["git", "-C", str(workspace), "config", "--local", "--get", "core.excludesFile"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip()


def test_the_case_checkout_names_its_own_exclude_file(tmp_path: Path) -> None:
    scenario = next(item for item in load_catalog() if item.id == OWN_EXCLUDE_CASE)
    assert (scenario.expectation, scenario.oracle) == ("allow", "native-tools")
    assert all(command.startswith("git check-ignore -v ") for command in scenario.commands)
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=OWN_EXCLUDE_CASE)
    assert _excludes_file(fixture.home, fixture.workspace) == ".git/info/exclude"


def test_other_cases_keep_the_default_ignore_list(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id="omp-native-git-compound-reads")
    assert _excludes_file(fixture.home, fixture.workspace) == ""
