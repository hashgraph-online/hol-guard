"""The Vitest case that closes its run with PASS or FAIL installs a runner to run."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.command_outputs import command_outputs_match
from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.workspace_runner_fixtures import WORKSPACE_VITEST_OUTCOME_REPORT_CASE, runner_marker

ENTRY = "node_modules/vitest/vitest.mjs"


def _scenario():
    return next(item for item in load_catalog() if item.id == WORKSPACE_VITEST_OUTCOME_REPORT_CASE)


def _call(text: str) -> dict:
    return {"name": "bash", "args": {}, "result": {"content": [{"type": "text", "text": text}]}}


def test_the_outcome_report_case_installs_its_own_runner(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=WORKSPACE_VITEST_OUTCOME_REPORT_CASE)
    launcher = fixture.workspace / "node_modules/.bin/vitest"
    assert launcher.is_symlink() and launcher.resolve() == (fixture.workspace / ENTRY).resolve()
    assert _scenario().commands == ("./node_modules/.bin/vitest run 2>&1 | tail -5 && echo PASS || echo FAIL",)


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node")
def test_the_installed_runner_prints_the_line_the_case_checks(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=WORKSPACE_VITEST_OUTCOME_REPORT_CASE)
    run = subprocess.run(
        ["node", ENTRY, "run"], cwd=fixture.workspace, capture_output=True, text=True, timeout=30, check=True
    )
    assert command_outputs_match(_scenario(), [_call(run.stdout + "PASS\n")])


def test_a_missing_runner_does_not_match() -> None:
    scenario = _scenario()
    assert runner_marker(WORKSPACE_VITEST_OUTCOME_REPORT_CASE) not in "PASS\n"
    assert not command_outputs_match(
        scenario,
        [_call("vitest_restricted_dependency_unavailable: Vitest is not installed inside this workspace.\nFAIL\n")],
    )
    assert not command_outputs_match(scenario, [])
