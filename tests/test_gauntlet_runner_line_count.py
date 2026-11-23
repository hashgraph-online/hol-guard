"""The `| wc -l` Vitest case installs a runner whose line count shows it ran."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.command_outputs import command_outputs_match
from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.workspace_runner_fixtures import WORKSPACE_VITEST_LINE_COUNT_CASE, runner_marker

ENTRY = "node_modules/vitest/vitest.mjs"


def _scenario():
    return next(item for item in load_catalog() if item.id == WORKSPACE_VITEST_LINE_COUNT_CASE)


def _call(text: str) -> dict:
    return {"name": "bash", "args": {}, "result": {"content": [{"type": "text", "text": text}]}}


def test_the_line_count_case_installs_its_own_runner(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=WORKSPACE_VITEST_LINE_COUNT_CASE)
    launcher = fixture.workspace / "node_modules/.bin/vitest"
    assert launcher.is_symlink() and launcher.resolve() == (fixture.workspace / ENTRY).resolve()
    assert _scenario().commands == ("npx vitest run --reporter=dot --silent 2>&1 | wc -l",)


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node")
@pytest.mark.parametrize(("arguments", "forwarded"), [(["run", "--reporter=dot", "--silent"], True), (["run"], False)])
def test_only_a_forwarded_run_prints_the_counted_lines(tmp_path: Path, arguments: list[str], forwarded: bool) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=WORKSPACE_VITEST_LINE_COUNT_CASE)
    run = subprocess.run(
        ["node", ENTRY, *arguments], cwd=fixture.workspace, capture_output=True, text=True, timeout=30, check=True
    )
    count = f"{len(run.stdout.splitlines()):>8}\n"
    assert command_outputs_match(_scenario(), [_call(count)]) is forwarded


def test_the_count_must_lead_the_output() -> None:
    scenario = _scenario()
    marker = runner_marker(WORKSPACE_VITEST_LINE_COUNT_CASE)
    assert command_outputs_match(scenario, [_call(f"       {marker}\n")])
    assert not command_outputs_match(scenario, [_call(f"      1{marker}\n")])
    assert not command_outputs_match(scenario, [_call("       0\nvitest is not installed\n")])
    assert not command_outputs_match(scenario, [])
