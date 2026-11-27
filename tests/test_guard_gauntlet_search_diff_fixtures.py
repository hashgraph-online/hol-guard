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
from ci.gauntlet.command_outputs import command_outputs_match
from ci.gauntlet.harness_judge import _linked_rg_harness_proven
from ci.gauntlet.search_diff_fixtures import DIFF_EXCLUSION_CASE, LINKED_RG_CASE, SEARCH_WORDS_CASE, linked_rg_omp_proven

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



def test_linked_rg_uses_a_real_alias_and_populated_roots(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "linked", realistic=True, scenario_id=LINKED_RG_CASE)
    assert fixture.workspace.is_symlink()
    assert fixture.workspace.resolve(strict=True) == (fixture.home / "project-feature").resolve(strict=True)
    assert (fixture.workspace / "src/rail.ts").read_text() == "export const railStage = 1;\n"
    assert (fixture.workspace / "tests/rail.test.tsx").read_text() == "export const railStage = 2;\n"
    ordinary = create_fixture(tmp_path / "ordinary", realistic=True, scenario_id=SEARCH_WORDS_CASE)
    assert not ordinary.workspace.is_symlink()
    assert not (ordinary.workspace / "src/rail.ts").exists()
    assert not (ordinary.workspace / "tests/rail.test.tsx").exists()


@pytest.mark.skipif(os.name == "nt" or shutil.which("rg") is None, reason="needs a POSIX shell and ripgrep")
def test_linked_rg_exact_commands_print_the_fixture_markers(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "linked", realistic=True, scenario_id=LINKED_RG_CASE)
    scenario = SCENARIOS[LINKED_RG_CASE]
    calls = []
    for command in scenario.commands:
        completed = _run(command, fixture.workspace, fixture.home)
        assert completed.returncode == 0, completed.stderr
        assert not completed.stderr
        calls.append({"name": "bash", "result": {"content": [{"type": "text", "text": completed.stdout}]}})
    assert command_outputs_match(scenario, calls)
    assert not command_outputs_match(scenario, calls[1:])


def test_linked_rg_requires_both_actual_hook_cwd_spellings() -> None:
    commands = SCENARIOS[LINKED_RG_CASE].commands
    observations = [
        {"event": "PreToolUse", "linked_fixture_cwd": True, "input": {"command": command}} for command in commands
    ]
    assert linked_rg_omp_proven(commands, observations)
    assert not linked_rg_omp_proven(commands, observations[:1])
    assert not linked_rg_omp_proven(commands, [dict(row, linked_fixture_cwd=False) for row in observations])
    assert not linked_rg_omp_proven(commands, [dict(row, event="PostToolUse") for row in observations])
    rows = [
        {"payload": {"hook_event_name": "PreToolUse", "tool_input": {"command": command}, "cwd": "{{workspace}}"}}
        for command in commands
    ]
    assert _linked_rg_harness_proven(commands, rows)
    assert not _linked_rg_harness_proven(commands, rows[:1])
    assert not _linked_rg_harness_proven(
        commands, [dict(row, payload=dict(row["payload"], cwd="{{home}}/project-feature")) for row in rows]
    )
    assert not _linked_rg_harness_proven(
        commands, [dict(row, payload=dict(row["payload"], cwd=None)) for row in rows]
    )
