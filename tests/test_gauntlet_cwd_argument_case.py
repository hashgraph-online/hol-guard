"""The home-spelled Bun case with ``cwd`` only counts when the model really sent ``cwd``."""

from __future__ import annotations

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.command_outputs import cwd_argument_error
from ci.gauntlet.workspace_runner_fixtures import HOME_BUN_ENTRY_CASE, HOME_BUN_ENTRY_CWD_CASE

CATALOG = {scenario.id: scenario for scenario in load_catalog()}


def _call(**args: object) -> dict[str, object]:
    command = CATALOG[HOME_BUN_ENTRY_CWD_CASE].commands[0]
    return {"id": "c1", "name": "bash", "args": {"command": command, **args}, "is_error": False}


@pytest.mark.parametrize("cwd", ["{{workspace}}", "{{workspace}}/", "{{workspace}}\\"])
def test_a_call_rooted_at_the_project_exercises_the_case(cwd: str) -> None:
    assert cwd_argument_error(CATALOG[HOME_BUN_ENTRY_CWD_CASE], [_call(cwd=cwd)]) is None


@pytest.mark.parametrize("args", [{}, {"cwd": None}, {"cwd": "{{workspace}}/dashboard"}, {"cwd": "{{home}}"}])
def test_a_call_without_the_project_cwd_is_not_exercised(args: dict[str, object]) -> None:
    error = cwd_argument_error(CATALOG[HOME_BUN_ENTRY_CWD_CASE], [_call(**args)])
    assert error == "the bash call did not set its cwd argument to the project"


def test_the_case_without_cwd_is_unaffected() -> None:
    assert cwd_argument_error(CATALOG[HOME_BUN_ENTRY_CASE], [_call()]) is None
