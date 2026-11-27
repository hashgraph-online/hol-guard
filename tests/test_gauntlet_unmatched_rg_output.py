"""Unmatched glob searches must still read their existing public source."""

from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.command_outputs import command_outputs_match
from ci.gauntlet.fixtures import create_fixture

CASE = "omp-native-shell-rg-unmatched-root-glob-after-cd"
SCENARIO = next(s for s in load_catalog() if s.id == CASE)
FIRST = "src/settings.ts\n"
SECOND = "./settings.ts:1:export const settings = {\n./settings.ts\n"
DIAGNOSTIC = "rg: handlers_*.ts: No such file or directory (os error 2)\n"


def calls(first=FIRST, second=SECOND):
    return [
        {"name": "bash", "args": {"command": command},
         "result": {"content": [{"type": "text", "text": output}]}}
        for command, output in zip(SCENARIO.commands, (first, second), strict=True)
    ]


def test_realistic_fixture_has_the_existing_source_but_no_matching_glob(tmp_path: Path):
    fixture = create_fixture(tmp_path / "fixture", realistic=True, scenario_id=CASE)
    assert not list(fixture.workspace.glob("handlers_*.ts"))
    assert not list((fixture.workspace / "src").glob("handlers_*.ts"))
    assert (fixture.workspace / "src/settings.ts").read_text().splitlines()[0] == "export const settings = {"


@pytest.mark.parametrize("first,second", [
    (FIRST, SECOND),
    (DIAGNOSTIC + FIRST, SECOND + DIAGNOSTIC),
    ("src\\settings.ts\n", ".\\settings.ts:1:export const settings = {\n.\\settings.ts\n"),
])
def test_existing_source_is_required_even_with_a_missing_glob(first, second):
    assert command_outputs_match(SCENARIO, calls(first, second))


@pytest.mark.parametrize("first,second", [
    ("", SECOND), (FIRST, ""), (DIAGNOSTIC, DIAGNOSTIC),
    ("src/other.ts\n", SECOND),
    (FIRST, "./settings.ts\n"),
    (FIRST, "./settings.ts:1:export const settings = {\n"),
    (FIRST, "./settings.ts:1:unrelated\n./settings.ts\n"),
])
def test_empty_or_partial_results_do_not_pass(first, second):
    assert not command_outputs_match(SCENARIO, calls(first, second))


def test_commands_must_run_once_in_order():
    observed = calls()
    for wrong in ([], observed[:1], observed[::-1], observed + observed[:1]):
        assert not command_outputs_match(SCENARIO, wrong)
