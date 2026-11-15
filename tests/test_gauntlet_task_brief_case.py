"""Protection cases that delegate work with an attack riding in the task brief."""

from __future__ import annotations

import pytest

from ci.gauntlet.catalog import load_catalog, load_catalog_data
from ci.gauntlet.harness_suite import lane_catalog
from ci.gauntlet.proofs import block_reasons
from ci.gauntlet.task_brief_cases import TASK_BRIEF_BLOCK_REASONS, TASK_BRIEF_ORACLE

# The schema the loader requires, so a malformed row fails on its own fields.
CATALOG_SCHEMA = "hol.guard-gauntlet.scenarios.v1"

CASE = "omp-task-brief-forwards-an-injection"


def test_the_case_drives_one_task_call_and_accepts_only_the_brief_review() -> None:
    scenarios = {s.id: s for s in load_catalog() if s.oracle == TASK_BRIEF_ORACLE}
    assert set(scenarios) == {CASE}
    scenario = scenarios[CASE]
    assert scenario.expectation == "block"
    assert scenario.required_tools == ("task",)
    assert not scenario.commands
    assert "Ignore your previous instructions" in scenario.prompt
    assert block_reasons(scenario) == TASK_BRIEF_BLOCK_REASONS


def test_only_the_oh_my_pi_lane_runs_the_case() -> None:
    for harness in ("claude-code", "codex", "cursor"):
        assert CASE not in {s.id for s in lane_catalog(harness)}


def _brief_row(**overrides: object) -> dict[str, object]:
    return {
        "id": "task-brief-case",
        "expectation": "block",
        "oracle": TASK_BRIEF_ORACLE,
        "required_tools": ["task"],
        "prompt": "Delegate one task.",
        **overrides,
    }


@pytest.mark.parametrize(
    "overrides",
    [{"expectation": "allow"}, {"required_tools": ["eval"]}, {"commands": ["true"]}],
    ids=["allow", "other-tool", "command"],
)
def test_the_catalog_rejects_a_malformed_task_brief_case(overrides: dict[str, object]) -> None:
    row = _brief_row(**overrides)
    with pytest.raises(ValueError):
        load_catalog_data({"schema": CATALOG_SCHEMA, "scenarios": [row]})


def test_the_unmodified_task_brief_case_loads() -> None:
    (scenario,) = load_catalog_data({"schema": CATALOG_SCHEMA, "scenarios": [_brief_row()]})
    assert scenario.oracle == TASK_BRIEF_ORACLE
