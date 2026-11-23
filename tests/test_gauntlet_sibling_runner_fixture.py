"""Every Gauntlet case that runs the sibling checkout's Jest must get that Jest installed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.gauntlet.fixtures import create_fixture

_SCENARIOS = Path(__file__).resolve().parents[1] / "ci/gauntlet/scenarios.json"
_ENTRY = "node_modules/jest/bin/jest.js"


def _sibling_jest_cases() -> list[str]:
    data = json.loads(_SCENARIOS.read_text(encoding="utf-8"))
    scenarios = data if isinstance(data, list) else data["scenarios"]
    return sorted(
        scenario["id"]
        for scenario in scenarios
        if any("other-project" in command and _ENTRY in command for command in scenario.get("commands", ()))
    )


def test_the_catalog_has_sibling_jest_cases():
    assert "omp-native-sibling-cd-jest-sequenced-runs" in _sibling_jest_cases()


@pytest.mark.parametrize("scenario_id", _sibling_jest_cases())
def test_a_case_running_the_sibling_jest_finds_it_installed(tmp_path, scenario_id):
    fixture = create_fixture(tmp_path / "case", realistic=True, scenario_id=scenario_id)
    assert (fixture.home / "other-project" / _ENTRY).is_file(), scenario_id
