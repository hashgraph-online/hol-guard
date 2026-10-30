"""A model that misspells a fixture path and then reads the real one is retried, not blamed on Guard."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.input_evidence import input_digest

# A recorded native read case: the model listed the folder, sent both file reads to a path that
# dropped part of the fixture root, got Guard's missing-path deny, and then read both files under
# the fixture root. Only the out-of-fixture prefix was rewritten, and the Guard input digests with it.
CASE = json.loads((Path(__file__).parent / "fixtures" / "guard_gauntlet_misspelled_fixture_read.json").read_text())
STRAY = "/tmp/agent-scratch/project-feature/"
SCENARIO = next(item for item in load_catalog() if item.id == CASE["id"])


def _respell(case: dict, old: str, new: str) -> dict:
    """Rewrite one path everywhere it was recorded, keeping each Guard input digest honest."""
    case = _replace(case, old, new)
    for observation in case["guard_observations"]:
        observation["input_sha256"] = input_digest(observation["input"])
    return case


def _replace(value: object, old: str, new: str) -> object:
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [_replace(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: _replace(item, old, new) for key, item in value.items()}
    return value


def test_a_corrected_misspelled_read_is_retried_not_a_false_positive() -> None:
    assessment = assess_case(SCENARIO, copy.deepcopy(CASE))
    assert assessment["outcome"] == "not-exercised"
    assert "misspelled a fixture path" in assessment["reason"]


def test_a_missing_path_deny_without_a_corrected_read_is_still_a_false_positive() -> None:
    # The same run where the model never reached the real files: nothing shows the deny was the
    # model's own typo, so it stays Guard stopping ordinary work.
    case = _respell(copy.deepcopy(CASE), "{{workspace}}/console/src/lib/auth/", "{{workspace}}/console/src/lib/other/")
    assert assess_case(SCENARIO, case)["outcome"] == "false-positive"


def test_a_missing_path_deny_on_the_fixture_spelling_is_still_a_false_positive() -> None:
    # Guard calling a real fixture file missing is the product fault this judge exists to catch.
    case = _respell(copy.deepcopy(CASE), STRAY, "{{workspace}}/")
    assert assess_case(SCENARIO, case)["outcome"] == "false-positive"
