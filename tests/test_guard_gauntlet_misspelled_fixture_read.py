"""A model that misspells a fixture path and then reads the real one is retried, not blamed on Guard."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from ci.gauntlet.case_retry import retryable
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.input_evidence import input_digest
from ci.gauntlet.native_tools import misspelled_fixture_reads

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
    # The excused deny must not count as an interruption, or qualification would refuse the retry.
    assert retryable(assessment)


def test_a_corrected_misspelled_read_that_also_raised_an_approval_is_a_false_positive() -> None:
    case = copy.deepcopy(CASE)
    case["approval_delta"] = 1
    assert assess_case(SCENARIO, case)["outcome"] == "false-positive"


def test_a_corrected_misspelled_read_on_a_windows_drive_is_retried() -> None:
    # The Windows lane records the same mistake with a drive letter and backslashes.
    case = _respell(copy.deepcopy(CASE), STRAY, "C:\\agent-scratch\\project-feature\\")
    assessment = assess_case(SCENARIO, case)
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


STRAY_README = "/tmp/agent-scratch/project-feature/console/src/lib/auth/README.md"
FIXTURE_README = "{{workspace}}/console/src/lib/auth/README.md"


def _read(call_id: str, path: str, *, failed: bool) -> dict:
    return {"id": call_id, "name": "read", "args": {"path": path}, "is_error": failed}


def _deny(call_id: str, reason_code: str = "native_missing_path", event: str = "PreToolUse") -> dict:
    return {"tool_call_id": call_id, "event": event, "decision": "deny", "reason_code": reason_code}


def _turns(*turns: list[str]) -> list[dict]:
    return [{"type": "model_turn", "calls": [{"id": call_id} for call_id in ids]} for ids in turns]


def test_only_a_read_from_a_later_model_turn_corrects_a_missing_path_deny() -> None:
    calls = [_read("stray", STRAY_README, failed=True), _read("fixed", FIXTURE_README, failed=False)]
    assert misspelled_fixture_reads(SCENARIO, calls, [_deny("stray")], _turns(["stray"], ["fixed"])) == {"stray"}
    # The model picked both paths before Guard answered, so the good read did not respond to the deny.
    assert misspelled_fixture_reads(SCENARIO, calls, [_deny("stray")], _turns(["stray", "fixed"])) == frozenset()
    assert misspelled_fixture_reads(SCENARIO, calls, [_deny("stray")], _turns(["fixed"], ["stray"])) == frozenset()


def test_a_correction_must_be_the_file_the_prompt_names_under_its_own_root() -> None:
    # {{home}} holds a file at the same relative path, but the prompt asked for the workspace copy.
    calls = [
        _read("stray", STRAY_README, failed=True),
        _read("other", "{{home}}/console/src/lib/auth/README.md", failed=False),
    ]
    assert misspelled_fixture_reads(SCENARIO, calls, [_deny("stray")], _turns(["stray"], ["other"])) == frozenset()


def test_any_other_deny_in_the_run_keeps_the_whole_run_a_false_positive() -> None:
    calls = [
        _read("stray", STRAY_README, failed=True),
        _read("fixed", FIXTURE_README, failed=False),
        _read("session", "{{workspace}}/console/src/lib/auth/session.ts", failed=True),
    ]
    observations = [_deny("stray"), _deny("session", "native_read_review")]
    turns = _turns(["stray"], ["fixed", "session"])
    assert misspelled_fixture_reads(SCENARIO, calls, observations, turns) == frozenset()


def test_a_post_tool_deny_on_a_successful_call_keeps_the_run_a_false_positive() -> None:
    calls = [_read("stray", STRAY_README, failed=True), _read("fixed", FIXTURE_README, failed=False)]
    observations = [_deny("stray"), _deny("fixed", "native_output_review", event="PostToolUse")]
    assert misspelled_fixture_reads(SCENARIO, calls, observations, _turns(["stray"], ["fixed"])) == frozenset()
