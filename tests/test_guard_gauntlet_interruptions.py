"""Interruption semantics of the Gauntlet judges and their metrics."""

from __future__ import annotations

import json

import pytest

from ci.gauntlet.approval_rows import offers_always
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.interruptions import (
    case_interruptions,
    known_gap_report,
    load_known_gaps,
    observation_interruptions,
    rendered_fields,
    summarize_interruptions,
)


def _row(response: dict, **extra: object) -> dict:
    return {"response": response, "payload": {"tool_name": "bash", "hook_event_name": "PreToolUse"}, **extra}


def test_warn_with_text_renders_and_interrupts() -> None:
    response = {"policy_action": "warn", "reason": "careful", "reason_code": "native_policy_warning"}
    assert rendered_fields(response) == ["reason"]
    assert [e["kind"] for e in observation_interruptions(_row(response))] == ["rendered"]


def test_warn_without_text_is_quiet() -> None:
    assert observation_interruptions(_row({"policy_action": "warn", "reason_code": "native_policy_observed"})) == []


def test_plain_reason_on_an_allow_is_not_rendered() -> None:
    assert rendered_fields({"policy_action": "allow", "reason": "ok"}) == []


@pytest.mark.parametrize(
    "response", [{"permissionDecision": "ask"}, {"decision": "block"}, {"policy_action": "review"}]
)
def test_any_non_allow_decision_interrupts(response: dict) -> None:
    assert [e["kind"] for e in observation_interruptions(_row(response))] == ["decision"]


def test_tap_row_without_rendered_fields_is_unproven() -> None:
    found = observation_interruptions({"decision": "allow", "tool": "bash", "event": "PreToolUse"})
    assert [e["kind"] for e in found] == ["unproven"]
    assert found[0]["why"] == "observer row carries no rendered-text proof"
    assert observation_interruptions({"decision": "allow", "event": "PreToolUse", "rendered_fields": []}) == []


def test_approval_rows_count_even_when_the_hook_was_quiet() -> None:
    scenario = next(s for s in load_catalog() if s.expectation == "allow" and s.oracle == "native-tools")
    record = case_interruptions(scenario, [_row({})], [{"tool_name": "bash", "reason_code": "r"}], 1)
    assert record["benign"] and record["approval_rows"] == 1 and record["events"][0]["kind"] == "approval"


def test_summary_counts_by_harness_reason_and_tool() -> None:
    interrupted = {
        "benign": True,
        "decisions": 2,
        "quiet_decisions": 1,
        "approval_rows": 0,
        "events": [{"kind": "rendered", "harness": "omp", "tool": "bash", "reason_code": "native_policy_warning"}],
    }
    quiet = {"benign": True, "decisions": 2, "quiet_decisions": 2, "approval_rows": 0, "events": []}
    attack = {
        "benign": False,
        "decisions": 1,
        "quiet_decisions": 0,
        "approval_rows": 1,
        "events": [{"kind": "decision"}],
    }
    summary = summarize_interruptions([{"interruptions": x} for x in (interrupted, quiet, attack)])
    assert summary["benign_interruptions"] == 1
    assert summary["by_harness"] == {"omp": 1}
    assert summary["by_reason_code"] == {"native_policy_warning": 1}
    assert summary["by_tool"] == {"bash": 1}
    assert summary["quiet_allow_rate"] == 0.75
    assert summary["quiet_case_rate"] == 0.5


def test_offers_always_only_from_the_scope_contract() -> None:
    exact = {"always_available": True, "exact_action_persistence_eligible": True, "exact_context_token_present": True}
    assert offers_always(exact)
    assert not offers_always({"always_available": True})
    assert not offers_always({**exact, "exact_action_persistence_eligible": False})
    assert not offers_always({**exact, "exact_context_token_present": False})
    assert not offers_always({"always_available": False, "exact_context_token_present": True})
    assert not offers_always({})


def test_known_gaps_name_catalog_scenarios_and_report_staleness() -> None:
    gaps = load_known_gaps()
    catalog_ids = [s.id for s in load_catalog()]
    assert set(gaps) <= set(catalog_ids)
    # The shipped gap list may be empty; staleness is a property of any listed case.
    listed = gaps or {catalog_ids[0]: "synthetic gap"}
    report = known_gap_report([{"id": next(iter(listed)), "outcome": "pass"}], listed)
    assert report[0]["stale"] is True
    assert json.dumps(report)


def test_harness_lane_counts_missing_codes_as_unknown() -> None:
    events = [{"kind": "approval", "harness": None, "reason_code": None, "tool": None}]
    case = {"interruptions": {"benign": True, "events": events, "decisions": 1}}
    summary = summarize_interruptions([case], harness="pi")
    assert summary["by_harness"] == {"pi": 1}
    assert summary["by_reason_code"] == summary["by_tool"] == {"unknown": 1}


def test_known_gaps_load_from_candidate_path_and_ids(tmp_path) -> None:
    path = tmp_path / "known_gaps.json"
    path.write_text(json.dumps({"known_gaps": {"candidate-only": "why"}}))
    assert load_known_gaps(path, {"candidate-only"}) == {"candidate-only": "why"}
    with pytest.raises(ValueError):
        load_known_gaps(path)


def test_containment_denial_row_still_checked_for_rendered_evidence() -> None:
    from ci.gauntlet.verify import _CONTAINMENT_REASON, _contained_interruptions

    denial = {
        "event": "PreToolUse",
        "decision": "deny",
        "reason_code": _CONTAINMENT_REASON,
        "policy_action": "sandbox-required",
        "http_status": 200,
        "rendered_fields": [],
    }
    assert _contained_interruptions([denial]) == []
    rendered = _contained_interruptions([{**denial, "rendered_fields": ["warning"]}])
    assert [e["kind"] for e in rendered] == ["rendered"]
