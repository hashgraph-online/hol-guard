"""The replay lane's strict judge, without the native runtime."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci.gauntlet.catalog import Scenario, load_catalog, retain_trusted_cases
from ci.gauntlet.interruptions import (
    case_interruptions,
    observation_interruptions,
    rendered_fields,
    summarize_interruptions,
)
from ci.gauntlet.qualify import retryable, summarize_attempt
from tests.gauntlet_replay import ReplayCase, expand, judge


def _case(expect: str, harness: str = "claude-code") -> ReplayCase:
    return ReplayCase(f"x@{harness}", "x", harness, "shell", {"command": "ls"}, "worktree", expect)


_QUIET = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}


def test_quiet_allow_passes() -> None:
    assert judge(_case("quiet"), _QUIET, []) is None


def test_warn_with_rendered_text_fails_ordinary_work() -> None:
    warned = {**_QUIET, "policy_action": "warn", "systemMessage": "Guard warning"}
    assert judge(_case("quiet"), warned, []) is not None


def test_warn_without_text_is_quiet() -> None:
    assert (
        judge(_case("quiet"), {**_QUIET, "policy_action": "warn", "reason_code": "native_policy_warning"}, []) is None
    )


def test_approval_row_fails_ordinary_work() -> None:
    assert judge(_case("quiet"), _QUIET, [{"tool_name": "Bash", "reason_code": "r"}]) is not None


def test_ask_fails_ordinary_work() -> None:
    asked = {"hookSpecificOutput": {"permissionDecision": "ask", "permissionDecisionReason": "review"}}
    assert judge(_case("quiet"), asked, []) is not None


def test_always_needs_a_persistent_allow_in_the_contract() -> None:
    asked = {"hookSpecificOutput": {"permissionDecision": "ask"}}
    once = {"tool_name": "Bash", "always_available": False, "exact_context_token_present": True}
    offered = {
        "tool_name": "Bash",
        "always_available": True,
        "exact_action_persistence_eligible": True,
        "exact_context_token_present": True,
    }
    assert judge(_case("always"), asked, [once]) is not None
    assert judge(_case("always"), asked, [offered]) is None


def test_attack_must_not_be_allowed() -> None:
    denied = {"hookSpecificOutput": {"permissionDecision": "deny"}}
    assert judge(_case("block"), _QUIET, []) is not None
    assert judge(_case("block"), denied, []) is None


def test_expansion_covers_pi_and_every_harness() -> None:
    cases = expand()
    assert {c.harness for c in cases} == {"codex", "zcode", "claude-code", "omp", "pi", "cursor"}
    ids = {c.case_id for c in cases}
    assert "omp-todo-phases@omp" in ids
    assert "omp-todo-phases@pi" not in ids  # Pi ships no todo tool


def test_silent_always_allow_fails_the_review_by_design_case() -> None:
    assert judge(_case("always"), _QUIET, []) is not None
    offered = {
        "tool_name": "Bash",
        "always_available": True,
        "exact_action_persistence_eligible": True,
        "exact_context_token_present": True,
    }
    assert judge(_case("always"), {"hookSpecificOutput": {"permissionDecision": "ask"}}, [offered]) is None


def _benign() -> Scenario:
    return next(s for s in load_catalog() if s.expectation == "allow" and s.oracle == "native-tools")


@pytest.mark.parametrize(
    "row",
    [
        {"observer_error": True, "event": "PreToolUse"},
        {"transport_error": True, "event": "PreToolUse"},
        {"event": "PreToolUse", "decision": "allow", "rendered_fields": [], "http_status": 500},
        {"event": "PreToolUse", "rendered_fields": []},
        {"decision": "allow", "rendered_fields": []},
    ],
)
def test_rows_that_cannot_prove_quiet_are_unproven_on_benign_work(row: dict) -> None:
    record = case_interruptions(_benign(), [row], [], 0, "omp")
    assert record["benign"] and [e["kind"] for e in record["events"]] == ["unproven"]
    assert record["quiet_decisions"] == 0


def test_a_proven_quiet_row_is_not_an_interruption() -> None:
    row = {"event": "PreToolUse", "decision": "allow", "rendered_fields": [], "http_status": 200}
    assert case_interruptions(_benign(), [row], [], 0, "omp")["events"] == []


def test_post_tool_rendered_text_counts() -> None:
    row = {
        "response": {"systemMessage": "note"},
        "payload": {"tool_name": "bash", "hook_event_name": "PostToolUse"},
    }
    assert [e["kind"] for e in case_interruptions(_benign(), [row], [], 0, "codex")["events"]] == ["rendered"]


def test_empty_top_level_text_does_not_shadow_nested_text() -> None:
    response = {"additionalContext": "", "hookSpecificOutput": {"additionalContext": "warn"}}
    assert rendered_fields(response) == ["additionalContext"]
    assert rendered_fields({"systemMessage": "x", "hookSpecificOutput": {"systemMessage": ""}}) == ["systemMessage"]


def test_nested_decision_wins_over_top_level() -> None:
    nested_ask = {"permissionDecision": "allow", "hookSpecificOutput": {"permissionDecision": "ask"}}
    nested_allow = {"permissionDecision": "ask", "hookSpecificOutput": {"permissionDecision": "allow"}}
    assert [e["kind"] for e in observation_interruptions({"response": nested_ask, "payload": _EVENT})] == ["decision"]
    assert observation_interruptions({"response": nested_allow, "payload": _EVENT}) == []


_EVENT = {"tool_name": "bash", "hook_event_name": "PreToolUse"}


def test_unknown_permission_string_is_a_decision() -> None:
    found = observation_interruptions({"response": {"permissionDecision": "defer"}, "payload": _EVENT})
    assert [e["kind"] for e in found] == ["decision"] and found[0]["decision"] == "defer"


def test_exemption_comes_from_trusted_ids_not_the_supplied_oracle() -> None:
    watch = next(s for s in load_catalog() if s.oracle == "watch-command")
    assert not case_interruptions(watch, [], [], 0)["benign"]
    from dataclasses import replace

    forged = replace(_benign(), id="new-case", oracle="watch-command")
    assert case_interruptions(forged, [], [], 0)["benign"]
    with pytest.raises(ValueError, match="exempt oracle"):
        retain_trusted_cases((*load_catalog(), forged), load_catalog())


def _summary(benign_cases: int, interrupted: int) -> dict:
    return {
        "pass": True,
        "merge_qualified": True,
        "cases": [],
        "interruptions": {"benign_cases": benign_cases, "benign_interruptions": interrupted},
    }


def test_qualify_rejects_interruptions_and_zero_benign_cases() -> None:
    assert summarize_attempt(1, Path("e"), 0, 1.0, _summary(3, 0))["pass"] is True
    assert summarize_attempt(1, Path("e"), 0, 1.0, _summary(3, 1))["pass"] is False
    assert summarize_attempt(1, Path("e"), 0, 1.0, _summary(0, 0))["pass"] is False


def test_an_interrupted_case_is_never_retried() -> None:
    quiet = {"outcome": "harness-error", "interrupted": False}
    assert retryable([quiet], 1, 3)
    assert not retryable([{**quiet, "interrupted": True}], 1, 3)


def test_summary_counts_unproven_as_benign_interruptions() -> None:
    record = case_interruptions(_benign(), [{"observer_error": True}], [], 0, "omp")
    assert summarize_interruptions([{"interruptions": record}])["benign_interruptions"] == 1


_RECEIPT = {
    "decision": "deny",
    "policy_action": "sandbox-required",
    "reason_code": "native_pytest_readonly_containment_required",
    "reason": "Run in the read-only sandbox.",
    "required_execution_profile": "pytest-readonly-v2",
}


def test_omp_containment_receipt_is_quiet_where_omp_routes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tests.gauntlet_replay.sys.platform", "darwin")
    assert judge(_case("quiet", "omp"), _RECEIPT, []) is None
    assert judge(_case("always", "omp"), _RECEIPT, []) is None


@pytest.mark.parametrize(
    ("harness", "platform", "receipt"),
    [
        ("omp", "linux", _RECEIPT),
        ("codex", "darwin", _RECEIPT),
        ("omp", "darwin", {**_RECEIPT, "required_execution_profile": "vitest-readonly-v1"}),
        ("omp", "darwin", {**_RECEIPT, "observe_mode": True}),
    ],
)
def test_containment_receipt_interrupts_where_nothing_routes_it(
    monkeypatch: pytest.MonkeyPatch, harness: str, platform: str, receipt: dict[str, object]
) -> None:
    monkeypatch.setattr("tests.gauntlet_replay.sys.platform", platform)
    assert judge(_case("quiet", harness), receipt, []) is not None


def test_a_routed_run_satisfies_an_always_case() -> None:
    # Z Code and Claude Code route in the hook path and Codex in its bridge.
    routed = {**_QUIET, "reason_code": "native_contained_execution_routed"}
    for harness in ("zcode", "claude-code", "codex"):
        assert judge(_case("always", harness), routed, []) is None
    assert judge(_case("always", "codex"), _QUIET, []) is not None
