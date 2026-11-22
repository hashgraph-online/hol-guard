"""Fail-closed hook responses when native review cannot complete."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.hook_review.hook_availability_policy import (
    availability_harness_response,
)


def test_availability_denies_inspection_and_high_impact_without_review(tmp_path: Path) -> None:
    allow = availability_harness_response(
        harness="cursor",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
    )
    assert allow["reason_code"] == "native_pre_tool_unavailable"
    assert allow["policy_action"] == "block"
    assert allow["hookSpecificOutput"]["permissionDecision"] == "deny"
    deny = availability_harness_response(
        harness="cursor",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
    )
    assert deny["reason_code"] == "native_pre_tool_unavailable"
    assert deny["policy_action"] == "block"
    output = deny["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"


def test_runtime_availability_reuses_the_rust_answer(monkeypatch) -> None:
    from codex_plugin_scanner.guard.hook_review import hook_availability_policy as policy

    calls: list[object] = []

    def answer(*_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append(None)
        return {"event_name": "CacheProbe", "pauses": False, "permission_request": False}

    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", answer)
    policy._RUNTIME_AVAILABILITY_CACHE.clear()
    assert policy._runtime_availability({"event": "CacheProbe"}) == {
        "event_name": "CacheProbe",
        "pauses": False,
        "permission_request": False,
    }
    assert policy._runtime_availability({"event": "CacheProbe"}) == {
        "event_name": "CacheProbe",
        "pauses": False,
        "permission_request": False,
    }
    assert len(calls) == 1
    policy._RUNTIME_AVAILABILITY_CACHE.clear()
