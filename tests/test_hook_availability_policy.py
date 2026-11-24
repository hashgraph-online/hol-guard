"""Fail-closed hook responses when native review cannot complete."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_hook_render import (
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
    from codex_plugin_scanner.guard import native_hook_availability as policy

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


def test_availability_response_uses_the_native_renderer(monkeypatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    def render(kind: str, harness: str, params: dict[str, object], **kwargs: object):
        calls.append({"kind": kind, "harness": harness, "params": params, **kwargs})
        return "document", {"policy_action": "block", "reason_code": "native_pre_tool_unavailable"}

    monkeypatch.setattr("codex_plugin_scanner.guard.native_hook_render.native_render_cli", render)
    response = availability_harness_response(
        harness="cursor",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="Native review unavailable.",
        guard_home=tmp_path,
        deadline=12.0,
    )
    assert response["policy_action"] == "block"
    assert calls == [
        {
            "kind": "availability_response",
            "harness": "cursor",
            "params": {
                "event_name": "PreToolUse",
                "reason": "Native review unavailable.",
                "reason_code": "native_pre_tool_unavailable",
                "prompt_reason": None,
            },
            "guard_home": tmp_path,
            "deadline": 12.0,
        }
    ]


def test_availability_response_does_not_retry_native_outage_render(monkeypatch, tmp_path: Path) -> None:
    calls: list[object] = []

    def render(*args: object, **kwargs: object):
        calls.append((args, kwargs))
        return None

    monkeypatch.setattr("codex_plugin_scanner.guard.native_hook_render.native_render_cli", render)
    response = availability_harness_response(
        harness="cursor",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="Native review unavailable.",
        guard_home=tmp_path,
        deadline=12.0,
    )
    assert response["policy_action"] == "block"
    assert len(calls) == 1
