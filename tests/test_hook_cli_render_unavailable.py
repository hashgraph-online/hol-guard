from __future__ import annotations

import io
import json

import pytest

from codex_plugin_scanner.guard.cli import commands_support_hook_payload as payload

BLOCKING = ("review", "require-reapproval", "sandbox-required", "block")


@pytest.fixture(autouse=True)
def _resident_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(payload, "_render_cli", lambda *_args, **_kwargs: None)


def _emit(**kwargs: object) -> dict[str, object] | None:
    stream = io.StringIO()
    payload._emit_native_hook_response(output_stream=stream, **kwargs)  # type: ignore[arg-type]
    text = stream.getvalue().strip()
    return json.loads(text) if text else None


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse", "Notification", "SessionStart", "Stop"])
@pytest.mark.parametrize("action", BLOCKING)
def test_blocking_verdict_never_renders_as_allow_when_resident_is_down(event: str, action: str) -> None:
    document = _emit(harness="claude-code", policy_action=action, reason="blocked by policy", event_name=event)

    assert document is not None
    assert document.get("decision") != "allow"
    assert document.get("policy_action") != "allow"
    hook_output = document.get("hookSpecificOutput")
    denied = document.get("decision") == "block" or (
        isinstance(hook_output, dict) and hook_output.get("permissionDecision") == "deny"
    )
    assert denied, document


def test_blocking_post_tool_use_gives_a_block_document() -> None:
    document = _emit(harness="codex", policy_action="block", reason="no", event_name="PostToolUse")

    assert document is not None
    assert document["decision"] == "block"
    assert document["reason"] == "no"


def test_nonblocking_notice_fields_survive_a_render_outage() -> None:
    document = _emit(
        harness="claude-code",
        policy_action="allow",
        reason="",
        event_name="Notification",
        additional_context="ctx",
        system_message="msg",
    )

    assert document == {
        "systemMessage": "msg",
        "hookSpecificOutput": {"hookEventName": "Notification", "additionalContext": "ctx"},
    }


def test_nonblocking_without_notice_writes_nothing() -> None:
    assert _emit(harness="claude-code", policy_action="allow", reason="", event_name="PreToolUse") is None
