"""Claude PermissionRequest events defer to Claude's dialog without a Guard decision."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_support_hook_state
from codex_plugin_scanner.guard.daemon import claude_permission_request
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore

_PAYLOAD = {
    "session_id": "session-permission-1",
    "hook_event_name": "PermissionRequest",
    "tool_name": "Bash",
    "tool_input": {"command": "ls -1"},
    "permission_suggestions": [],
}


def test_permission_request_without_pending_guard_review_is_a_bare_passthrough(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    response = claude_permission_request.claude_permission_request_response(store, dict(_PAYLOAD))

    assert response == {
        "guard_permission_passthrough": True,
        "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
    }


def test_pending_package_review_adds_context_but_no_decision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    seen: list[dict[str, object] | None] = []
    notice = {
        "tool_name": "npm",
        "artifact_type": "package_request",
        "reason": "HOL Guard requires fresh approval for this command.",
    }
    monkeypatch.setattr(commands_support_hook_state, "_peek_claude_permission_notice", lambda _store, _payload: notice)
    monkeypatch.setattr(
        commands_support_hook_state,
        "_mark_claude_pending_permission_prompt_seen",
        lambda *, store, payload, notice: seen.append(notice),
    )

    response = claude_permission_request.claude_permission_request_response(store, dict(_PAYLOAD))

    assert response["guard_permission_passthrough"] is True
    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert "decision" not in hook_output
    assert hook_output == {"hookEventName": "PermissionRequest"}
    assert "requires fresh approval" in str(response["systemMessage"])
    assert seen == [notice]


@pytest.mark.parametrize("native_mode", ["auto", "force", "off"])
def test_worker_routes_claude_permission_requests_before_native_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_mode: str
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", native_mode)
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store, wait_for_native_policy=False)
    try:
        response = worker.review_http_payload(
            payload=dict(_PAYLOAD),
            params={},
            default_harness="claude-code",
            home_dir=tmp_path,
            guard_home=store.guard_home,
            workspace=None,
        )
    finally:
        worker.close()

    assert response["guard_permission_passthrough"] is True
    assert "decision" not in response["hookSpecificOutput"]


def test_pending_tool_review_keeps_the_guard_approval_question_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    notice = {"tool_name": "Bash", "reason": "HOL Guard requires fresh approval for this command."}
    monkeypatch.setattr(commands_support_hook_state, "_peek_claude_permission_notice", lambda _store, _payload: notice)
    monkeypatch.setattr(
        commands_support_hook_state,
        "_mark_claude_pending_permission_prompt_seen",
        lambda *, store, payload, notice: None,
    )

    response = claude_permission_request.claude_permission_request_response(store, dict(_PAYLOAD))

    assert "guard_permission_passthrough" not in response
    decision = response["hookSpecificOutput"]["decision"]
    assert decision["behavior"] == "deny"
    assert decision["interrupt"] is False
    assert "AskUserQuestion" in decision["message"]
