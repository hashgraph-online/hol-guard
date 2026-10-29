"""Claude Code's lifecycle hooks are answered by one resident call.

The resident op reads the session's pending Guard review, marks it seen and
records the prompt in one transaction; its responses are pinned by the
guard-runtime lifecycle tests. These tests pin what the worker sends and how
it answers when the resident cannot.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_authority_state
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore

_PAYLOAD = {
    "session_id": "session-permission-1",
    "hook_event_name": "PermissionRequest",
    "tool_name": "Bash",
    "tool_input": {"command": "ls -1"},
    "permission_suggestions": [],
}


def _review(worker: HookWorker, tmp_path: Path, payload: dict[str, object]) -> dict[str, object]:
    return worker.review_http_payload(
        payload=payload,
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=worker.store.guard_home,
        workspace=None,
    )


def _resident(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object] | None) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def answer(_store: object, op: str, **fields: object) -> dict[str, object] | None:
        calls.append((op, fields))
        return reply

    monkeypatch.setattr(native_hook_authority_state, "hook_authority_state", answer)
    return calls


@pytest.mark.parametrize("native_mode", ["auto", "force", "off"])
def test_worker_routes_claude_permission_requests_before_native_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_mode: str
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", native_mode)
    calls = _resident(monkeypatch, None)
    store = GuardStore(tmp_path / "guard-home")
    worker = HookWorker(store=store, wait_for_native_policy=False)
    try:
        response = _review(worker, tmp_path, dict(_PAYLOAD))
    finally:
        worker.close()

    assert [op for op, _fields in calls] == ["claude_permission_request"]
    assert response == {
        "guard_permission_passthrough": True,
        "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
    }


@pytest.mark.parametrize(
    ("payload", "op"),
    [
        (dict(_PAYLOAD), "claude_permission_request"),
        (
            {
                "session_id": "session-permission-1",
                "hook_event_name": "Notification",
                "notification_type": "permission_prompt",
                "message": "Claude needs your permission to use Bash",
                "title": "Permission needed",
                "transcript_path": "/tmp/transcript.jsonl",
            },
            "claude_permission_prompt",
        ),
    ],
)
def test_the_resident_answer_is_the_hook_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: dict[str, object], op: str
) -> None:
    answer = {"hookSpecificOutput": {"hookEventName": str(payload["hook_event_name"])}, "systemMessage": "resident"}
    calls = _resident(monkeypatch, {"harness_response": answer})
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"), wait_for_native_policy=False)
    try:
        response = _review(worker, tmp_path, payload)
    finally:
        worker.close()

    assert response == answer
    [(called, fields)] = calls
    assert called == op
    assert fields["session_id"] == "session-permission-1"
    assert fields["required_feature"] == native_hook_authority_state.HOOK_AUTHORITY_STATE_CLAUDE_LIFECYCLE_FEATURE
    # Only the fields the copy reads travel; the tool's input never does.
    sent = fields["payload"]
    assert isinstance(sent, dict)
    assert set(sent) <= {"session_id", "notification_type", "tool_name", "message", "title"}
    assert "tool_input" not in sent
    assert "transcript_path" not in sent


def test_a_permission_prompt_without_the_resident_still_tells_claude_to_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _resident(monkeypatch, None)
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"), wait_for_native_policy=False)
    try:
        response = _review(
            worker,
            tmp_path,
            {"session_id": "s", "hook_event_name": "Notification", "notification_type": "permission_prompt"},
        )
    finally:
        worker.close()

    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["hookEventName"] == "Notification"
    assert hook_output["additionalContext"] == response["systemMessage"]
    assert "HOL Guard" in str(response["systemMessage"])


def test_stop_drops_the_sessions_prompts_and_leaves_the_answer_to_the_edge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _resident(monkeypatch, {"discarded": 1})
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"), wait_for_native_policy=False)
    try:
        answered = worker._claude_lifecycle_response("Stop", {"session_id": "s", "hook_event_name": "Stop"})
    finally:
        worker.close()

    assert answered is None
    assert [(op, fields["session_id"]) for op, fields in calls] == [("claude_turn_stop", "s")]
