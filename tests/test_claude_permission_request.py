"""Claude lifecycle events use the native hook edge."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore


def _review(worker: HookWorker, tmp_path: Path, payload: dict[str, object]) -> dict[str, object]:
    return worker.review_http_payload(
        payload=payload,
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=worker.store.guard_home,
        workspace=None,
    )


def test_claude_permission_request_is_returned_by_native_edge(tmp_path: Path, monkeypatch) -> None:
    answer = {"hookSpecificOutput": {"hookEventName": "PermissionRequest"}}
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"), wait_for_native_policy=False)
    monkeypatch.setattr(worker, "_review_native_edge", lambda **_kwargs: answer)
    try:
        response = _review(worker, tmp_path, {"hook_event_name": "PermissionRequest", "session_id": "s"})
    finally:
        worker.close()

    assert response == answer


def test_claude_stop_is_returned_by_native_edge(tmp_path: Path, monkeypatch) -> None:
    answer = {"continue": True, "hookSpecificOutput": {"hookEventName": "Stop"}}
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"), wait_for_native_policy=False)
    monkeypatch.setattr(worker, "_review_native_edge", lambda **_kwargs: answer)
    try:
        response = _review(worker, tmp_path, {"hook_event_name": "Stop", "session_id": "s"})
    finally:
        worker.close()

    assert response == answer


def test_claude_post_tool_question_still_settles_before_native_edge(tmp_path: Path, monkeypatch) -> None:
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"), wait_for_native_policy=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_support_claude_approval._settle_claude_guard_question",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(worker, "_review_native_edge", lambda **_kwargs: (_ for _ in ()).throw(AssertionError()))
    try:
        response = _review(
            worker,
            tmp_path,
            {"hook_event_name": "PostToolUse", "tool_name": "AskUserQuestion", "session_id": "s"},
        )
    finally:
        worker.close()

    assert response == {}
