"""A native store that cannot answer never aborts the desktop notification path."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import approvals
from codex_plugin_scanner.guard.native_approval_scope import ApprovalScopeUnavailableError


class _UnavailableStore:
    guard_home = Path("/nonexistent-guard-home")

    def approval_desktop_notified_at(self, request_id: str) -> str | None:
        raise ApprovalScopeUnavailableError

    def mark_approval_desktop_notified(self, request_id: str, notified_at: str) -> None:
        raise ApprovalScopeUnavailableError


def _request() -> SimpleNamespace:
    return SimpleNamespace(
        request_id="req-1", workspace=None, approval_url="http://127.0.0.1:4781/approvals/req-1", queue_group_id=None
    )


def test_an_unreadable_marker_skips_the_notification(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[object] = []
    monkeypatch.setattr(approvals, "load_guard_config", lambda *_args: None)
    monkeypatch.setattr(approvals, "notify_pending_approval_once", lambda *args, **kwargs: sent.append(args))

    approvals._notify_pending_approval(store=_UnavailableStore(), request=_request())  # type: ignore[arg-type]

    assert sent == []


def test_an_unwritable_marker_keeps_the_sent_notification(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _UnavailableStore()
    monkeypatch.setattr(store, "approval_desktop_notified_at", lambda _request_id: None)
    monkeypatch.setattr(approvals, "load_guard_config", lambda *_args: None)
    monkeypatch.setattr(approvals, "load_guard_daemon_auth_token", lambda _home: None)
    monkeypatch.setattr(approvals, "_approval_notification_message", lambda _request: "message")
    delivered: list[str] = []

    def _deliver(notification: object, *, on_success: object) -> bool:
        on_success()  # type: ignore[operator]
        delivered.append(notification.request_id)  # type: ignore[attr-defined]
        return True

    monkeypatch.setattr(approvals, "notify_pending_approval_once", _deliver)

    approvals._notify_pending_approval(store=store, request=_request())  # type: ignore[arg-type]

    assert delivered == ["req-1"]
