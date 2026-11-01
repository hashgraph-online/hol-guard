"""Desktop notification tests for local Guard approvals.

The notifier commands themselves are covered by the native runtime's
`desktop_notification` tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import desktop_notifications
from codex_plugin_scanner.guard.desktop_notifications import (
    _NOTIFICATION_ATTEMPTS_IN_FLIGHT,
    _NOTIFIED_APPROVAL_IDS,
    _NOTIFIED_APPROVAL_IDS_LOCK,
    DesktopApprovalNotification,
    ensure_desktop_notification_setup,
    notify_pending_approval_once,
    send_desktop_approval_notification,
)


def _notification() -> DesktopApprovalNotification:
    return DesktopApprovalNotification(
        request_id="req-native",
        title="HOL Guard needs approval",
        message="Codex wants approval: Bash shell command",
        approval_url="http://127.0.0.1:5474/approvals/req-native",
    )


class _Runtime:
    def __init__(self, answer: dict[str, object] | None) -> None:
        self.answer = answer
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def __call__(self, feature: str, command: str, request: dict[str, object], **_: Any) -> dict[str, object] | None:
        self.calls.append((feature, command, request))
        return self.answer


def _install(monkeypatch: pytest.MonkeyPatch, system: str, answer: dict[str, object] | None) -> _Runtime:
    runtime = _Runtime(answer)
    monkeypatch.setattr(desktop_notifications, "runtime_answer", runtime)
    monkeypatch.setattr(desktop_notifications.platform, "system", lambda: system)
    monkeypatch.delenv("HOL_GUARD_DESKTOP_NOTIFICATIONS", raising=False)
    return runtime


@pytest.mark.parametrize("system", ["Darwin", "Windows"])
def test_notification_is_sent_by_the_native_runtime(monkeypatch: pytest.MonkeyPatch, system: str) -> None:
    runtime = _install(monkeypatch, system, {"sent": True})

    assert send_desktop_approval_notification(_notification()) is True
    assert runtime.calls == [
        (
            "native-desktop-notification-v1",
            "desktop-notification",
            {
                "op": "send",
                "schema": "desktop-notification.v1",
                "notification": {
                    "request_id": "req-native",
                    "title": "HOL Guard needs approval",
                    "message": "Codex wants approval: Bash shell command",
                    "approval_url": "http://127.0.0.1:5474/approvals/req-native",
                },
            },
        )
    ]


@pytest.mark.parametrize("answer", [None, {"sent": False}, {"sent": "yes"}])
def test_a_notification_the_runtime_did_not_show_is_not_sent(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
) -> None:
    _install(monkeypatch, "Darwin", answer)

    assert send_desktop_approval_notification(_notification()) is False


def test_unsupported_platform_never_asks_the_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime = _install(monkeypatch, "Linux", {"sent": True, "supported": True})

    assert send_desktop_approval_notification(_notification()) is False
    result = ensure_desktop_notification_setup(tmp_path, approval_url="http://127.0.0.1:5474")
    assert result.platform == "Linux"
    assert result.supported is False
    assert runtime.calls == []


def test_setup_reports_the_runtime_answer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime = _install(
        monkeypatch,
        "Darwin",
        {
            "supported": True,
            "preview_sent": True,
            "settings_opened": True,
            "settings_url": "x-apple.systempreferences:example",
            "already_prompted": False,
            "notifier_path": "/opt/homebrew/bin/terminal-notifier",
        },
    )

    result = ensure_desktop_notification_setup(tmp_path, approval_url="http://127.0.0.1:5474", force=True)

    assert runtime.calls[0][2] == {
        "op": "setup",
        "schema": "desktop-notification.v1",
        "guard_home": str(tmp_path),
        "approval_url": "http://127.0.0.1:5474",
        "force": True,
    }
    assert result.supported is True
    assert result.preview_sent is True
    assert result.settings_opened is True
    assert result.settings_url == "x-apple.systempreferences:example"
    assert result.already_prompted is False
    assert result.notifier_path == "/opt/homebrew/bin/terminal-notifier"


def test_setup_without_a_runtime_is_unsupported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install(monkeypatch, "Darwin", None)

    result = ensure_desktop_notification_setup(tmp_path, approval_url="http://127.0.0.1:5474")

    assert result.supported is False
    assert result.settings_url is None


def test_setup_disabled_by_environment_never_asks_the_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime = _install(monkeypatch, "Darwin", {"supported": True})
    monkeypatch.setenv("HOL_GUARD_DESKTOP_NOTIFICATIONS", "off")

    assert ensure_desktop_notification_setup(tmp_path, approval_url="http://127.0.0.1:5474").supported is False
    assert runtime.calls == []


def test_failed_notification_attempt_can_retry(monkeypatch) -> None:
    with _NOTIFIED_APPROVAL_IDS_LOCK:
        _NOTIFIED_APPROVAL_IDS.clear()
        _NOTIFICATION_ATTEMPTS_IN_FLIGHT.clear()
    outcomes = [False, True]

    def fake_send(_notification: DesktopApprovalNotification) -> bool:
        return outcomes.pop(0)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.desktop_notifications.send_desktop_approval_notification",
        fake_send,
    )

    assert notify_pending_approval_once(_notification(), asynchronous=False) is False
    assert notify_pending_approval_once(_notification(), asynchronous=False) is True
    assert notify_pending_approval_once(_notification(), asynchronous=False) is False


def test_thread_start_failure_clears_inflight(monkeypatch) -> None:
    with _NOTIFIED_APPROVAL_IDS_LOCK:
        _NOTIFIED_APPROVAL_IDS.clear()
        _NOTIFICATION_ATTEMPTS_IN_FLIGHT.clear()

    class BrokenThread:
        def __init__(self, **_: Any) -> None:
            pass

        def start(self) -> None:
            raise RuntimeError("thread limit")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.desktop_notifications.threading.Thread",
        BrokenThread,
    )

    assert notify_pending_approval_once(_notification()) is False
    with _NOTIFIED_APPROVAL_IDS_LOCK:
        assert not _NOTIFICATION_ATTEMPTS_IN_FLIGHT
