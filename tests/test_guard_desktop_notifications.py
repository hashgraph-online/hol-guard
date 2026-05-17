"""Desktop notification tests for local Guard approvals."""

from __future__ import annotations

import subprocess
from typing import Any

from codex_plugin_scanner.guard.desktop_notifications import (
    _NOTIFICATION_ATTEMPTS_IN_FLIGHT,
    _NOTIFIED_APPROVAL_IDS,
    _NOTIFIED_APPROVAL_IDS_LOCK,
    DesktopApprovalNotification,
    notify_pending_approval_once,
    send_desktop_approval_notification,
)


class _Completed:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode


def _notification() -> DesktopApprovalNotification:
    return DesktopApprovalNotification(
        request_id="req-native",
        title="HOL Guard needs approval",
        message="Codex wants approval: Bash shell command",
        approval_url="http://127.0.0.1:5474/approvals/req-native",
    )


def test_macos_notification_uses_terminal_notifier_when_available() -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        calls.append(command)
        return _Completed()  # type: ignore[return-value]

    sent = send_desktop_approval_notification(
        _notification(),
        system_name="Darwin",
        run=run,
        which=lambda name: "/usr/local/bin/terminal-notifier" if name == "terminal-notifier" else None,
    )

    assert sent is True
    assert calls[0][:2] == ["/usr/local/bin/terminal-notifier", "-title"]
    assert "-open" in calls[0]
    assert "-sound" in calls[0]
    assert "default" in calls[0]
    assert "-ignoreDnD" in calls[0]
    assert any(str(item).startswith("hol-guard-req-native-") for item in calls[0])
    assert "http://127.0.0.1:5474/approvals/req-native" in calls[0]


def test_macos_notification_falls_back_to_osascript() -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        calls.append(command)
        return _Completed()  # type: ignore[return-value]

    sent = send_desktop_approval_notification(
        _notification(),
        system_name="Darwin",
        run=run,
        which=lambda _name: None,
    )

    assert sent is True
    assert calls[0][0] == "osascript"
    assert "display notification" in calls[0][2]
    assert "HOL Guard needs approval" in calls[0][2]
    assert 'sound name "default"' in calls[0][2]
    assert "http://127.0.0.1:5474/approvals/req-native" in calls[0][2]


def test_windows_notification_uses_powershell_toast() -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        calls.append(command)
        return _Completed()  # type: ignore[return-value]

    sent = send_desktop_approval_notification(
        _notification(),
        system_name="Windows",
        run=run,
    )

    assert sent is True
    assert calls[0][:4] == ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass"]
    assert "ToastNotificationManager" in calls[0][-1]
    assert "$OpenAction.SetAttribute('activationType', 'protocol')" in calls[0][-1]
    assert "$OpenAction.SetAttribute('arguments', $Url)" in calls[0][-1]
    assert "CreateToastNotifier()" in calls[0][-1]
    assert "http://127.0.0.1:5474/approvals/req-native" in calls[0][-1]


def test_unsupported_platform_is_noop() -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        calls.append(command)
        return _Completed()  # type: ignore[return-value]

    sent = send_desktop_approval_notification(
        _notification(),
        system_name="Linux",
        run=run,
    )

    assert sent is False
    assert calls == []


def test_notification_command_nonzero_exit_is_failure() -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        calls.append(command)
        return _Completed(returncode=1)  # type: ignore[return-value]

    sent = send_desktop_approval_notification(
        _notification(),
        system_name="Darwin",
        run=run,
        which=lambda _name: None,
    )

    assert sent is False
    assert calls[0][0] == "osascript"


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
