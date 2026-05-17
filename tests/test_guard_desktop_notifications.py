"""Desktop notification tests for local Guard approvals."""

from __future__ import annotations

import subprocess
from typing import Any

from codex_plugin_scanner.guard.desktop_notifications import (
    DesktopApprovalNotification,
    send_desktop_approval_notification,
)


class _Completed:
    returncode = 0


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
