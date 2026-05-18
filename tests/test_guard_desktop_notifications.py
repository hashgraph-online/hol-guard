"""Desktop notification tests for local Guard approvals."""

from __future__ import annotations

import subprocess
from typing import Any

from codex_plugin_scanner.guard.desktop_notifications import (
    _NOTIFICATION_ATTEMPTS_IN_FLIGHT,
    _NOTIFICATION_SETUP_LOCK,
    _NOTIFICATION_SETUP_PATHS_IN_FLIGHT,
    _NOTIFIED_APPROVAL_IDS,
    _NOTIFIED_APPROVAL_IDS_LOCK,
    DesktopApprovalNotification,
    ensure_desktop_notification_setup,
    ensure_desktop_notification_setup_async,
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


def test_notification_command_launch_failure_is_best_effort() -> None:
    def run(_command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        raise FileNotFoundError("osascript")

    sent = send_desktop_approval_notification(
        _notification(),
        system_name="Darwin",
        run=run,
        which=lambda _name: None,
    )

    assert sent is False


def test_macos_setup_command_timeout_does_not_raise(tmp_path) -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        calls.append(command)
        raise subprocess.TimeoutExpired(command, timeout=3)

    result = ensure_desktop_notification_setup(
        tmp_path / "guard-home",
        approval_url="http://127.0.0.1:5474/approvals/preview",
        system_name="Darwin",
        run=run,
        which=lambda _name: "/usr/local/bin/terminal-notifier",
    )

    assert result.preview_sent is False
    assert result.settings_opened is False
    assert len(calls) == 2
    assert not (tmp_path / "guard-home" / "desktop-notifications.json").exists()


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


def test_macos_setup_async_deduplicates_inflight_work(tmp_path, monkeypatch) -> None:
    started: list[dict[str, Any]] = []

    class CapturingThread:
        def __init__(self, **kwargs: Any) -> None:
            started.append(kwargs)

        def start(self) -> None:
            return None

    monkeypatch.setattr("codex_plugin_scanner.guard.desktop_notifications.threading.Thread", CapturingThread)
    monkeypatch.setattr("codex_plugin_scanner.guard.desktop_notifications.platform.system", lambda: "Darwin")

    guard_home = tmp_path / "guard-home"

    assert ensure_desktop_notification_setup_async(
        guard_home,
        approval_url="http://127.0.0.1:5474/approvals/preview",
    )
    assert not ensure_desktop_notification_setup_async(
        guard_home,
        approval_url="http://127.0.0.1:5474/approvals/preview",
    )
    assert len(started) == 1
    assert started[0]["target"].__name__ == "_ensure_desktop_notification_setup_worker"
    assert started[0]["args"][1] == guard_home
    assert started[0]["daemon"] is True
    with _NOTIFICATION_SETUP_LOCK:
        _NOTIFICATION_SETUP_PATHS_IN_FLIGHT.clear()


def test_macos_setup_sends_preview_opens_settings_and_records_state(tmp_path) -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        calls.append(command)
        return _Completed()  # type: ignore[return-value]

    result = ensure_desktop_notification_setup(
        tmp_path / "guard-home",
        approval_url="http://127.0.0.1:5474/approvals/preview",
        system_name="Darwin",
        run=run,
        which=lambda name: "/usr/local/bin/terminal-notifier" if name == "terminal-notifier" else None,
    )

    assert result.supported is True
    assert result.preview_sent is True
    assert result.settings_opened is True
    assert result.already_prompted is False
    assert result.notifier_path == "/usr/local/bin/terminal-notifier"
    assert calls[0][0] == "/usr/local/bin/terminal-notifier"
    assert calls[1][:2] == ["open", "x-apple.systempreferences:com.apple.Notifications-Settings.extension"]
    assert (tmp_path / "guard-home" / "desktop-notifications.json").exists()


def test_macos_setup_does_not_reopen_after_prompt_marker(tmp_path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "desktop-notifications.json").write_text("{}", encoding="utf-8")
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[object]:
        calls.append(command)
        return _Completed()  # type: ignore[return-value]

    result = ensure_desktop_notification_setup(
        guard_home,
        approval_url="http://127.0.0.1:5474/approvals/preview",
        system_name="Darwin",
        run=run,
        which=lambda _name: "/usr/local/bin/terminal-notifier",
    )

    assert result.supported is True
    assert result.already_prompted is True
    assert result.preview_sent is False
    assert result.settings_opened is False
    assert calls == []
