"""Best-effort desktop notifications for local Guard approvals."""

from __future__ import annotations

import html
import os
import platform
import shutil
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DesktopApprovalNotification:
    """Notification copy for a pending local approval request."""

    request_id: str
    title: str
    message: str
    approval_url: str


_NOTIFIED_APPROVAL_IDS: set[str] = set()
_NOTIFICATION_ATTEMPTS_IN_FLIGHT: set[str] = set()
_NOTIFIED_APPROVAL_IDS_LOCK = threading.Lock()


def notify_pending_approval_once(notification: DesktopApprovalNotification) -> bool:
    """Send one native notification for an approval request ID."""

    if _desktop_notifications_disabled_by_env():
        return False
    with _NOTIFIED_APPROVAL_IDS_LOCK:
        if (
            notification.request_id in _NOTIFIED_APPROVAL_IDS
            or notification.request_id in _NOTIFICATION_ATTEMPTS_IN_FLIGHT
        ):
            return False
        _NOTIFICATION_ATTEMPTS_IN_FLIGHT.add(notification.request_id)
    try:
        sent = send_desktop_approval_notification(notification)
    except Exception:
        return False
    finally:
        with _NOTIFIED_APPROVAL_IDS_LOCK:
            _NOTIFICATION_ATTEMPTS_IN_FLIGHT.discard(notification.request_id)
    if not sent:
        return False
    with _NOTIFIED_APPROVAL_IDS_LOCK:
        _NOTIFIED_APPROVAL_IDS.add(notification.request_id)
    return True


def send_desktop_approval_notification(
    notification: DesktopApprovalNotification,
    *,
    system_name: str | None = None,
    run: Callable[..., subprocess.CompletedProcess[object]] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
) -> bool:
    """Send a native desktop notification on macOS or Windows."""

    system = system_name or platform.system()
    if system == "Darwin":
        return _send_macos_notification(notification, run=run, which=which)
    if system == "Windows":
        return _send_windows_notification(notification, run=run)
    return False


def _desktop_notifications_disabled_by_env() -> bool:
    value = os.environ.get("HOL_GUARD_DESKTOP_NOTIFICATIONS", "").strip().lower()
    return value in {"0", "false", "off", "no"}


def _send_macos_notification(
    notification: DesktopApprovalNotification,
    *,
    run: Callable[..., subprocess.CompletedProcess[object]],
    which: Callable[[str], str | None],
) -> bool:
    terminal_notifier = which("terminal-notifier")
    if terminal_notifier:
        return _run_notification_command(
            run,
            [
                terminal_notifier,
                "-title",
                notification.title,
                "-subtitle",
                "Action needs approval",
                "-message",
                notification.message,
                "-open",
                notification.approval_url,
                "-group",
                f"hol-guard-{notification.request_id}",
            ],
            check=False,
            timeout=3,
        )
    return _run_notification_command(
        run,
        [
            "osascript",
            "-e",
            (
                f'display notification "{_escape_osascript(notification.message)}" '
                f'with title "{_escape_osascript(notification.title)}" '
                'subtitle "Action needs approval"'
            ),
        ],
        check=False,
        timeout=3,
    )


def _send_windows_notification(
    notification: DesktopApprovalNotification,
    *,
    run: Callable[..., subprocess.CompletedProcess[object]],
) -> bool:
    script = _windows_toast_script(notification)
    return _run_notification_command(
        run,
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        check=False,
        timeout=5,
    )


def _windows_toast_script(notification: DesktopApprovalNotification) -> str:
    title = _escape_powershell_single_quoted(notification.title)
    message = _escape_powershell_single_quoted(notification.message)
    url = _escape_powershell_single_quoted(notification.approval_url)
    return f"""
$Title = '{title}'
$Message = '{message}'
$Url = '{url}'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$Template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
$Xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($Template)
$TextNodes = $Xml.GetElementsByTagName('text')
$TextNodes.Item(0).AppendChild($Xml.CreateTextNode($Title)) > $null
$TextNodes.Item(1).AppendChild($Xml.CreateTextNode($Message)) > $null
$ToastNode = $Xml.GetElementsByTagName('toast').Item(0)
$ToastNode.SetAttribute('launch', $Url)
$Actions = $Xml.CreateElement('actions')
$OpenAction = $Xml.CreateElement('action')
$OpenAction.SetAttribute('content', 'Open approval')
$OpenAction.SetAttribute('arguments', $Url)
$OpenAction.SetAttribute('activationType', 'protocol')
$Actions.AppendChild($OpenAction) > $null
$ToastNode.AppendChild($Actions) > $null
$Toast = [Windows.UI.Notifications.ToastNotification]::new($Xml)
$Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('HOL Guard')
$Notifier.Show($Toast)
""".strip()


def _run_notification_command(
    run: Callable[..., subprocess.CompletedProcess[object]],
    command: list[str],
    **kwargs: object,
) -> bool:
    result = run(command, **kwargs)
    return result.returncode == 0


def _escape_osascript(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_powershell_single_quoted(value: str) -> str:
    return html.unescape(value).replace("'", "''")
