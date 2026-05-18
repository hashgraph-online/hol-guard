"""Best-effort desktop notifications for local Guard approvals."""

from __future__ import annotations

import html
import json
import os
import platform
import shutil
import subprocess
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MACOS_TERMINAL_NOTIFIER_BUNDLE_ID = "fr.julienxx.oss.terminal-notifier"
MACOS_NOTIFICATION_SETTINGS_URL = (
    "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
    f"?id={MACOS_TERMINAL_NOTIFIER_BUNDLE_ID}"
)
_NOTIFICATION_SETUP_STATE_FILE = "desktop-notifications.json"


@dataclass(frozen=True, slots=True)
class DesktopApprovalNotification:
    """Notification copy for a pending local approval request."""

    request_id: str
    title: str
    message: str
    approval_url: str


@dataclass(frozen=True, slots=True)
class DesktopNotificationSetupResult:
    """Result from local OS notification permission setup."""

    platform: str
    supported: bool
    preview_sent: bool
    settings_opened: bool
    settings_url: str | None
    already_prompted: bool
    notifier_path: str | None


_NOTIFIED_APPROVAL_IDS: set[str] = set()
_NOTIFICATION_ATTEMPTS_IN_FLIGHT: set[str] = set()
_NOTIFIED_APPROVAL_IDS_LOCK = threading.Lock()
_NOTIFICATION_SETUP_PATHS_IN_FLIGHT: set[Path] = set()
_NOTIFICATION_SETUP_LOCK = threading.Lock()


def notify_pending_approval_once(
    notification: DesktopApprovalNotification,
    *,
    asynchronous: bool = True,
    on_success: Callable[[], None] | None = None,
) -> bool:
    """Send one native notification for an approval request ID.

    The default path dispatches native notification work off-thread so approval
    waiting is never delayed by OS notification APIs.
    """

    if _desktop_notifications_disabled_by_env():
        return False
    with _NOTIFIED_APPROVAL_IDS_LOCK:
        if (
            notification.request_id in _NOTIFIED_APPROVAL_IDS
            or notification.request_id in _NOTIFICATION_ATTEMPTS_IN_FLIGHT
        ):
            return False
        _NOTIFICATION_ATTEMPTS_IN_FLIGHT.add(notification.request_id)
    if asynchronous:
        try:
            threading.Thread(
                target=_deliver_notification,
                args=(notification, on_success),
                name=f"hol-guard-notify-{notification.request_id}",
            ).start()
        except Exception:
            with _NOTIFIED_APPROVAL_IDS_LOCK:
                _NOTIFICATION_ATTEMPTS_IN_FLIGHT.discard(notification.request_id)
            return False
        return True
    return _deliver_notification(notification, on_success)


def _deliver_notification(
    notification: DesktopApprovalNotification,
    on_success: Callable[[], None] | None = None,
) -> bool:
    """Deliver notification and update request ID state after real success."""

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
    if on_success is not None:
        on_success()
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


def desktop_notification_setup_supported(system_name: str | None = None) -> bool:
    """Return whether local notification setup can prompt the current OS."""

    return (system_name or platform.system()) == "Darwin" and not _desktop_notifications_disabled_by_env()


def ensure_desktop_notification_setup_async(
    guard_home: Path,
    *,
    approval_url: str,
    force: bool = False,
) -> bool:
    """Start local notification setup without delaying approval queueing."""

    if not force and not desktop_notification_setup_supported():
        return False
    state_path = guard_home / _NOTIFICATION_SETUP_STATE_FILE
    if state_path.exists() and not force:
        return False
    key = guard_home.expanduser().resolve(strict=False)
    with _NOTIFICATION_SETUP_LOCK:
        if key in _NOTIFICATION_SETUP_PATHS_IN_FLIGHT:
            return False
        _NOTIFICATION_SETUP_PATHS_IN_FLIGHT.add(key)
    try:
        threading.Thread(
            target=_ensure_desktop_notification_setup_worker,
            args=(key, guard_home, approval_url, force),
            name=f"hol-guard-notification-setup-{uuid.uuid4().hex}",
            daemon=True,
        ).start()
    except Exception:
        with _NOTIFICATION_SETUP_LOCK:
            _NOTIFICATION_SETUP_PATHS_IN_FLIGHT.discard(key)
        return False
    return True


def ensure_desktop_notification_setup(
    guard_home: Path,
    *,
    approval_url: str,
    force: bool = False,
    system_name: str | None = None,
    run: Callable[..., subprocess.CompletedProcess[object]] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
) -> DesktopNotificationSetupResult:
    """Register macOS notifier and open Notifications settings when needed."""

    system = system_name or platform.system()
    if not desktop_notification_setup_supported(system):
        return DesktopNotificationSetupResult(
            platform=system,
            supported=False,
            preview_sent=False,
            settings_opened=False,
            settings_url=None,
            already_prompted=False,
            notifier_path=None,
        )
    state_path = guard_home / _NOTIFICATION_SETUP_STATE_FILE
    already_prompted = state_path.exists()
    terminal_notifier = which("terminal-notifier")
    if already_prompted and not force:
        return DesktopNotificationSetupResult(
            platform=system,
            supported=True,
            preview_sent=False,
            settings_opened=False,
            settings_url=MACOS_NOTIFICATION_SETTINGS_URL,
            already_prompted=True,
            notifier_path=terminal_notifier,
        )
    preview_sent = send_desktop_approval_notification(
        DesktopApprovalNotification(
            request_id=f"notification-setup-{uuid.uuid4().hex}",
            title="HOL Guard notifications",
            message="Enable alerts for approval requests from HOL Guard.",
            approval_url=approval_url,
        ),
        system_name=system,
        run=run,
        which=which,
    )
    settings_opened = _open_macos_notification_settings(run=run)
    if settings_opened:
        _write_notification_setup_state(
            state_path,
            {
                "opened_at": _utc_now(),
                "settings_url": MACOS_NOTIFICATION_SETTINGS_URL,
                "preview_sent": preview_sent,
                "settings_opened": settings_opened,
                "notifier_path": terminal_notifier,
            },
        )
    return DesktopNotificationSetupResult(
        platform=system,
        supported=True,
        preview_sent=preview_sent,
        settings_opened=settings_opened,
        settings_url=MACOS_NOTIFICATION_SETTINGS_URL,
        already_prompted=already_prompted,
        notifier_path=terminal_notifier,
    )


def _ensure_desktop_notification_setup_worker(
    key: Path,
    guard_home: Path,
    approval_url: str,
    force: bool,
) -> None:
    try:
        ensure_desktop_notification_setup(
            guard_home,
            approval_url=approval_url,
            force=force,
        )
    except Exception:
        return
    finally:
        with _NOTIFICATION_SETUP_LOCK:
            _NOTIFICATION_SETUP_PATHS_IN_FLIGHT.discard(key)


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
                f"hol-guard-{notification.request_id}-{uuid.uuid4().hex}",
                "-sound",
                "default",
                "-ignoreDnD",
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
                f'display notification "{_escape_osascript(_macos_fallback_message(notification))}" '
                f'with title "{_escape_osascript(notification.title)}" '
                'subtitle "Action needs approval" sound name "default"'
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


def _open_macos_notification_settings(
    *,
    run: Callable[..., subprocess.CompletedProcess[object]],
) -> bool:
    return _run_notification_command(
        run,
        ["open", MACOS_NOTIFICATION_SETTINGS_URL],
        check=False,
        timeout=3,
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
$Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier()
$Notifier.Show($Toast)
""".strip()


def _run_notification_command(
    run: Callable[..., subprocess.CompletedProcess[object]],
    command: list[str],
    **kwargs: object,
) -> bool:
    try:
        result = run(command, **kwargs)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _write_notification_setup_state(state_path: Path, payload: dict[str, object]) -> None:
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    except OSError:
        return


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _escape_osascript(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _macos_fallback_message(notification: DesktopApprovalNotification) -> str:
    return f"{notification.message} Open: {notification.approval_url}"


def _escape_powershell_single_quoted(value: str) -> str:
    return html.unescape(value).replace("'", "''")
