"""Best-effort desktop notifications for local Guard approvals.

The native runtime's `desktop-notification` command runs the platform
notifier; this module keeps the once-per-request bookkeeping.
"""

from __future__ import annotations

import os
import platform
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .mdm.runtime_request import runtime_answer

_NATIVE_FEATURE = "native-desktop-notification-v1"
_NATIVE_COMMAND = "desktop-notification"
_NATIVE_SCHEMA = "desktop-notification.v1"
_NATIVE_OUTPUT_LIMIT = 4096
# The runtime gives each notifier a few seconds, and setup runs two.
_SEND_TIMEOUT_SECONDS = 10.0
_SETUP_TIMEOUT_SECONDS = 15.0


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


def desktop_notification_setup_payload(
    result: object,
    *,
    guidance: str | None = None,
) -> dict[str, object]:
    """Return a stable JSON payload for notification setup results."""

    payload: dict[str, object] = {
        "platform": getattr(result, "platform", "unknown"),
        "supported": bool(getattr(result, "supported", False)),
        "preview_sent": bool(getattr(result, "preview_sent", False)),
        "settings_opened": bool(getattr(result, "settings_opened", False)),
        "settings_url": getattr(result, "settings_url", None),
        "already_prompted": bool(getattr(result, "already_prompted", False)),
        "notifier_path": getattr(result, "notifier_path", None),
    }
    if guidance:
        payload["guidance"] = guidance
    return payload


def macos_notification_guidance(notifier_path: str | None) -> str:
    """Describe macOS setup when Settings cannot reliably deep-link to the app row."""

    app_name = "terminal-notifier" if notifier_path else "Terminal or terminal-notifier"
    return (
        f"macOS may open the general Notifications list. Choose {app_name}, enable Allow Notifications, "
        "then enable Banners or Alerts plus Sounds."
    )


_NOTIFIED_APPROVAL_IDS: set[str] = set()
_NOTIFICATION_ATTEMPTS_IN_FLIGHT: set[str] = set()
_NOTIFIED_APPROVAL_IDS_LOCK = threading.Lock()


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


def send_desktop_approval_notification(notification: DesktopApprovalNotification) -> bool:
    """Send a native desktop notification on macOS or Windows."""

    if platform.system() not in {"Darwin", "Windows"}:
        return False
    answer = runtime_answer(
        _NATIVE_FEATURE,
        _NATIVE_COMMAND,
        {
            "op": "send",
            "schema": _NATIVE_SCHEMA,
            "notification": {
                "request_id": notification.request_id,
                "title": notification.title,
                "message": notification.message,
                "approval_url": notification.approval_url,
            },
        },
        output_limit=_NATIVE_OUTPUT_LIMIT,
        timeout_seconds=_SEND_TIMEOUT_SECONDS,
    )
    return answer is not None and answer.get("sent") is True


def desktop_notification_setup_supported(system_name: str | None = None) -> bool:
    """Return whether local notification setup can prompt the current OS."""

    return (system_name or platform.system()) == "Darwin" and not _desktop_notifications_disabled_by_env()


def ensure_desktop_notification_setup(
    guard_home: Path,
    *,
    approval_url: str,
    force: bool = False,
) -> DesktopNotificationSetupResult:
    """Register macOS notifier and open Notifications settings when needed."""

    system = platform.system()
    answer = None
    if desktop_notification_setup_supported(system):
        answer = runtime_answer(
            _NATIVE_FEATURE,
            _NATIVE_COMMAND,
            {
                "op": "setup",
                "schema": _NATIVE_SCHEMA,
                "guard_home": str(guard_home.absolute()),
                "approval_url": approval_url,
                "force": force,
            },
            output_limit=_NATIVE_OUTPUT_LIMIT,
            timeout_seconds=_SETUP_TIMEOUT_SECONDS,
        )
    if answer is None or answer.get("supported") is not True:
        return DesktopNotificationSetupResult(
            platform=system,
            supported=False,
            preview_sent=False,
            settings_opened=False,
            settings_url=None,
            already_prompted=False,
            notifier_path=None,
        )
    settings_url = answer.get("settings_url")
    notifier_path = answer.get("notifier_path")
    return DesktopNotificationSetupResult(
        platform=system,
        supported=True,
        preview_sent=answer.get("preview_sent") is True,
        settings_opened=answer.get("settings_opened") is True,
        settings_url=settings_url if isinstance(settings_url, str) else None,
        already_prompted=answer.get("already_prompted") is True,
        notifier_path=notifier_path if isinstance(notifier_path, str) else None,
    )


def _desktop_notifications_disabled_by_env() -> bool:
    value = os.environ.get("HOL_GUARD_DESKTOP_NOTIFICATIONS", "").strip().lower()
    return value in {"0", "false", "off", "no"}
