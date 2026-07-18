"""Canonical dashboard launcher service.

Single entry point for opening the local Guard dashboard from both the
CLI (``hol-guard dashboard``) and the tray icon (``Open HOL Guard``).
Both callers must use this service — never duplicate the launch logic.

Security contract:
    - Daemon auth tokens are loaded in-process and placed only in the
      browser URL fragment. They never appear in return values, logs,
      process arguments, or diagnostics.
    - The returned ``DashboardLaunchResult.browser_url`` is the public
      (redacted) URL without the token fragment. The authenticated URL
      is passed directly to the browser opener and discarded.
"""

from __future__ import annotations

import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

from .daemon.manager import ensure_guard_daemon, load_guard_daemon_auth_token
from .local_dashboard_session import build_local_dashboard_session_token
from .runtime.surface_server import GuardSurfaceRuntime
from .tray.security import sanitize_secret

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DashboardLaunchResult:
    """Result of opening the local Guard dashboard.

    The ``browser_url`` field is the public (redacted) URL without the
    auth token fragment. It is safe to display in CLI output, logs,
    and dashboard UI. The authenticated URL is never stored here.
    """

    opened: bool
    approval_center_url: str
    """The daemon's approval-center base URL (no token)."""

    browser_url: str | None
    """Public browser URL without the token fragment, or None."""

    reason: str
    """Machine-readable reason code for the result."""

    error: str | None = None
    """Human-readable error message if the launch failed."""

    def to_payload(self) -> dict[str, object]:
        return {
            "opened": self.opened,
            "approval_center_url": self.approval_center_url,
            "browser_url": self.browser_url,
            "reason": self.reason,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Launch coalescing
# ---------------------------------------------------------------------------

_launch_lock = threading.Lock()
_in_flight = False
_last_result: DashboardLaunchResult | None = None


def open_dashboard(
    *,
    guard_home: Path,
    store: GuardStore,
    config: GuardConfig,
    force_open: bool = True,
    open_key: str = "dashboard",
) -> DashboardLaunchResult:
    """Open the local Guard dashboard in the default browser.

    This is the canonical launcher. Both ``hol-guard dashboard`` and the
    tray icon's ``Open HOL Guard`` call this function. It:

    1. Ensures the local daemon is running (starts it if needed).
    2. Loads the daemon auth token from trusted storage.
    3. Constructs the authenticated browser URL with the token in the fragment.
    4. Calls ``GuardSurfaceRuntime.ensure_surface()`` to open the browser
       with deduplication.
    5. Returns a result with only the public (redacted) URL.

    Raises:
        RuntimeError: If the daemon cannot be started or the auth token
            is unavailable. Callers should catch this and report a
            ``dashboard_open_failed`` reason.
    """
    global _in_flight, _last_result

    import webbrowser

    with _launch_lock:
        if _in_flight:
            # Coalesce repeated activations while a launch is in progress
            if _last_result is not None:
                return _last_result
            return DashboardLaunchResult(
                opened=False,
                approval_center_url="",
                browser_url=None,
                reason="already_in_flight",
            )
        _in_flight = True

    try:
        # 1. Ensure daemon is running
        try:
            approval_center_url = ensure_guard_daemon(guard_home)
        except RuntimeError as error:
            result = DashboardLaunchResult(
                opened=False,
                approval_center_url="",
                browser_url=None,
                reason="daemon_unavailable",
                error=sanitize_secret(str(error)),
            )
            _last_result = result
            return result

        # 2. Load auth token
        auth_token = load_guard_daemon_auth_token(guard_home)
        if auth_token is None:
            result = DashboardLaunchResult(
                opened=False,
                approval_center_url=approval_center_url,
                browser_url=None,
                reason="auth_token_missing",
                error="Guard daemon auth token is not available",
            )
            _last_result = result
            return result

        # 3. Construct authenticated browser URL (token in fragment)
        browser_url = _build_authenticated_browser_url(
            approval_center_url, auth_token=auth_token, surface="approval-center"
        )

        # 4. Open via surface runtime with deduplication. Wrap in try so any
        # unexpected failure (e.g. surface runtime raising) is normalized into
        # a clean redacted error payload instead of propagating to the caller
        # (which would crash the tray's open callback).
        surface_runtime = GuardSurfaceRuntime(store)
        try:
            open_result = surface_runtime.ensure_surface(
                surface="approval-center",
                approval_center_url=approval_center_url,
                browser_url=browser_url,
                approval_surface_policy=config.approval_surface_policy,
                open_key=open_key,
                force_open=force_open,
                opener=webbrowser.open,
            )
        except Exception as error:
            result = DashboardLaunchResult(
                opened=False,
                approval_center_url=approval_center_url,
                browser_url=_redact_token_from_url(browser_url),
                reason="dashboard_open_failed",
                error=sanitize_secret(str(error)),
            )
            _last_result = result
            return result

        # 5. Return redacted result (no token in browser_url)
        public_url = _redact_token_from_url(browser_url)
        result = DashboardLaunchResult(
            opened=bool(open_result.get("opened")),
            approval_center_url=approval_center_url,
            browser_url=public_url,
            reason=str(open_result.get("reason") or "unknown"),
        )
        _last_result = result
        return result

    finally:
        with _launch_lock:
            _in_flight = False


# ---------------------------------------------------------------------------
# URL construction helpers (token never leaves this module)
# ---------------------------------------------------------------------------


def _build_authenticated_browser_url(
    approval_center_url: str,
    *,
    auth_token: str,
    surface: str,
    daemon_url: str | None = None,
) -> str:
    """Construct the authenticated browser URL with the token in the fragment.

    The token is placed in the URL fragment (after ``#``) so it is never
    sent to a server. The fragment is stripped before returning any public URL.
    """
    parsed = urllib.parse.urlparse(approval_center_url)
    fragment_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key not in {"guard-token", "guardDaemon"}
    ]
    if daemon_url:
        fragment_pairs.append(("guardDaemon", daemon_url))
    fragment_pairs.append(
        (
            "guard-token",
            build_local_dashboard_session_token(auth_token=auth_token, surface=surface),
        )
    )
    return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.urlencode(fragment_pairs)))

def _redact_token_from_url(url: str | None) -> str | None:
    """Remove the ``guard-token`` parameter from a URL fragment.

    Returns the URL without the token, safe for display in CLI output,
    logs, and dashboard UI. If the URL is None, returns None.
    """
    if url is None:
        return None
    parsed = urllib.parse.urlparse(url)
    fragment_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key != "guard-token"
    ]
    return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.urlencode(fragment_pairs)))
