"""Canonical dashboard launcher service.

Single entry point for opening the local Guard dashboard from the CLI and other
trusted local launch surfaces. Callers must use this service rather than
duplicating authentication and browser-launch logic.

Security contract:
    - Daemon auth tokens are loaded in-process and never returned.
    - Browser launches put a short-lived, surface-scoped dashboard session token
      only in the URL fragment so it is never sent in an HTTP request.
    - ``build_desktop_dashboard_session_url`` is reserved for the trusted local
      Desktop bootstrap contract. It returns a short-lived dashboard session URL,
      never the daemon auth token, and callers must treat that URL as sensitive.
    - The returned ``DashboardLaunchResult.browser_url`` is the public
      (redacted) URL without the token fragment. The authenticated URL
      is passed directly to the browser opener and discarded.
"""

from __future__ import annotations

import os
import sys
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

from ..version import __version__
from .browser_opener import open_browser_url
from .cli.update_desktop_core_start import wait_for_started_core
from .local_dashboard_session import build_local_dashboard_session_token
from .native_daemon_failure import daemon_failure_code
from .native_daemon_manage import (
    GuardDaemonStillStartingError,
    desktop_preflight_requested,
    ensure_guard_daemon,
    load_guard_daemon_auth_token,
)
from .runtime.surface_server import GuardSurfaceRuntime
from .secret_redaction import sanitize_secret

DESKTOP_DASHBOARD_EMBED_QUERY_KEY = "desktop_embed"


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
            **dashboard_diagnostics(self),
        }


# Surface-runtime reasons renamed to the dashboard's diagnostic codes.
_SURFACE_REASONS = {"open-failed": "browser_unavailable"}
# How the browser step ended for each reason.
_BROWSER_RESULTS = {
    "opened": "opened",
    "browser_unavailable": "unavailable",
    "dashboard_open_failed": "unavailable",
    "already-opened": "already_open",
    "live-client": "already_open",
    "policy-disabled": "skipped_by_policy",
    "attention-deferred": "deferred",
    "already_in_flight": "launch_in_progress",
}
_FALLBACKS = {
    "browser_unavailable": "No browser could be opened. Run `hol-guard dashboard` from a desktop session, "
    "or open the dashboard address in a browser on this machine and sign in from the Guard prompt.",
    "port_conflict": "Another program holds every port Guard can use. Close it, or set a free port "
    "in Guard's settings, then run `hol-guard dashboard` again.",
    "native_runtime_unavailable": "Guard's native runtime is missing or damaged. Reinstall HOL Guard, "
    "then run `hol-guard dashboard` again.",
    "daemon_still_starting": "Guard is still starting. Wait a few seconds and run `hol-guard dashboard` again.",
    "already_in_flight": "Another dashboard launch is in progress. Wait for it to finish.",
    "policy-disabled": "Your approval surface policy keeps the browser closed. "
    "Open the dashboard address in a browser on this machine.",
    "attention-deferred": "Guard deferred opening the browser. "
    "Open the dashboard address in a browser on this machine.",
    "auth_token_missing": "Guard's local credentials are missing. Run `hol-guard doctor` to repair them.",
}
_FALLBACKS["dashboard_open_failed"] = _FALLBACKS["browser_unavailable"]
_DAEMON_FALLBACK = "Guard's approval center did not start. Run `hol-guard doctor` for details."


def dashboard_diagnostics(result: DashboardLaunchResult) -> dict[str, object]:
    """Port, browser result and terminal fallback for a dashboard launch.

    The signed browser URL carries a dashboard session token, so it is only
    handed to the browser and never printed: an agent reading this output
    must not be able to open the approval center on the user's behalf.
    """

    port: int | None = None
    if result.approval_center_url:
        try:
            port = urllib.parse.urlparse(result.approval_center_url).port
        except ValueError:
            port = None
    browser = _BROWSER_RESULTS.get(result.reason, "not_attempted")
    fallback = None if result.opened else _FALLBACKS.get(result.reason, _DAEMON_FALLBACK)
    return {
        "port": port,
        "browser": browser,
        "signed_url": "delivered_to_browser" if result.opened else "withheld",
        "fallback": fallback,
    }


_launch_lock = threading.Lock()
_in_flight = False
_last_result: DashboardLaunchResult | None = None


def desktop_bootstrap_is_preflight() -> bool:
    """True when Desktop is validating a candidate Core without starting a daemon."""

    return desktop_preflight_requested()


def _desktop_owned_core_executable() -> Path | None:
    """Return the Core binary Desktop launched, so the daemon is that same binary."""

    raw = os.environ.get("HOL_GUARD_DESKTOP_RUNTIME_OWNER")
    if isinstance(raw, str) and raw.strip():
        candidate = Path(raw).expanduser()
        try:
            if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                return candidate.resolve()
        except OSError:
            return None
    if bool(getattr(sys, "frozen", False)):
        try:
            return Path(sys.executable).expanduser().resolve(strict=True)
        except OSError:
            return None
    return None


def build_desktop_dashboard_session_url(
    *,
    guard_home: Path,
    home_dir: Path | None = None,
) -> str:
    """Return a short-lived canonical dashboard URL for trusted Desktop embedding.

    The daemon's long-lived auth token never crosses this boundary. Desktop only
    receives a surface-scoped local dashboard session token in the URL fragment.
    The explicit query marker allows the local daemon to relax frame ancestry for
    the Tauri host on this document only; ordinary browser dashboard responses
    remain non-frameable.
    """

    if desktop_bootstrap_is_preflight():
        raise RuntimeError("Desktop preflight does not start a local daemon")
    try:
        approval_center_url = ensure_guard_daemon(
            guard_home,
            home_dir=home_dir,
            executable=_desktop_owned_core_executable(),
        )
    except GuardDaemonStillStartingError:
        # A loaded machine can need longer than the start window to load Core.
        # The launch keeps running, so wait for it inside Desktop's activation
        # budget instead of failing bootstrap. Only a daemon serving this Core
        # (or newer) counts; an older one is not the Core Desktop activated.
        started_url = wait_for_started_core(guard_home, minimum_version=__version__)
        if started_url is None:
            raise
        approval_center_url = started_url
    auth_token = load_guard_daemon_auth_token(guard_home)
    if auth_token is None:
        raise RuntimeError("Guard daemon auth token is not available")
    return build_desktop_dashboard_session_url_for_daemon(
        daemon_url=approval_center_url,
        auth_token=auth_token,
    )


def build_desktop_dashboard_session_url_for_daemon(*, daemon_url: str, auth_token: str) -> str:
    """Mint a dashboard session URL for a daemon this process already knows is local.

    Callers inside the running daemon use this so bootstrap does not health-check
    itself. The daemon auth token stays in-process; the URL fragment carries only
    the short-lived dashboard session token.
    """

    parsed = urllib.parse.urlparse(daemon_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("Desktop bootstrap session URL requires the loopback daemon")
    if parsed.username or parsed.password:
        raise ValueError("Desktop bootstrap session URL requires the loopback daemon")
    query_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != DESKTOP_DASHBOARD_EMBED_QUERY_KEY
    ]
    query_pairs.append((DESKTOP_DASHBOARD_EMBED_QUERY_KEY, "1"))
    embed_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_pairs)))
    return _build_authenticated_browser_url(
        embed_url,
        auth_token=auth_token,
        surface="approval-center",
    )


def open_dashboard(
    *,
    guard_home: Path,
    store: GuardStore,
    config: GuardConfig,
    force_open: bool = True,
    open_key: str = "dashboard",
) -> DashboardLaunchResult:
    """Open the local Guard dashboard in the default browser.

    This is the canonical launcher for trusted local callers. It:

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

    with _launch_lock:
        if _in_flight:
            return DashboardLaunchResult(
                opened=False,
                approval_center_url="",
                browser_url=None,
                reason="already_in_flight",
            )
        _in_flight = True

    try:
        try:
            approval_center_url = ensure_guard_daemon(guard_home)
        except (RuntimeError, OSError, ValueError) as error:
            # TimeoutError is an OSError. Every failure names its native cause.
            result = DashboardLaunchResult(
                opened=False,
                approval_center_url="",
                browser_url=None,
                reason=daemon_failure_code(error),
                error=sanitize_secret(str(error)),
            )
            _last_result = result
            return result

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

        browser_url = _build_authenticated_browser_url(
            approval_center_url, auth_token=auth_token, surface="approval-center"
        )

        surface_runtime = GuardSurfaceRuntime(store)
        try:
            open_result = surface_runtime.ensure_surface(
                surface="approval-center",
                approval_center_url=approval_center_url,
                browser_url=browser_url,
                approval_surface_policy=config.approval_surface_policy,
                open_key=open_key,
                force_open=force_open,
                opener=open_browser_url,
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

        public_url = _redact_token_from_url(browser_url)
        result = DashboardLaunchResult(
            opened=bool(open_result.get("opened")),
            approval_center_url=approval_center_url,
            browser_url=public_url,
            reason=_surface_reason(open_result),
        )
        _last_result = result
        return result

    finally:
        with _launch_lock:
            _in_flight = False


def _surface_reason(open_result: dict[str, object]) -> str:
    """The surface runtime's reason as a dashboard code; never unknown."""

    raw = open_result.get("reason")
    if isinstance(raw, str) and raw:
        return _SURFACE_REASONS.get(raw, raw)
    return "opened" if open_result.get("opened") else "browser_unavailable"


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
