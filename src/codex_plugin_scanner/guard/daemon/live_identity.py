"""Authenticated verification for an already-running Guard daemon."""

from __future__ import annotations

import math
import time
from pathlib import Path

from .discovery import load_authenticated_daemon_state
from .manager import GUARD_DAEMON_COMPATIBILITY_VERSION, load_guard_daemon_auth_token


def _state_marker(state: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = state.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _state_identity_matches(
    expected: dict[str, object],
    current: dict[str, object],
    guard_home: Path,
    *,
    require_markers: bool,
) -> bool:
    expected_home = expected.get("guard_home")
    current_home = current.get("guard_home")
    try:
        if (
            not isinstance(expected_home, str)
            or not isinstance(current_home, str)
            or Path(expected_home).expanduser().resolve() != guard_home.expanduser().resolve()
            or Path(current_home).expanduser().resolve() != guard_home.expanduser().resolve()
        ):
            return False
    except (OSError, RuntimeError, ValueError):
        return False
    if (
        expected.get("package_version") != current.get("package_version")
        or expected.get("compatibility_version") != current.get("compatibility_version")
        or expected.get("pid") != current.get("pid")
        or expected.get("host") != current.get("host")
        or expected.get("port") != current.get("port")
    ):
        return False
    expected_runtime = _state_marker(expected, "runtime_fingerprint", "runtime")
    current_runtime = _state_marker(current, "runtime_fingerprint", "runtime")
    expected_generation = _state_marker(expected, "generation", "state_id")
    current_generation = _state_marker(current, "generation", "state_id")
    expected_owner = _state_marker(expected, "user", "uid")
    current_owner = _state_marker(current, "user", "uid")
    expected_start = _state_marker(expected, "start_marker", "process_start_marker")
    current_start = _state_marker(current, "start_marker", "process_start_marker")
    if require_markers and None in {
        expected_runtime,
        current_runtime,
        expected_generation,
        current_generation,
        expected_owner,
        current_owner,
        expected_start,
        current_start,
    }:
        return False
    return (
        expected_runtime == current_runtime
        and expected_generation == current_generation
        and expected_owner == current_owner
        and expected_start == current_start
    )


def _health_details_match(details: object, state: dict[str, object], guard_home: Path) -> bool:
    if not isinstance(details, dict):
        return False
    details_guard_home = details.get("guard_home")
    identity_fields = ("package_version", "compatibility_version", "runtime_fingerprint", "pid")
    if (
        details.get("ok") is not True
        or not isinstance(details_guard_home, str)
        or not details_guard_home
        or any(details.get(field) != state.get(field) for field in identity_fields)
    ):
        return False
    try:
        return Path(details_guard_home).expanduser().resolve() == guard_home.expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def _proxy_disabled_health_details(
    url: str,
    auth_token: str,
    *,
    timeout: float | None = None,
) -> dict[str, object] | None:
    """Use the bounded loopback client without changing authenticated identity checks."""
    from .client import read_guard_health_details

    return read_guard_health_details(url, auth_token, timeout=timeout)


def _proxy_dashboard_session_capabilities(
    url: str,
    auth_token: str,
    *,
    timeout: float,
) -> dict[str, object] | None:
    """Prove the normal dashboard session path without exposing its tokens."""
    from .client import GuardSurfaceDaemonClient

    try:
        return GuardSurfaceDaemonClient(url, auth_token).dashboard_session_capabilities(timeout=timeout)
    except (OSError, RuntimeError, TimeoutError, ValueError):
        return None


def probe_live_guard_daemon_identity(
    guard_home: Path,
    *,
    session_timeout: float = 1.0,
    verify_dashboard: bool = True,
) -> tuple[dict[str, object] | None, str]:
    """Return identity plus a safe reason for health or session failure.

    Health details prove the selected process and Guard home. A successful
    health probe with a failed normal dashboard session keeps that identity so
    recovery can report a reconnect issue without replacing the healthy
    process.
    """
    try:
        probe_timeout = float(session_timeout)
    except (TypeError, ValueError, OverflowError):
        return None, "service_unresponsive"
    if not math.isfinite(probe_timeout) or probe_timeout <= 0.0:
        return None, "service_unresponsive"
    deadline = time.monotonic() + probe_timeout

    def remaining() -> float:
        return max(0.0, deadline - time.monotonic())

    state = load_authenticated_daemon_state(guard_home)
    if not isinstance(state, dict):
        return None, "identity_unverified"
    version_text = state.get("package_version")
    host = state.get("host")
    port = state.get("port")
    pid = state.get("pid")
    runtime_fingerprint = state.get("runtime_fingerprint")
    token = load_guard_daemon_auth_token(guard_home)
    if (
        not isinstance(version_text, str)
        or not isinstance(host, str)
        or host not in {"127.0.0.1", "::1"}
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65_535
        or state.get("compatibility_version") != GUARD_DAEMON_COMPATIBILITY_VERSION
        or not isinstance(runtime_fingerprint, str)
        or not runtime_fingerprint
        or not isinstance(pid, int)
        or pid <= 0
        or not isinstance(token, str)
        or not token
    ):
        return None, "identity_unverified"
    url_host = f"[{host}]" if host == "::1" else host
    # S5332 is a false positive: the authenticated local IPC host is loopback-only above.
    daemon_url = f"http://{url_host}:{port}"  # NOSONAR(S5332)
    health_timeout = remaining()
    if health_timeout <= 0.0:
        return None, "service_unresponsive"
    details = _proxy_disabled_health_details(daemon_url, token, timeout=health_timeout)
    if not _health_details_match(details, state, guard_home):
        return None, "service_unresponsive"
    identity = {**state, "daemon_url": daemon_url}
    if not verify_dashboard:
        return identity, "healthy"
    session_timeout_remaining = remaining()
    if session_timeout_remaining <= 0.0:
        return identity, "session_invalid"
    if (
        _proxy_dashboard_session_capabilities(
            daemon_url,
            token,
            timeout=session_timeout_remaining,
        )
        is None
    ):
        return identity, "session_invalid"
    refreshed_state = load_authenticated_daemon_state(guard_home)
    if not isinstance(refreshed_state, dict):
        return identity, "identity_unverified"
    if not _state_identity_matches(
        state,
        refreshed_state,
        guard_home,
        require_markers=True,
    ):
        # Do not send the freshly loaded bearer token to an authority that
        # differs from the process generation which passed the first probe.
        return identity, "identity_unverified"
    refreshed_host = refreshed_state.get("host")
    refreshed_port = refreshed_state.get("port")
    if (
        not isinstance(refreshed_host, str)
        or refreshed_host not in {"127.0.0.1", "::1"}
        or not isinstance(refreshed_port, int)
        or isinstance(refreshed_port, bool)
        or not 1 <= refreshed_port <= 65_535
    ):
        return identity, "identity_unverified"
    refreshed_token = load_guard_daemon_auth_token(guard_home)
    if not isinstance(refreshed_token, str) or not refreshed_token:
        return identity, "identity_unverified"
    refreshed_url_host = f"[{refreshed_host}]" if refreshed_host == "::1" else refreshed_host
    # S5332 is a false positive: the refreshed host and generation are verified above.
    refreshed_url = f"http://{refreshed_url_host}:{refreshed_port}"  # NOSONAR(S5332)
    refreshed_health_timeout = remaining()
    if refreshed_health_timeout <= 0.0:
        return identity, "identity_unverified"
    refreshed_details = _proxy_disabled_health_details(
        refreshed_url,
        refreshed_token,
        timeout=refreshed_health_timeout,
    )
    if not _health_details_match(refreshed_details, refreshed_state, guard_home):
        return identity, "identity_unverified"
    return identity, "healthy"


def verified_live_guard_daemon_identity(
    guard_home: Path,
    *,
    session_timeout: float = 1.0,
) -> dict[str, object] | None:
    """Return authenticated process identity from the existing health probe."""
    identity, reason = probe_live_guard_daemon_identity(
        guard_home,
        session_timeout=session_timeout,
        verify_dashboard=False,
    )
    return identity if reason == "healthy" else None


__all__ = ["probe_live_guard_daemon_identity", "verified_live_guard_daemon_identity"]
