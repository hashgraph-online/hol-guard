"""Authenticated verification for an already-running Guard daemon."""

from __future__ import annotations

from pathlib import Path

from .discovery import load_authenticated_daemon_state
from .manager import GUARD_DAEMON_COMPATIBILITY_VERSION, load_guard_daemon_auth_token


def _proxy_disabled_health_details(url: str, auth_token: str) -> dict[str, object] | None:
    """Use the bounded loopback client without changing authenticated identity checks."""
    from .client import read_guard_health_details

    return read_guard_health_details(url, auth_token)


def verified_live_guard_daemon_identity(guard_home: Path) -> dict[str, object] | None:
    """Return authenticated live daemon identity after state and health agree."""

    state = load_authenticated_daemon_state(guard_home)
    if not isinstance(state, dict):
        return None
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
        or not 1 <= port <= 65_535
        or state.get("compatibility_version") != GUARD_DAEMON_COMPATIBILITY_VERSION
        or not isinstance(runtime_fingerprint, str)
        or not runtime_fingerprint
        or not isinstance(pid, int)
        or pid <= 0
        or not isinstance(token, str)
        or not token
    ):
        return None
    url_host = f"[{host}]" if host == "::1" else host
    daemon_url = f"http://{url_host}:{port}"
    details = _proxy_disabled_health_details(daemon_url, token)
    identity_fields = ("package_version", "compatibility_version", "runtime_fingerprint", "pid")
    details_guard_home = details.get("guard_home") if isinstance(details, dict) else None
    if (
        not isinstance(details, dict)
        or details.get("ok") is not True
        or not isinstance(details_guard_home, str)
        or not details_guard_home
        or any(details.get(field) != state.get(field) for field in identity_fields)
    ):
        return None
    try:
        resolved_details_home = Path(details_guard_home).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved_details_home != guard_home.expanduser().resolve():
        return None
    return {**state, "daemon_url": daemon_url}


__all__ = ["verified_live_guard_daemon_identity"]
