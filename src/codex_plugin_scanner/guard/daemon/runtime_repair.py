"""User-initiated repair for stale local daemon runtimes."""

from __future__ import annotations

from pathlib import Path

from packaging.version import InvalidVersion, Version

from ...version import __version__
from .discovery import load_authenticated_daemon_state
from .manager import (
    GUARD_DAEMON_COMPATIBILITY_VERSION,
    _daemon_healthz_details_payload,
    _guard_daemon_start_lock,
    clear_guard_daemon_state,
    ensure_guard_daemon_after_update,
    guard_daemon_retirement_is_complete,
    load_guard_daemon_auth_token,
    repair_approval_center_locator,
    retire_all_guard_daemons_for_home,
)


def _verified_live_runtime(
    guard_home: Path,
    state: dict[str, object],
) -> tuple[Version, str] | None:
    version_text = state.get("package_version")
    host = state.get("host")
    port = state.get("port")
    pid = state.get("pid")
    token = load_guard_daemon_auth_token(guard_home)
    identity_fields = ("package_version", "compatibility_version", "runtime_fingerprint", "pid")
    if (
        not isinstance(version_text, str)
        or host not in {"127.0.0.1", "::1"}
        or not isinstance(port, int)
        or not 1 <= port <= 65_535
        or state.get("compatibility_version") != GUARD_DAEMON_COMPATIBILITY_VERSION
        or not isinstance(state.get("runtime_fingerprint"), str)
        or not state.get("runtime_fingerprint")
        or not isinstance(pid, int)
        or pid <= 0
        or not isinstance(token, str)
        or not token
    ):
        return None
    try:
        version = Version(version_text)
    except InvalidVersion:
        return None
    url_host = f"[{host}]" if host == "::1" else host
    details = _daemon_healthz_details_payload(f"http://{url_host}:{port}", token)
    if (
        details is None
        or details.get("ok") is not True
        or any(details.get(field) != state.get(field) for field in identity_fields)
    ):
        return None
    try:
        details_guard_home = Path(str(details.get("guard_home"))).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if details_guard_home != guard_home.expanduser().resolve():
        return None
    return version, version_text


def repair_guard_daemon_runtime(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
) -> dict[str, object]:
    """Repair discovery state and replace an authenticated older runtime."""

    trusted_home = (home_dir or Path.home()).expanduser().resolve(strict=True)
    with _guard_daemon_start_lock(guard_home):
        result = repair_approval_center_locator(guard_home)
        state = load_authenticated_daemon_state(guard_home)
        if not isinstance(state, dict):
            return result
        verified_runtime = _verified_live_runtime(guard_home, state)
        try:
            current_version = Version(__version__)
        except InvalidVersion:
            return result
        if verified_runtime is not None and verified_runtime[0] >= current_version:
            daemon_version, daemon_version_text = verified_runtime
            return {
                **result,
                "runtime_status": "current" if daemon_version == current_version else "retained_newer_runtime",
                "daemon_version": daemon_version_text,
                "cli_version": __version__,
            }

        daemon_version_text = state.get("package_version")
        retired = retire_all_guard_daemons_for_home(guard_home)
        if not guard_daemon_retirement_is_complete(guard_home):
            raise RuntimeError("Stale Guard daemon could not be retired safely.")
        clear_guard_daemon_state(guard_home)
    daemon_url = ensure_guard_daemon_after_update(
        guard_home,
        home_dir=trusted_home,
    )
    return {
        **result,
        "runtime_status": "restarted",
        "daemon_version": daemon_version_text if isinstance(daemon_version_text, str) else "unknown",
        "cli_version": __version__,
        "daemon_url": daemon_url,
        "retired": retired,
    }


__all__ = ["repair_guard_daemon_runtime"]
