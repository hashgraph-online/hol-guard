"""User-initiated repair for stale local daemon runtimes."""

from __future__ import annotations

import time
from contextlib import ExitStack
from pathlib import Path

from packaging.version import InvalidVersion, Version

from ...version import __version__
from ..cursor_hook_ops import rebind_stale_cursor_hooks
from ..native_daemon_manage import (
    GuardDaemonStartLockTimeoutError,
    _guard_daemon_state_matches_current_runtime,
    clear_guard_daemon_state,
    ensure_guard_daemon_after_update,
    guard_daemon_retirement_is_complete,
    record_daemon_repair,
    repair_approval_center_locator,
    retire_all_guard_daemons_for_home,
)
from ..native_daemon_manage import guard_daemon_start_lock as _guard_daemon_start_lock
from ..native_daemon_peer import verified_live_guard_daemon_identity

# A start or another repair holds the lock for as long as a daemon takes to
# come up, which a migration can stretch to most of a minute. Waiting past
# that never helps: the holder is wedged, and the caller needs to know.
REPAIR_LOCK_TIMEOUT_SECONDS = 90.0


class DaemonRepairBusyError(RuntimeError):
    """Another process held the daemon start lock for the whole repair wait.

    ``reason_code`` and ``recovery`` are what ``hol-guard daemon repair`` prints
    so the caller sees a bounded, actionable state instead of a hung command.
    """

    reason_code = "daemon_repair_busy"

    def __init__(self, waited_seconds: float) -> None:
        self.waited_seconds = round(waited_seconds, 1)
        self.recovery = (
            "Another Guard process is starting or repairing the daemon. Run `hol-guard daemon status` "
            "to see whether it came up, wait for that process to finish, then run `hol-guard daemon repair` "
            "again. Existing approvals, audit records, policies and credentials are untouched."
        )
        super().__init__(f"Guard daemon repair waited {self.waited_seconds}s for the daemon start lock.")


def _verified_live_runtime(
    identity: dict[str, object],
) -> tuple[Version, str, str] | None:
    version_text = identity.get("package_version")
    runtime_fingerprint = identity.get("runtime_fingerprint")
    if not isinstance(version_text, str) or not isinstance(runtime_fingerprint, str):
        return None
    try:
        version = Version(version_text)
    except InvalidVersion:
        return None
    return version, version_text, runtime_fingerprint


def _retained_runtime_status(daemon_version: Version, current_version: Version) -> str:
    if daemon_version == current_version:
        return "current"
    if daemon_version > current_version:
        return "retained_newer_runtime"
    return "retained_desktop_runtime"


def _rebind_cursor_hooks_best_effort(guard_home: Path, *, home_dir: Path) -> dict[str, object]:
    try:
        return rebind_stale_cursor_hooks(guard_home, home_dir=home_dir)
    except (OSError, RuntimeError, UnicodeError) as error:
        return {
            "rebound": False,
            "reason": "cursor_hook_script_rebind_failed",
            "error": str(error),
        }


def _keep_live_runtime_result(
    result: dict[str, object],
    *,
    identity: dict[str, object] | None,
    verified_runtime: tuple[Version, str, str] | None,
    current_version: Version,
) -> dict[str, object] | None:
    if verified_runtime is None or identity is None:
        return None
    if not _guard_daemon_state_matches_current_runtime(identity, current_version=str(current_version)):
        return None
    daemon_version, daemon_version_text, _ = verified_runtime
    return {
        **result,
        "runtime_status": _retained_runtime_status(daemon_version, current_version),
        "daemon_version": daemon_version_text,
        "cli_version": __version__,
    }


def repair_guard_daemon_runtime(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
    lock_timeout_seconds: float | None = REPAIR_LOCK_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Repair discovery state and replace an authenticated older runtime.

    Raises ``DaemonRepairBusyError`` when another process keeps the daemon
    start lock for ``lock_timeout_seconds``; ``None`` waits without a limit.
    """

    trusted_home = (home_dir or Path.home()).expanduser().resolve(strict=True)
    if not trusted_home.is_dir():
        raise RuntimeError("Guard daemon requires a user home directory.")
    record_daemon_repair(guard_home)
    started = time.monotonic()
    deadline = None if lock_timeout_seconds is None else started + max(lock_timeout_seconds, 0.0)
    with ExitStack() as held:
        try:
            held.enter_context(_guard_daemon_start_lock(guard_home, deadline=deadline))
        except GuardDaemonStartLockTimeoutError as error:
            raise DaemonRepairBusyError(time.monotonic() - started) from error
        result = repair_approval_center_locator(guard_home)
        identity = verified_live_guard_daemon_identity(guard_home)
        verified_runtime = _verified_live_runtime(identity) if identity is not None else None
        try:
            current_version = Version(__version__)
        except InvalidVersion as error:
            raise RuntimeError("Installed Guard package version is invalid.") from error
        kept = _keep_live_runtime_result(
            result,
            identity=identity,
            verified_runtime=verified_runtime,
            current_version=current_version,
        )
        if kept is not None:
            cursor_rebind = _rebind_cursor_hooks_best_effort(guard_home, home_dir=trusted_home)
            return {**kept, "cursor_hook_rebind": cursor_rebind.get("reason")}

        daemon_version_text = identity.get("package_version") if identity is not None else None
        retired = retire_all_guard_daemons_for_home(guard_home)
        if not guard_daemon_retirement_is_complete(guard_home):
            raise RuntimeError("Stale Guard daemon could not be retired safely.")
        clear_guard_daemon_state(guard_home)
        daemon_url = ensure_guard_daemon_after_update(
            guard_home,
            home_dir=trusted_home,
        )
        cursor_rebind = _rebind_cursor_hooks_best_effort(guard_home, home_dir=trusted_home)
    return {
        **result,
        "runtime_status": "restarted",
        "daemon_version": daemon_version_text if isinstance(daemon_version_text, str) else "unknown",
        "cli_version": __version__,
        "daemon_url": daemon_url,
        "retired": retired,
        "cursor_hook_rebind": cursor_rebind.get("reason"),
    }


__all__ = ["REPAIR_LOCK_TIMEOUT_SECONDS", "DaemonRepairBusyError", "repair_guard_daemon_runtime"]
