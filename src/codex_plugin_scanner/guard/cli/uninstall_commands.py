"""Helpers for removing the installed HOL Guard CLI and local Guard state."""

from __future__ import annotations

import shutil
import subprocess
import sys

from ..adapters.base import HarnessContext
from ..codex_install_transaction import codex_install_transaction
from ..daemon.manager import retire_all_guard_daemons_for_home
from ..native_resident_update_lock import NativeResidentUpdateLockError, hold_native_resident_update_lock
from ..redaction import redact_sensitive_text
from ..shims import package_shim_status, remove_guard_profile_blocks, uninstall_package_shims
from ..store import GuardStore
from .install_commands import apply_managed_install
from .managed_install_context import managed_install_context as _managed_install_context
from .update_commands import _current_version, _installer_kind
from .update_retirement import _resident_state_absent, resident_stop_executable, retire_native_resident_for_home


def run_guard_self_uninstall(
    *,
    dry_run: bool,
    context: HarnessContext,
    store: GuardStore,
    now: str,
) -> tuple[dict[str, object], int]:
    current_version = _current_version()
    installer = _installer_kind()
    frozen_package_skip = _frozen_package_uninstall_unsupported()
    # A frozen desktop core is not a pip/uv/pipx package; never plan or run one.
    command = [] if frozen_package_skip else _uninstall_command(installer)
    managed_installs, managed_install_error = _active_managed_installs(store)
    notes: list[str] = []
    if managed_install_error is not None:
        notes.append(managed_install_error)
    try:
        shim_status = package_shim_status(context)
        planned_managers = _string_items(shim_status.get("installed_managers"))
    except (OSError, RuntimeError, ValueError) as error:
        planned_managers = []
        notes.append(f"Could not read package shim state before uninstall: {error}")
    payload: dict[str, object] = {
        "self_uninstall": True,
        "status": "planned" if dry_run else "pending",
        "current_version": current_version,
        "installer": installer,
        "dry_run": dry_run,
        "command": command,
        "package_uninstall_skipped": frozen_package_skip,
        "guard_home": str(context.guard_home),
        "planned_managed_harnesses": [str(item.get("harness") or "unknown") for item in managed_installs],
        "planned_package_shim_managers": planned_managers,
    }
    if notes:
        payload["notes"] = [_clean_output(note) for note in notes]
    if dry_run:
        payload["changed"] = False
        payload["message"] = _planned_uninstall_message(
            managed_count=len(managed_installs),
            package_shim_count=len(planned_managers),
            package_uninstall_skipped=frozen_package_skip,
        )
        return payload, 0

    removed_managed_installs: list[dict[str, object]] = []
    package_shim_uninstall: dict[str, object] | None = None
    daemon_cleanup: dict[str, object] | None = None
    profile_cleanup: dict[str, object] | None = None

    try:
        retired_pids = retire_all_guard_daemons_for_home(context.guard_home)
        daemon_cleanup = {"retired_pids": retired_pids, "retired_count": len(retired_pids)}
    except (OSError, RuntimeError) as error:
        daemon_cleanup = {"retired_pids": [], "retired_count": 0, "error": _clean_output(str(error))}
        notes.append(f"Could not stop every Guard daemon before uninstall: {error}")

    # The native resident is its own long-lived process, so retiring the Python
    # daemons leaves it running. It also holds the runtime executable open,
    # which on Windows keeps that file from being removed at all. The update
    # barrier has to stay held until the harness hooks are gone: a hook that
    # fires after the stop and before those hooks are removed starts the
    # resident again, and it then outlives the uninstall.
    barrier_held = False
    try:
        with hold_native_resident_update_lock(
            context.guard_home,
            initial_executable=resident_stop_executable(),
        ):
            barrier_held = True
            native_resident_retired = retire_native_resident_for_home(context.guard_home)
            daemon_cleanup["native_resident_retired"] = native_resident_retired
            if not native_resident_retired:
                notes.append(
                    "Could not stop the Guard native runtime before uninstall; "
                    "it may keep running until the machine restarts."
                )
            _removed_managed, managed_failure = _disconnect_managed_installs(
                managed_installs,
                context=context,
                store=store,
                now=now,
            )
            removed_managed_installs.extend(_removed_managed)
            if managed_failure is not None:
                harness, error = managed_failure
                payload.update(
                    {
                        "status": "failed",
                        "changed": bool(removed_managed_installs),
                        "managed_installs": removed_managed_installs,
                        "daemon_cleanup": daemon_cleanup,
                        "message": _stopped_message(
                            failed=f"harness {harness or 'unknown'}",
                            removed=[str(item.get("harness") or "unknown") for item in removed_managed_installs],
                        ),
                        "failed_harness": harness or "unknown",
                        "error": _clean_output(str(error)),
                        "notes": [_clean_output(note) for note in notes],
                    }
                )
                return payload, 1
    except NativeResidentUpdateLockError:
        if barrier_held:
            raise
        notes.append("Could not hold the native runtime update barrier, so uninstall stopped before removing hooks.")
        daemon_cleanup["native_resident_retired"] = False
        payload.update(
            {
                "status": "failed",
                "changed": False,
                "managed_installs": [],
                "daemon_cleanup": daemon_cleanup,
                "message": "HOL Guard removal stopped before disconnecting harnesses.",
                "notes": [_clean_output(note) for note in notes],
            }
        )
        return payload, 1

    try:
        package_shim_uninstall = uninstall_package_shims(context, managers=tuple(planned_managers) or None)
    except (OSError, RuntimeError, ValueError) as error:
        payload.update(
            {
                "status": "failed",
                "changed": bool(removed_managed_installs),
                "managed_installs": removed_managed_installs,
                "daemon_cleanup": daemon_cleanup,
                "message": _stopped_message(
                    failed="package-manager shims",
                    removed=[str(item.get("harness") or "unknown") for item in removed_managed_installs],
                ),
                "error": _clean_output(str(error)),
                "notes": [_clean_output(note) for note in notes],
            }
        )
        return payload, 1

    try:
        profile_cleanup = remove_guard_profile_blocks(context)
    except (OSError, RuntimeError) as error:
        profile_cleanup = {"changed": False, "error": _clean_output(str(error))}
        notes.append(f"Could not remove Guard PATH entries from shell profiles: {error}")

    if frozen_package_skip:
        notes.append(_FROZEN_PACKAGE_NOTE)
        oauth_error = _clear_oauth_credentials(store)
        if oauth_error is not None:
            notes.append(oauth_error)
        payload.update(
            {
                "status": "removed" if oauth_error is None else "failed",
                "oauth_credentials_cleared": oauth_error is None,
                "managed_installs": removed_managed_installs,
                "package_shim_uninstall": package_shim_uninstall,
                "daemon_cleanup": daemon_cleanup,
                "profile_cleanup": profile_cleanup,
                "package_removed": False,
                "guard_home_removed": False,
                "changed": _self_uninstall_changed(
                    removed_managed_installs=removed_managed_installs,
                    package_shim_uninstall=package_shim_uninstall,
                    profile_cleanup=profile_cleanup,
                    package_removed=False,
                ),
                "message": (
                    "Removed Guard protection from this environment; the Guard desktop core was kept."
                    if oauth_error is None
                    else "Removed Guard protection, but Guard Cloud credentials could not be cleared."
                ),
                "notes": [_clean_output(note) for note in notes],
            }
        )
        return payload, 0 if oauth_error is None else 1

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as error:
        payload.update(
            {
                "status": "failed",
                "changed": _self_uninstall_changed(
                    removed_managed_installs=removed_managed_installs,
                    package_shim_uninstall=package_shim_uninstall,
                    profile_cleanup=profile_cleanup,
                    package_removed=False,
                ),
                "managed_installs": removed_managed_installs,
                "package_shim_uninstall": package_shim_uninstall,
                "daemon_cleanup": daemon_cleanup,
                "profile_cleanup": profile_cleanup,
                "package_removed": False,
                "message": "HOL Guard package uninstall failed before the installer started.",
                "error": _clean_output(str(error)),
                "notes": [_clean_output(note) for note in notes],
            }
        )
        return payload, 1

    payload["stdout"] = _clean_output(result.stdout)
    payload["stderr"] = _clean_output(result.stderr)
    payload["return_code"] = result.returncode
    payload["managed_installs"] = removed_managed_installs
    payload["package_shim_uninstall"] = package_shim_uninstall
    payload["daemon_cleanup"] = daemon_cleanup
    payload["profile_cleanup"] = profile_cleanup
    payload["package_removed"] = result.returncode == 0

    if result.returncode != 0:
        payload["status"] = "failed"
        payload["changed"] = _self_uninstall_changed(
            removed_managed_installs=removed_managed_installs,
            package_shim_uninstall=package_shim_uninstall,
            profile_cleanup=profile_cleanup,
            package_removed=False,
        )
        payload["message"] = "HOL Guard package uninstall failed after local protection cleanup."
        if notes:
            payload["notes"] = [_clean_output(note) for note in notes]
        return payload, 1

    cleanup_errors: list[str] = []
    oauth_error = _clear_oauth_credentials(store)
    oauth_cleared = oauth_error is None
    if oauth_error is not None:
        cleanup_errors.append(oauth_error)

    guard_home_removed = False
    if context.guard_home.exists():
        try:
            shutil.rmtree(context.guard_home)
            guard_home_removed = True
        except OSError as error:
            cleanup_errors.append(f"Could not remove Guard home {context.guard_home}: {error}")
    else:
        guard_home_removed = True

    payload["oauth_credentials_cleared"] = oauth_cleared
    payload["guard_home_removed"] = guard_home_removed
    payload["changed"] = _self_uninstall_changed(
        removed_managed_installs=removed_managed_installs,
        package_shim_uninstall=package_shim_uninstall,
        profile_cleanup=profile_cleanup,
        package_removed=True,
    )
    if cleanup_errors:
        payload["status"] = "failed"
        payload["message"] = "HOL Guard package was removed, but local cleanup needs attention."
        notes.extend(cleanup_errors)
        payload["notes"] = [_clean_output(note) for note in notes]
        return payload, 1

    payload["status"] = "removed"
    payload["message"] = _success_uninstall_message(
        managed_count=len(removed_managed_installs),
        package_shim_count=len(_string_items(package_shim_uninstall.get("removed_managers"))),
    )
    if notes:
        payload["notes"] = [_clean_output(note) for note in notes]
    return payload, 0


_FROZEN_PACKAGE_NOTE = (
    "Skipped the pip uninstall step because this Guard is a self-contained desktop binary, not a pip package. "
    "Remove the app with the Guard desktop uninstaller; ~/.hol-guard was kept because it holds the running core."
)


def _disconnect_managed_installs(
    managed_installs: list[dict[str, object]],
    *,
    context: HarnessContext,
    store: GuardStore,
    now: str,
) -> tuple[list[dict[str, object]], tuple[str, str] | None]:
    """Remove harness hooks while the caller still holds the update barrier."""

    removed: list[dict[str, object]] = []
    for managed_install in managed_installs:
        harness = str(managed_install.get("harness") or "").strip()
        try:
            uninstall_context, uninstall_workspace = _managed_install_context(context, managed_install)
            uninstall_payload = apply_managed_install(
                "uninstall",
                harness,
                False,
                uninstall_context,
                store,
                uninstall_workspace,
                now,
            )
        except (OSError, RuntimeError, ValueError) as error:
            return removed, (harness, str(error))
        record = uninstall_payload.get("managed_install")
        if isinstance(record, dict):
            removed.append(record)
    return removed, None


def retire_native_resident_after_last_harness(context: HarnessContext, store: GuardStore) -> bool | None:
    """Stop the native resident once a harness uninstall leaves none managed.

    The resident only serves harness hooks, so with every harness disconnected
    nothing will ask for it again, yet it would linger until its idle timeout.
    On Windows it also keeps the runtime executable open. Returns ``None`` when
    a harness is still managed (or the state cannot be read) or no resident
    state exists, otherwise whether it stopped.
    """

    if _resident_kept(context, store):
        return None
    try:
        # Same order as self-uninstall: the update barrier, then the install
        # transaction. Holding both, an install cannot activate a harness
        # between the last check and the stop.
        with (
            hold_native_resident_update_lock(
                context.guard_home,
                initial_executable=resident_stop_executable(),
            ),
            codex_install_transaction(
                context.guard_home, context.guard_home / "managed", actor="managed.retire_resident"
            ),
        ):
            if _resident_kept(context, store):
                return None
            return retire_native_resident_for_home(context.guard_home)
    except (NativeResidentUpdateLockError, OSError, RuntimeError, TimeoutError):
        return False


def _resident_kept(context: HarnessContext, store: GuardStore) -> bool:
    installs, error = _active_managed_installs(store)
    if installs or error is not None:
        return True
    try:
        return _resident_state_absent(context.guard_home)
    except (OSError, RuntimeError):
        return True


def _frozen_package_uninstall_unsupported() -> bool:
    return bool(getattr(sys, "frozen", False))


def _clear_oauth_credentials(store: GuardStore) -> str | None:
    try:
        store.clear_oauth_local_credentials()
    except (OSError, RuntimeError) as error:
        return f"Could not clear Guard Cloud credentials: {error}"
    return None


def _stopped_message(*, failed: str, removed: list[str]) -> str:
    done = f" Already removed: {', '.join(removed)}." if removed else " Nothing had been removed yet."
    return f"HOL Guard removal stopped at {failed} before the package uninstall command ran.{done}"


def _uninstall_command(installer: str) -> list[str]:
    if installer == "uv":
        return ["uv", "tool", "uninstall", "hol-guard"]
    if installer == "pipx":
        return ["pipx", "uninstall", "hol-guard"]
    return [sys.executable, "-m", "pip", "uninstall", "-y", "hol-guard"]


def _active_managed_installs(store: GuardStore) -> tuple[list[dict[str, object]], str | None]:
    try:
        installs = [item for item in store.list_managed_installs() if bool(item.get("active"))]
    except Exception as error:  # pragma: no cover - defensive path depends on local store failures.
        return [], f"Could not read managed install state before uninstall: {error}"
    return installs, None


def _planned_uninstall_message(
    *, managed_count: int, package_shim_count: int, package_uninstall_skipped: bool = False
) -> str:
    actions: list[str] = [] if package_uninstall_skipped else ["remove the installed hol-guard package"]
    if managed_count:
        actions.append(f"disconnect {managed_count} Guard-managed harness{'es' if managed_count != 1 else ''}")
    if package_shim_count:
        actions.append(f"remove {package_shim_count} package-manager shim{'s' if package_shim_count != 1 else ''}")
    if package_uninstall_skipped:
        actions.append("remove Guard protection from this environment and keep the Guard desktop core")
    return f"Review the planned steps to {' and '.join(actions)}."


def _success_uninstall_message(*, managed_count: int, package_shim_count: int) -> str:
    parts = ["Removed HOL Guard from this environment"]
    if managed_count:
        parts.append(f"disconnected {managed_count} managed harness{'es' if managed_count != 1 else ''}")
    if package_shim_count:
        parts.append(f"removed {package_shim_count} package-manager shim{'s' if package_shim_count != 1 else ''}")
    return "; ".join(parts) + "."


def _self_uninstall_changed(
    *,
    removed_managed_installs: list[dict[str, object]],
    package_shim_uninstall: dict[str, object] | None,
    profile_cleanup: dict[str, object] | None,
    package_removed: bool,
) -> bool:
    removed_managers = _string_items(package_shim_uninstall.get("removed_managers")) if package_shim_uninstall else []
    profile_changed = bool(profile_cleanup and profile_cleanup.get("changed"))
    return bool(removed_managed_installs or removed_managers or profile_changed or package_removed)


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str) and item.strip()] if isinstance(value, list) else []


def _clean_output(value: str) -> str:
    return redact_sensitive_text(value.strip())


__all__ = ["run_guard_self_uninstall"]
