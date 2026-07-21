"""Helpers for removing the installed HOL Guard CLI and local Guard state."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from ..adapters.base import HarnessContext
from ..daemon.manager import retire_all_guard_daemons_for_home
from ..redaction import redact_sensitive_text
from ..shims import package_shim_status, remove_guard_profile_blocks, uninstall_package_shims
from ..store import GuardStore
from .install_commands import apply_managed_install
from .update_commands import _current_version, _installer_kind


def run_guard_self_uninstall(
    *,
    dry_run: bool,
    context: HarnessContext,
    store: GuardStore,
    now: str,
) -> tuple[dict[str, object], int]:
    current_version = _current_version()
    installer = _installer_kind()
    command = _uninstall_command(installer)
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
            payload.update(
                {
                    "status": "failed",
                    "changed": bool(removed_managed_installs),
                    "managed_installs": removed_managed_installs,
                    "daemon_cleanup": daemon_cleanup,
                    "message": "HOL Guard removal stopped before the package uninstall command ran.",
                    "error": _clean_output(str(error)),
                    "notes": [_clean_output(note) for note in notes],
                }
            )
            return payload, 1
        removed = uninstall_payload.get("managed_install")
        if isinstance(removed, dict):
            removed_managed_installs.append(removed)

    try:
        package_shim_uninstall = uninstall_package_shims(context, managers=tuple(planned_managers) or None)
    except (OSError, RuntimeError, ValueError) as error:
        payload.update(
            {
                "status": "failed",
                "changed": bool(removed_managed_installs),
                "managed_installs": removed_managed_installs,
                "daemon_cleanup": daemon_cleanup,
                "message": "HOL Guard removal stopped before the package uninstall command ran.",
                "error": _clean_output(str(error)),
                "notes": [_clean_output(note) for note in notes],
            }
        )
        return payload, 1

    try:
        profile_cleanup = remove_guard_profile_blocks(context)
    except OSError as error:
        profile_cleanup = {"changed": False, "error": _clean_output(str(error))}
        notes.append(f"Could not remove Guard PATH entries from shell profiles: {error}")

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

    oauth_cleared = False
    cleanup_errors: list[str] = []
    try:
        store.clear_oauth_local_credentials()
        oauth_cleared = True
    except (OSError, RuntimeError) as error:
        cleanup_errors.append(f"Could not clear Guard Cloud credentials: {error}")

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


def _managed_install_context(
    context: HarnessContext,
    managed_install: dict[str, object],
) -> tuple[HarnessContext, str | None]:
    managed_workspace = managed_install.get("workspace")
    if isinstance(managed_workspace, str) and managed_workspace.strip():
        workspace_path = Path(managed_workspace).expanduser().resolve()
        return (
            HarnessContext(
                home_dir=context.home_dir,
                workspace_dir=workspace_path,
                guard_home=context.guard_home,
                home_override_explicit=context.home_override_explicit,
            ),
            str(workspace_path),
        )
    return (
        HarnessContext(
            home_dir=context.home_dir,
            workspace_dir=None,
            guard_home=context.guard_home,
            home_override_explicit=context.home_override_explicit,
        ),
        None,
    )


def _planned_uninstall_message(*, managed_count: int, package_shim_count: int) -> str:
    actions: list[str] = ["remove the installed hol-guard package"]
    if managed_count:
        actions.append(f"disconnect {managed_count} Guard-managed harness{'es' if managed_count != 1 else ''}")
    if package_shim_count:
        actions.append(f"remove {package_shim_count} package-manager shim{'s' if package_shim_count != 1 else ''}")
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
