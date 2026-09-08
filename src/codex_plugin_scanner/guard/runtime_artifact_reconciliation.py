"""Reconcile Guard-managed runtime artifacts when daemon ownership changes."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .adapters.base import HarnessContext
from .approvals import _live_hook_verification
from .cli.install_commands import apply_managed_install
from .cursor_hook_rebind import rebind_stale_cursor_hooks
from .shim_refresh import refresh_stale_harness_shims
from .shims import package_shim_dashboard_status, package_shim_status, repair_package_shims
from .store import GuardStore


@dataclass(frozen=True, slots=True)
class RuntimeArtifactReconciliation:
    """Result of one bounded reconciliation pass."""

    refreshed_launchers: tuple[str, ...]
    repaired_harnesses: tuple[str, ...]
    repaired_package_managers: tuple[str, ...]
    failed_harnesses: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return bool(self.refreshed_launchers or self.repaired_harnesses or self.repaired_package_managers)

    @property
    def healthy(self) -> bool:
        return not self.failed_harnesses and not self.errors


def _runtime_context(
    store: GuardStore,
    *,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
) -> HarnessContext:
    return HarnessContext(
        home_dir=(home_dir or Path.home()).resolve(),
        workspace_dir=workspace_dir.resolve() if workspace_dir is not None else None,
        guard_home=store.guard_home.resolve(),
        home_override_explicit=home_dir is not None,
        workspace_override_explicit=workspace_dir is not None,
    )


def _package_shim_reconciliation_status(context: HarnessContext) -> dict[str, object]:
    """Use persisted shell activation for daemon health, not the daemon PATH.

    The resident daemon intentionally does not source interactive shell profiles.
    When the Guard shims are intact and their profile blocks are present, a
    restart-required process PATH is expected and must not degrade protection.
    Keep the raw status as the fallback for incomplete or damaged setup.
    """

    status = package_shim_status(context)
    if status.get("path_status") == "restart_required" and status.get("shell_profile_configured") is True:
        return package_shim_dashboard_status(context)
    return status


def _managed_install_needs_artifact_repair(
    harness: str,
    *,
    context: HarnessContext,
    verified: Mapping[str, bool],
) -> bool:
    if harness == "grok":
        from .cli.install_commands import grok_hooks_protection_ready

        return grok_hooks_protection_ready(context) is not True
    return verified.get(harness) is not True


def _managed_install_artifacts_ready(
    harness: str,
    *,
    context: HarnessContext,
    install: Mapping[str, object],
    store: GuardStore,
) -> bool:
    if harness == "grok":
        from .cli.install_commands import grok_hooks_protection_ready

        return grok_hooks_protection_ready(context) is True
    return _live_hook_verification([install], store).get(harness) is True


def repair_failing_managed_harness_hooks(
    store: GuardStore,
    *,
    home_dir: Path | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Repair active managed installs whose live hooks or owned artifacts are incomplete."""

    installs: list[Mapping[str, object]] = list(store.list_managed_installs())
    verified = _live_hook_verification(installs, store)
    repaired: list[str] = []
    failed: list[str] = []
    for install in installs:
        harness = install.get("harness")
        if not isinstance(harness, str) or install.get("active") is not True:
            continue
        stored_workspace = install.get("workspace")
        workspace = stored_workspace if isinstance(stored_workspace, str) and stored_workspace else None
        context = _runtime_context(
            store,
            home_dir=home_dir,
            workspace_dir=Path(workspace).expanduser() if workspace is not None else None,
        )
        if not _managed_install_needs_artifact_repair(harness, context=context, verified=verified):
            continue
        try:
            apply_managed_install(
                "install",
                harness,
                False,
                context,
                store,
                workspace,
                datetime.now(timezone.utc).isoformat(),
            )
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError, sqlite3.Error):
            failed.append(harness)
            continue
        refreshed = store.get_managed_install(harness)
        if refreshed is None or not _managed_install_artifacts_ready(
            harness,
            context=context,
            install=refreshed,
            store=store,
        ):
            failed.append(harness)
            continue
        repaired.append(harness)
    return tuple(repaired), tuple(failed)


def reconcile_runtime_artifacts(
    store: GuardStore,
    *,
    home_dir: Path | None = None,
) -> RuntimeArtifactReconciliation:
    """Bring existing Guard-owned artifacts in line with the active runtime.

    The pass never enrolls a new harness or package manager. It only refreshes
    artifacts already represented by a managed install or package-shim
    manifest, so daemon restarts cannot broaden protection scope.
    """

    context = _runtime_context(store, home_dir=home_dir)
    errors: list[str] = []
    installs: list[Mapping[str, object]] = list(store.list_managed_installs())

    launcher_result = refresh_stale_harness_shims(
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        managed_installs=installs,
    )
    errors.extend(f"launcher:{error}" for error in launcher_result.errors)

    repaired_harnesses, failed_harnesses = repair_failing_managed_harness_hooks(
        store,
        home_dir=context.home_dir,
    )
    try:
        cursor_rebind = rebind_stale_cursor_hooks(store.guard_home, home_dir=context.home_dir)
    except (OSError, RuntimeError, UnicodeError) as error:
        cursor_rebind = {
            "rebound": False,
            "reason": "cursor_hook_script_rebind_failed",
            "error": str(error),
        }
    if cursor_rebind.get("rebound") is True and "cursor" not in repaired_harnesses:
        repaired_harnesses = (*repaired_harnesses, "cursor")
    if cursor_rebind.get("reason") in {
        "cursor_hook_script_rebind_failed",
        "cursor_hook_script_unreadable",
    }:
        error_text = cursor_rebind.get("error")
        errors.append(f"cursor:rebind:{error_text if isinstance(error_text, str) else 'failed'}")

    repaired_managers: tuple[str, ...] = ()
    try:
        shim_status = _package_shim_reconciliation_status(context)
        manifest_state = shim_status.get("manifest_state")
        if manifest_state not in (None, "absent", "valid"):
            errors.append(f"package:manifest:{manifest_state}")
        installed_values = shim_status.get("installed_managers")
        installed_managers = (
            tuple(str(manager) for manager in installed_values if isinstance(manager, str))
            if isinstance(installed_values, list)
            else ()
        )
        if installed_managers:
            package_result = repair_package_shims(context, managers=installed_managers)
            repaired_values = package_result.get("repaired")
            repaired_managers = (
                tuple(str(manager) for manager in repaired_values if isinstance(manager, str))
                if isinstance(repaired_values, list)
                else ()
            )
            verified = _package_shim_reconciliation_status(context)
            manager_details = verified.get("manager_details")
            if isinstance(manager_details, list):
                for detail in manager_details:
                    if not isinstance(detail, dict) or detail.get("manager") not in installed_managers:
                        continue
                    manager = str(detail.get("manager"))
                    if detail.get("integrity") != "ok":
                        errors.append(f"package:{manager}:integrity")
                    if detail.get("path_active") is not True:
                        errors.append(f"package:{manager}:path_inactive")
            else:
                errors.extend(f"package:{manager}:status_missing" for manager in installed_managers)
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        errors.append("package:reconciliation_failed")

    return RuntimeArtifactReconciliation(
        refreshed_launchers=launcher_result.refreshed,
        repaired_harnesses=repaired_harnesses,
        repaired_package_managers=repaired_managers,
        failed_harnesses=failed_harnesses,
        errors=tuple(errors),
    )
