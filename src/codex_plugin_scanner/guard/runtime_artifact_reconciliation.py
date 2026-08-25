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
from .shim_refresh import refresh_stale_harness_shims
from .shims import package_shim_status, repair_package_shims
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


def _runtime_context(store: GuardStore, *, home_dir: Path | None = None) -> HarnessContext:
    return HarnessContext(
        home_dir=(home_dir or Path.home()).resolve(),
        workspace_dir=None,
        guard_home=store.guard_home.resolve(),
    )


def repair_failing_managed_harness_hooks(
    store: GuardStore,
    *,
    home_dir: Path | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Repair only active managed installs that fail live verification."""

    installs: list[Mapping[str, object]] = list(store.list_managed_installs())
    context = _runtime_context(store, home_dir=home_dir)
    verified = _live_hook_verification(installs, store)
    repaired: list[str] = []
    failed: list[str] = []
    for install in installs:
        harness = install.get("harness")
        if not isinstance(harness, str) or install.get("active") is not True:
            continue
        if verified.get(harness) is True:
            continue
        try:
            apply_managed_install(
                "install",
                harness,
                False,
                context,
                store,
                None,
                datetime.now(timezone.utc).isoformat(),
            )
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError, sqlite3.Error):
            failed.append(harness)
            continue
        refreshed = store.get_managed_install(harness)
        if refreshed is None or _live_hook_verification([refreshed], store).get(harness) is not True:
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

    repaired_managers: tuple[str, ...] = ()
    try:
        shim_status = package_shim_status(context)
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
            verified = package_shim_status(context)
            manager_details = verified.get("manager_details")
            invalid_managers = (
                [
                    str(detail.get("manager"))
                    for detail in manager_details
                    if isinstance(detail, dict)
                    and detail.get("manager") in installed_managers
                    and detail.get("integrity") != "ok"
                ]
                if isinstance(manager_details, list)
                else list(installed_managers)
            )
            errors.extend(f"package:{manager}:integrity" for manager in invalid_managers)
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        errors.append("package:reconciliation_failed")

    return RuntimeArtifactReconciliation(
        refreshed_launchers=launcher_result.refreshed,
        repaired_harnesses=repaired_harnesses,
        repaired_package_managers=repaired_managers,
        failed_harnesses=failed_harnesses,
        errors=tuple(errors),
    )
