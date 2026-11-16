"""Reconcile Guard-managed runtime artifacts when daemon ownership changes."""

from __future__ import annotations

import json
import sqlite3
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from .adapters import get_adapter
from .adapters.base import HarnessContext
from .approvals import _live_hook_verification
from .cli.install_commands import apply_managed_install
from .cursor_hook_rebind import rebind_stale_cursor_hooks
from .shim_refresh import refresh_stale_harness_shims
from .shims import package_shim_dashboard_status, package_shim_status, repair_package_shims
from .store import GuardStore

_LAUNCH_SCAN_TIMEOUT_SECONDS = 10.0
_LAUNCH_SCAN_FEATURE = "native-hook-launch-scan-v2"
_LAUNCH_SCAN_OUTPUT_LIMIT = 64 * 1024
_MANIFEST_SCAN_MAX_PATHS = 16
_REPORT_FEATURE = "native-guard-repair-report-v1"
_REPORT_TIMEOUT_SECONDS = 10.0
_REPORT_OUTPUT_LIMIT = 64 * 1024


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


def _current_durable_runtime_digest() -> str | None:
    """The digest a frozen build's hook commands should pin, or None.

    Only a frozen build writes ``native-runtime/<sha256>`` into hook commands,
    so a source install never repins them.
    """

    if not getattr(sys, "frozen", False):
        return None
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        return None
    return status.identity.sha256


def _planned_artifact_paths(harness: str, context: HarnessContext) -> tuple[Path, ...]:
    """Existing files a fresh install would rewrite that the stored manifest may not name.

    A manifest records what the adapter chose to; ZCode writes the CLI's
    ``setting.json`` beside the Desktop ``config.json`` and names only the
    latter, so a hook pinned to an older runtime there was never read. The
    adapter's own install plan lists everything it publishes. A file the plan
    would leave byte-identical cannot be stale, which also keeps preserved
    backups of the user's earlier config out of the scan. Adapters that write
    without a plan fall back to their manifest alone.
    """

    try:
        plan = get_adapter(harness).prepare_install(context)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        return ()
    paths: list[Path] = []
    for change in plan.files:
        if change.after is None or change.after == change.before:
            continue
        try:
            if change.path.is_file():
                paths.append(change.path)
        except (OSError, ValueError):
            continue
    return tuple(paths[:_MANIFEST_SCAN_MAX_PATHS])


def current_guard_python() -> str | None:
    """The interpreter this process bakes into hook artifacts, or None when frozen.

    A frozen Guard has no Python install of its own, so every launcher that
    runs the Guard package through an interpreter belongs to another install.
    """

    if bool(getattr(sys, "frozen", False)):
        return None
    return str(Path(sys.executable).absolute())


@dataclass(frozen=True, slots=True)
class _ScanEntry:
    harness: str
    install: Mapping[str, object]
    extra_paths: tuple[Path, ...]
    hooks_ready: bool


def _manifest_json(install: Mapping[str, object]) -> str | None:
    manifest = install.get("manifest")
    if not isinstance(manifest, Mapping):
        return None
    try:
        return json.dumps(manifest)
    except (TypeError, ValueError):
        return None


def _scan_installs(
    entries: list[_ScanEntry],
    *,
    current_digest: str | None,
    guard_home: Path,
) -> dict[str, bool]:
    """Which installs need their hooks reinstalled, from one ``hook_launch_scan.rs`` pass.

    The runtime reads every file each install's manifest names, plus the files
    a fresh install would rewrite, and reports an install whose launchers pin
    an older runtime or run another Guard install's Python. A scan that never
    answered is not a clean one: every install then counts as needing repair,
    so a harness reports as failed rather than keeping a stale or foreign
    launcher in place. A runtime that does not offer the scan (none installed
    yet, or an older one mid-upgrade) skips it, since no reinstall could make
    it answer; the installs' own hook checks decide alone.
    """

    if not entries:
        return {}
    from .mdm.runtime_request import runtime_answer, runtime_offers

    answer = runtime_answer(
        _LAUNCH_SCAN_FEATURE,
        "hook-launch-scan",
        {
            "schema": "hook-launch-scan.v2",
            "runtime_digest": current_digest,
            "interpreter": {"current": current_guard_python(), "guard_home": str(guard_home)},
            "installs": [
                {
                    "harness": entry.harness,
                    "manifest_json": _manifest_json(entry.install),
                    "extra_paths": [str(path) for path in entry.extra_paths],
                    "hooks_ready": entry.hooks_ready,
                }
                for entry in entries
            ],
        },
        output_limit=_LAUNCH_SCAN_OUTPUT_LIMIT,
        timeout_seconds=_LAUNCH_SCAN_TIMEOUT_SECONDS,
    )
    installs = answer.get("installs") if answer is not None else None
    if not isinstance(installs, Mapping):
        if answer is None and not runtime_offers(_LAUNCH_SCAN_FEATURE):
            return {entry.harness: not entry.hooks_ready for entry in entries}
        return {entry.harness: True for entry in entries}
    needs: dict[str, bool] = {}
    for entry in entries:
        verdict = installs.get(entry.harness)
        needs[entry.harness] = not isinstance(verdict, Mapping) or verdict.get("needs_repair") is not False
    return needs


def _hooks_ready(harness: str, context: HarnessContext, *, verified: Mapping[str, bool]) -> bool:
    if harness == "grok":
        from .cli.install_commands import grok_hooks_protection_ready

        return grok_hooks_protection_ready(context) is True
    return verified.get(harness) is True


def repair_failing_managed_harness_hooks(
    store: GuardStore,
    *,
    home_dir: Path | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Repair active managed installs whose live hooks or owned artifacts are incomplete."""

    installs: list[Mapping[str, object]] = list(store.list_managed_installs())
    verified = _live_hook_verification(installs, store)
    current_digest = _current_durable_runtime_digest()
    contexts: dict[str, tuple[HarnessContext, str | None]] = {}
    entries: list[_ScanEntry] = []
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
        contexts[harness] = (context, workspace)
        entries.append(
            _ScanEntry(
                harness,
                install,
                _planned_artifact_paths(harness, context),
                _hooks_ready(harness, context, verified=verified),
            )
        )
    guard_home = store.guard_home.resolve()
    needs_repair = _scan_installs(entries, current_digest=current_digest, guard_home=guard_home)
    failed: list[str] = []
    reinstalled: list[_ScanEntry] = []
    for entry in entries:
        if not needs_repair.get(entry.harness, True):
            continue
        context, workspace = contexts[entry.harness]
        try:
            apply_managed_install(
                "install",
                entry.harness,
                False,
                context,
                store,
                workspace,
                datetime.now(timezone.utc).isoformat(),
            )
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError, sqlite3.Error):
            failed.append(entry.harness)
            continue
        refreshed = store.get_managed_install(entry.harness)
        if refreshed is None:
            failed.append(entry.harness)
            continue
        reinstalled.append(replace(entry, install=refreshed))
    refreshed_verified = _live_hook_verification([entry.install for entry in reinstalled], store)
    confirmed = [
        _ScanEntry(
            entry.harness,
            entry.install,
            entry.extra_paths,
            _hooks_ready(entry.harness, contexts[entry.harness][0], verified=refreshed_verified),
        )
        for entry in reinstalled
    ]
    still_needs = _scan_installs(confirmed, current_digest=current_digest, guard_home=guard_home)
    repaired: list[str] = []
    for entry in confirmed:
        if still_needs.get(entry.harness, True):
            failed.append(entry.harness)
        else:
            repaired.append(entry.harness)
    order = [entry.harness for entry in entries]
    return tuple(repaired), tuple(sorted(failed, key=order.index))


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
    installs: list[Mapping[str, object]] = list(store.list_managed_installs())

    launcher_result = refresh_stale_harness_shims(
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        managed_installs=installs,
    )
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
    package = _package_shim_pass(context)
    from .mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _REPORT_FEATURE,
        "guard-repair-report",
        {
            "schema": "guard-repair-report.v1",
            "op": "reconcile",
            "launcher_errors": [str(error) for error in launcher_result.errors],
            "repaired_harnesses": list(repaired_harnesses),
            "failed_harnesses": list(failed_harnesses),
            "cursor_rebind": {
                key: cursor_rebind.get(key)
                for key in ("rebound", "reason", "error")
                if isinstance(cursor_rebind.get(key), (str, bool))
            },
            "package": package,
        },
        output_limit=_REPORT_OUTPUT_LIMIT,
        timeout_seconds=_REPORT_TIMEOUT_SECONDS,
    )
    if answer is None:
        return RuntimeArtifactReconciliation(
            refreshed_launchers=launcher_result.refreshed,
            repaired_harnesses=repaired_harnesses,
            repaired_package_managers=_names(package.get("repaired")),
            failed_harnesses=failed_harnesses,
            errors=(*(f"launcher:{error}" for error in launcher_result.errors), "runtime:reconcile_unanswered"),
        )
    return RuntimeArtifactReconciliation(
        refreshed_launchers=launcher_result.refreshed,
        repaired_harnesses=_names(answer.get("repaired_harnesses")),
        repaired_package_managers=_names(answer.get("repaired_package_managers")),
        failed_harnesses=_names(answer.get("failed_harnesses")),
        errors=_names(answer.get("errors")),
    )


def _names(value: object) -> tuple[str, ...]:
    return tuple(item for item in value if isinstance(item, str)) if isinstance(value, list) else ()


def _package_shim_pass(context: HarnessContext) -> dict[str, object]:
    """Repair the installed package shims and return what each step saw.

    The runtime turns these into the pass's errors; a step that raised still
    reports the manifest state it read first.
    """

    package: dict[str, object] = {}
    try:
        shim_status = _package_shim_reconciliation_status(context)
        installed_values = shim_status.get("installed_managers")
        installed_managers = (
            [manager for manager in installed_values if isinstance(manager, str)]
            if isinstance(installed_values, list)
            else []
        )
        manifest_state = shim_status.get("manifest_state")
        package["initial"] = {
            "manifest_state": manifest_state if isinstance(manifest_state, (str, bool)) else None,
            "installed_managers": installed_managers,
        }
        if installed_managers:
            package_result = repair_package_shims(context, managers=tuple(installed_managers))
            repaired_values = package_result.get("repaired")
            package["repaired"] = (
                [manager for manager in repaired_values if isinstance(manager, str)]
                if isinstance(repaired_values, list)
                else []
            )
            details = _package_shim_reconciliation_status(context).get("manager_details")
            package["verified"] = {
                "manager_details": [
                    {
                        "manager": detail.get("manager"),
                        "integrity": detail.get("integrity"),
                        "path_active": detail.get("path_active"),
                    }
                    for detail in details
                    if isinstance(detail, dict)
                ]
                if isinstance(details, list)
                else None
            }
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        package["failed"] = True
    return package
