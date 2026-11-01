"""Reconcile Guard-managed runtime artifacts when daemon ownership changes."""

from __future__ import annotations

import json
import sqlite3
import sys
from collections.abc import Mapping
from dataclasses import dataclass
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
_MANIFEST_SCAN_MAX_PATHS = 16
_MANIFEST_SCAN_MAX_NODES = 512


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


def _manifest_file_paths(manifest: object) -> tuple[Path, ...]:
    """Every existing file an install manifest names, bounded.

    Harnesses record their artifacts under their own keys: Cursor keeps a list
    of written files, OpenCode names ``managed_config_path`` and Hermes points
    ``config_path`` at its YAML while its hook lives in ``pretool_hook_path``.
    Reading every string the manifest holds covers all of them without a
    per-harness table that would silently miss the next adapter. Paths come
    back in manifest order, so the bound drops the last artifacts, never the
    hook launchers an adapter lists first.
    """

    found: list[Path] = []
    seen: set[str] = set()
    pending: list[object] = [manifest]
    nodes = 0
    while pending and len(found) < _MANIFEST_SCAN_MAX_PATHS and nodes < _MANIFEST_SCAN_MAX_NODES:
        node = pending.pop()
        nodes += 1
        if isinstance(node, Mapping):
            pending.extend(reversed(list(node.values())))
            continue
        if isinstance(node, (list, tuple)):
            pending.extend(reversed(node))
            continue
        if not isinstance(node, str) or not node or node in seen:
            continue
        seen.add(node)
        try:
            candidate = Path(node)
            if not candidate.is_absolute() or not candidate.is_file():
                continue
        except (OSError, ValueError):
            # A persisted path can hold an embedded NUL or an unreadable
            # mount; that is this harness's problem, not the whole pass's.
            continue
        found.append(candidate)
    return tuple(found)


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


def _scanned_paths(install: Mapping[str, object], extra_paths: tuple[Path, ...]) -> tuple[Path, ...]:
    manifest = install.get("manifest")
    named = _manifest_file_paths(manifest) if isinstance(manifest, Mapping) else ()
    return (*named, *(path for path in extra_paths if path not in named))


def current_guard_python() -> str | None:
    """The interpreter this process bakes into hook artifacts, or None when frozen.

    A frozen Guard has no Python install of its own, so every launcher that
    runs the Guard package through an interpreter belongs to another install.
    """

    if bool(getattr(sys, "frozen", False)):
        return None
    return str(Path(sys.executable).absolute())


def _scan_launchers(
    paths: tuple[Path, ...],
    *,
    current_digest: str | None,
    guard_home: Path | None,
) -> Mapping[str, object]:
    """``hook_launch_scan.rs`` over the install's artifacts; empty without a runtime."""

    if not paths or (current_digest is None and guard_home is None):
        return {}
    from .mdm.runtime_request import runtime_answer

    interpreter = None if guard_home is None else {"current": current_guard_python(), "guard_home": str(guard_home)}
    answer = runtime_answer(
        "native-hook-launch-scan-v1",
        "hook-launch-scan",
        {
            "schema": "hook-launch-scan.v1",
            "paths": [str(path) for path in paths],
            "runtime_digest": current_digest,
            "interpreter": interpreter,
        },
        output_limit=4 * 1024,
        timeout_seconds=_LAUNCH_SCAN_TIMEOUT_SECONDS,
    )
    return answer or {}


def _pins_stale_native_runtime(
    install: Mapping[str, object],
    current_digest: str | None,
    extra_paths: tuple[Path, ...] = (),
) -> bool:
    """Whether the install's harness artifacts still launch an older runtime.

    The resident refuses a hook bridge whose runtime digest differs from its
    own, so a stale pin silently sends every hook to the slower Python path.
    """

    scan = _scan_launchers(_scanned_paths(install, extra_paths), current_digest=current_digest, guard_home=None)
    return scan.get("stale_runtime") is True


def _launches_stale_client(
    harness: str,
    install: Mapping[str, object],
    context: HarnessContext,
    current_digest: str | None,
) -> bool:
    """Whether the install's hook artifacts pin an older runtime or run another Guard install's Python.

    The install-time file proof only hashes what it recorded, and the runtime
    pin only knows a frozen build's own copy. A launcher left by a different
    Guard install keeps both of them satisfied while every hook reaches a
    client the resident no longer serves.
    """

    paths = _scanned_paths(install, _planned_artifact_paths(harness, context))
    scan = _scan_launchers(paths, current_digest=current_digest, guard_home=context.guard_home)
    return scan.get("stale_runtime") is True or scan.get("foreign_interpreter") is True


def _managed_install_needs_artifact_repair(
    harness: str,
    *,
    context: HarnessContext,
    verified: Mapping[str, bool],
    install: Mapping[str, object],
    current_digest: str | None,
) -> bool:
    if _launches_stale_client(harness, install, context, current_digest):
        return True
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
    current_digest: str | None,
) -> bool:
    if _launches_stale_client(harness, install, context, current_digest):
        return False
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
    current_digest = _current_durable_runtime_digest()
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
        if not _managed_install_needs_artifact_repair(
            harness,
            context=context,
            verified=verified,
            install=install,
            current_digest=current_digest,
        ):
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
            current_digest=current_digest,
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
