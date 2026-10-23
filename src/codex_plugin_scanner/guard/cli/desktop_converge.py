"""Converge every HOL Guard install on the Desktop-managed Core.

An update through Desktop must leave one Guard behind: hooks, daemon and the
``hol-guard`` a shell finds all run the Core Desktop just activated. Older
pipx, uv tool or ``pip --user`` copies and their bin links are removed, and the
user PATH wrapper Desktop writes is restored when nothing else provides it.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from ..adapters.base import HarnessContext
from ..desktop_foreign_installs import (
    DESKTOP_PATH_SHIM_MARKER,
    ForeignInventory,
    inventory_foreign_installs,
    remove_foreign_installs,
)
from ..stable_guard_cli import durable_desktop_current_hol_guard
from ..store import GuardStore

_SHIM_TEMP_NAME = "hol-guard.desktop-shim.tmp"
_CORE_ONLY_MESSAGE = "Run hol-guard desktop converge from the HOL Guard Desktop Core."
_DEFERRED_NOTE = (
    "Kept the other HOL Guard installs because harness hook repair reported a problem. "
    "Fix it, then run hol-guard desktop converge."
)
# Every harness repair failure note starts with this; success notes do not.
_REPAIR_FAILURE_MARKER = "Could not "


def converge_on_desktop_core(
    context: HarnessContext,
    *,
    dry_run: bool = False,
    path_env: str | None = None,
    retire_runtime: Callable[[Path], bool] | None = None,
    retire_daemons: Callable[[], object] | None = None,
    refresh_package_shims: Callable[[], str | None] | None = None,
) -> dict[str, object]:
    """Remove superseded installs and point the user PATH at Desktop's launcher."""

    launcher = durable_desktop_current_hol_guard(context.home_dir)
    if launcher is None:
        return {
            "status": "skipped",
            "reason_code": "desktop_core_launcher_missing",
            "message": "Desktop has not activated a Core yet, so other installs were left in place.",
        }
    # A preview from a pip or uv install lists that install too: the Desktop
    # Core run removes it. Real removal never touches the running install.
    inventory = inventory_foreign_installs(context.home_dir, path_env=path_env, protect_running=not dry_run)
    payload: dict[str, object] = {"launcher": str(launcher), "found": _describe(inventory)}
    if dry_run:
        payload["status"] = "planned"
        return payload
    if not inventory.empty:
        try:
            _ = (retire_daemons or (lambda: _retire_daemons(context.guard_home)))()
        except (OSError, RuntimeError) as error:
            payload.update(
                {
                    "status": "partial",
                    "removed": [],
                    "daemon_restart_required": False,
                    "notes": [f"Kept the other HOL Guard installs: could not stop the Guard daemon: {error}"],
                }
            )
            return payload
    result = remove_foreign_installs(
        inventory,
        retire_runtime=retire_runtime or _resident_retirer(context.guard_home),
    )
    notes = list(result.notes)
    if result.removed:
        # Package-manager shims bake the interpreter that wrote them, which may
        # be the install just removed. Rewriting them here binds them to Core.
        package_note = (refresh_package_shims or (lambda: _refresh_package_shims(context)))()
        notes.extend([package_note] if package_note else [])
    shim = _ensure_user_path_shim(context.home_dir, launcher, result.removed_entry_dirs)
    if shim.get("status") == "failed":
        notes.append(f"Could not write the Desktop hol-guard wrapper at {shim.get('path')}: {shim.get('error')}.")
    resolved = shutil.which("hol-guard", path=path_env)
    on_desktop = resolved is not None and _resolves_to_launcher(Path(resolved), launcher)
    if resolved is not None and not on_desktop:
        notes.append(f"hol-guard on PATH still runs {resolved}. Remove it so the shell uses the Desktop Core.")
    payload.update(
        {
            "status": "partial" if notes else "converged",
            "removed": list(result.removed),
            "path_shim": shim,
            "resolved_cli": resolved,
            "resolved_cli_is_desktop": on_desktop,
            "daemon_restart_required": not inventory.empty,
            "notes": notes,
        }
    )
    return payload


def repair_hooks_then_converge(
    context: HarnessContext,
    *,
    store: GuardStore,
    workspace: str | None,
    now: str,
    dry_run: bool = False,
) -> tuple[dict[str, object], list[dict[str, object]], list[str]]:
    """Point every hook at this Core, then retire the installs it supersedes.

    Installs are removed only after hook repair finished without a failure, so
    no harness is left calling a deleted binary. Informational notes, such as
    a reminder to restart OpenCode, do not hold converge back. Returns the converge payload,
    the repaired managed installs and the repair notes.
    """

    from . import update_commands as commands

    if dry_run:
        return converge_on_desktop_core(context, dry_run=True), [], []
    repaired, repair_notes = commands._repair_supported_harnesses_in_process(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
        dry_run=False,
    )
    if any(_REPAIR_FAILURE_MARKER in note for note in repair_notes):
        planned = converge_on_desktop_core(context, dry_run=True)
        if planned["status"] == "planned" and planned.get("found"):
            planned["status"] = "deferred"
            planned["notes"] = [_DEFERRED_NOTE]
            return planned, repaired, list(repair_notes)
    return converge_on_desktop_core(context), repaired, list(repair_notes)


def run_desktop_converge(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: Path | None,
    output_stream: TextIO,
) -> int:
    """``hol-guard desktop converge``: repair hooks, retire other installs, restart the daemon."""

    from .update_desktop_apply import refresh_desktop_core_daemon

    dry_run = bool(getattr(args, "dry_run", False))
    if not dry_run and not getattr(sys, "frozen", False):
        # The daemon restart below runs this process's executable, which must be
        # the Desktop Core, never an install that converge is about to remove.
        # A dry run changes nothing, so any install may preview it.
        print(_CORE_ONLY_MESSAGE, file=output_stream)
        return 1
    payload, repaired, repair_notes = repair_hooks_then_converge(
        context,
        store=store,
        workspace=str(workspace) if workspace else None,
        now=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        dry_run=dry_run,
    )
    if payload["status"] not in {"skipped", "planned"}:
        payload["managed_installs"] = repaired
        # Informational repair notes, such as a restart reminder, are reported
        # but do not make a successful converge partial.
        failures = [*(note for note in repair_notes if _REPAIR_FAILURE_MARKER in note), *converge_notes(payload)]
        notes = [*repair_notes, *converge_notes(payload)]
        if payload.get("daemon_restart_required"):
            refreshed, refresh_note = refresh_desktop_core_daemon(context, executable=Path(sys.executable).resolve())
            payload["daemon_refresh"] = refreshed
            notes.extend([refresh_note] if refresh_note else [])
            failures.extend([refresh_note] if refresh_note and refreshed is None else [])
        payload["notes"] = notes
        if payload["status"] != "deferred":
            payload["status"] = "partial" if failures else "converged"
    if bool(getattr(args, "json", False)):
        print(json.dumps(payload, sort_keys=True), file=output_stream)
    else:
        print(_summary(payload), file=output_stream)
    return 0 if payload["status"] in {"converged", "planned", "skipped"} else 1


def _describe(inventory: ForeignInventory) -> list[dict[str, str]]:
    found = [{"kind": venv.kind, "path": str(venv.root)} for venv in inventory.venvs]
    found += [{"kind": "stale_link", "path": str(entry)} for entry in inventory.stale_entries]
    found += [{"kind": "pip_user", "path": str(path)} for path in inventory.user_site_interpreters]
    return found


def converge_notes(payload: dict[str, object]) -> list[str]:
    notes = payload.get("notes")
    return [str(note) for note in notes] if isinstance(notes, list) else []


def _summary(payload: dict[str, object]) -> str:
    if payload["status"] == "skipped":
        return str(payload["message"])
    key = "found" if payload["status"] in {"planned", "deferred"} else "removed"
    entries = payload.get(key)
    paths = [str(item["path"]) for item in entries if isinstance(item, dict)] if isinstance(entries, list) else []
    verb = "Would remove" if key == "found" else "Removed"
    lines = [f"{verb} {path}" for path in paths] or ["No other HOL Guard installs found."]
    lines += converge_notes(payload)
    return "\n".join(lines)


def _resident_retirer(guard_home: Path) -> Callable[[Path], bool]:
    from ..native_resident_client import retire_native_resident_for_update
    from ..native_runtime import _isolated_environment
    from .update_retirement import retire_with_retry

    def retire(executable: Path) -> bool:
        return retire_with_retry(
            lambda timeout_seconds: retire_native_resident_for_update(
                executable=executable,
                guard_home=guard_home,
                environment=_isolated_environment(),
                timeout_seconds=timeout_seconds,
            )
        )

    return retire


def _refresh_package_shims(context: HarnessContext) -> str | None:
    from ..shims import package_shim_status, repair_package_shims

    try:
        installed = package_shim_status(context).get("installed_managers")
        managers = tuple(str(item) for item in installed) if isinstance(installed, list) else ()
        if managers:
            _ = repair_package_shims(context, managers=managers)
    except (OSError, RuntimeError, ValueError) as error:
        return f"Could not rebind package firewall shims to the Desktop Core: {error}"
    return None


def _retire_daemons(guard_home: Path) -> None:
    from ..daemon.manager import retire_all_guard_daemons_for_home

    _ = retire_all_guard_daemons_for_home(guard_home)


def _ensure_user_path_shim(home: Path, launcher: Path, removed_dirs: frozenset[Path]) -> dict[str, object]:
    """Write Desktop's ``~/.local/bin`` wrapper where a removed install used to be.

    The format matches the wrapper the Desktop app writes, so either writer can
    later replace the other's file. A user's own file is never replaced.
    """

    bin_dir = home / ".local" / "bin"
    if sys.platform == "win32":
        if bin_dir not in removed_dirs or any((bin_dir / f"hol-guard{s}").exists() for s in ("", ".exe", ".cmd")):
            return {"status": "unchanged"}
        target, text = bin_dir / "hol-guard.cmd", f'@echo off\r\nrem {DESKTOP_PATH_SHIM_MARKER}\r\n"{launcher}" %*\r\n'
    else:
        target = bin_dir / "hol-guard"
        present = target.exists() or target.is_symlink()
        if present and DESKTOP_PATH_SHIM_MARKER not in _read_text(target):
            return {"status": "unchanged"}
        quoted = str(launcher).replace("'", "'\\''")
        text = f"#!/bin/sh\n# {DESKTOP_PATH_SHIM_MARKER}\nset -eu\nexec '{quoted}' \"$@\"\n"
        if _read_text(target) == text:
            return {"status": "current", "path": str(target)}
    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
        temporary = bin_dir / _SHIM_TEMP_NAME
        # newline="" keeps the CRLF endings cmd.exe expects on Windows.
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            _ = handle.write(text)
        temporary.chmod(0o755)
        os.replace(temporary, target)
    except OSError as error:
        return {"status": "failed", "path": str(target), "error": error.strerror or str(error)}
    return {"status": "written", "path": str(target)}


def _resolves_to_launcher(resolved: Path, launcher: Path) -> bool:
    try:
        if resolved.resolve() == launcher.resolve():
            return True
    except OSError:
        return False
    return DESKTOP_PATH_SHIM_MARKER in _read_text(resolved)


def _read_text(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(64 * 1024).decode("utf-8", errors="replace")
    except OSError:
        return ""


__all__ = ["converge_notes", "converge_on_desktop_core", "repair_hooks_then_converge", "run_desktop_converge"]
