"""Remove every Guard hook from every known harness, recorded or not.

Two passes per affected harness:

1. The harness adapter's own ``uninstall`` (through ``apply_managed_install``),
   which owns authenticated manifests, hook scripts, shims, and store state.
2. ``hook_removal_sweep``, which strips any Guard-signed handler still left in
   the harness's JSON/TOML config files (hooks Guard no longer has a record of).

Every config file that changes is first copied to a private backup directory.
Non-Guard hook handlers are never touched. This module performs no
authorization; callers must have already passed step-up.
"""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .adapters import list_adapters
from .adapters.base import HarnessContext
from .hook_removal_sweep import harness_hook_files, sweep_harness

if TYPE_CHECKING:
    from .store import GuardStore

REINSTALL_COMMAND = "hol-guard install --all"
_MAX_ERROR_CHARS = 160


@dataclass
class HarnessPlan:
    harness: str
    reasons: list[str] = field(default_factory=list)
    files_with_hooks: list[str] = field(default_factory=list)
    hook_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "harness": self.harness,
            "reasons": list(self.reasons),
            "files_with_hooks": list(self.files_with_hooks),
            "hook_count": self.hook_count,
        }


def plan_hook_removal(context: HarnessContext, store: GuardStore) -> list[HarnessPlan]:
    """List the harnesses removal would touch, without changing anything."""

    active = {
        str(item["harness"])
        for item in store.list_managed_installs()
        if bool(item.get("active")) and isinstance(item.get("harness"), str)
    }
    plans: list[HarnessPlan] = []
    for adapter in list_adapters():
        harness = adapter.harness
        plan = HarnessPlan(harness=harness)
        if harness in active:
            plan.reasons.append("managed_install")
        for result in sweep_harness(harness, context, dry_run=True).files:
            if result.removed:
                plan.files_with_hooks.append(str(result.path))
                plan.hook_count += result.removed
        if plan.hook_count:
            plan.reasons.append("hooks_in_config")
        if plan.reasons:
            plans.append(plan)
    return plans


def _error_text(error: BaseException) -> str:
    return f"{type(error).__name__}: {str(error)[:_MAX_ERROR_CHARS]}".strip()


def _snapshot(files: tuple[Path, ...]) -> dict[Path, bytes]:
    snapshot: dict[Path, bytes] = {}
    for path in files:
        with suppress(OSError):
            snapshot[path] = path.read_bytes()
    return snapshot


def _write_backups(
    *,
    guard_home: Path,
    before: dict[str, dict[Path, bytes]],
    stamp: str,
) -> tuple[Path | None, list[dict[str, str]]]:
    """Copy every file whose content changed to a private backup directory."""

    backup_dir = guard_home / "backups" / f"hook-removal-{stamp}"
    entries: list[dict[str, str]] = []
    for harness, files in before.items():
        for path, original in files.items():
            try:
                current = path.read_bytes() if path.exists() else None
            except OSError:
                current = None
            if current == original:
                continue
            digest = hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:8]
            name = f"{harness}-{digest}-{path.name}"
            try:
                backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(backup_dir, 0o700)
                target = backup_dir / name
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(original)
            except OSError:
                continue
            entries.append({"harness": harness, "original_path": str(path), "backup_path": str(target)})
    if not entries:
        return None, entries
    manifest = backup_dir / "manifest.json"
    with suppress(OSError):
        descriptor = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"created_at": stamp, "files": entries}, handle, indent=2)
    return backup_dir, entries


def remove_all_guard_hooks(
    *,
    context: HarnessContext,
    store: GuardStore,
    dry_run: bool = False,
    now: datetime | None = None,
) -> dict[str, object]:
    """Remove all Guard hooks; return a report with per-harness results."""

    moment = now or datetime.now(timezone.utc)
    stamp = moment.strftime("%Y%m%dT%H%M%SZ")
    plans = plan_hook_removal(context, store)
    base: dict[str, object] = {
        "dry_run": dry_run,
        "harnesses": [plan.to_dict() for plan in plans],
        "reinstall_command": REINSTALL_COMMAND,
    }
    if dry_run:
        return {**base, "status": "planned" if plans else "nothing_to_remove", "removed_hook_count": 0}
    if not plans:
        return {**base, "status": "nothing_to_remove", "removed_hook_count": 0, "backup_dir": None}

    from .cli.install_commands import apply_managed_install

    before = {plan.harness: _snapshot(harness_hook_files(plan.harness, context)) for plan in plans}
    workspace = str(context.workspace_dir) if context.workspace_dir is not None else None
    results: list[dict[str, object]] = []
    for plan in plans:
        entry: dict[str, object] = {"harness": plan.harness, "reasons": list(plan.reasons)}
        try:
            apply_managed_install("uninstall", plan.harness, False, context, store, workspace, moment.isoformat())
            entry["adapter_uninstall"] = "ok"
        except Exception as error:  # one harness failing must not strand the others
            entry["adapter_uninstall"] = "error"
            entry["adapter_error"] = _error_text(error)
        swept = sweep_harness(plan.harness, context, dry_run=False)
        entry["swept_hook_count"] = swept.removed
        entry["sweep_errors"] = [f"{item.path.name}:{item.error}" for item in swept.files if item.error]
        results.append(entry)

    backup_dir, backups = _write_backups(guard_home=context.guard_home, before=before, stamp=stamp)
    remaining: list[dict[str, object]] = []
    remaining_count = 0
    for plan in plans:
        for item in sweep_harness(plan.harness, context, dry_run=True).files:
            if item.removed:
                remaining.append({"harness": plan.harness, "path": str(item.path), "hook_count": item.removed})
                remaining_count += item.removed
    removed_total = max(0, sum(plan.hook_count for plan in plans) - remaining_count)
    failed = [item for item in results if item.get("adapter_uninstall") == "error"]
    status = "removed" if not remaining and not failed else "partial"
    return {
        **base,
        "harnesses": results,
        "status": status,
        "removed_hook_count": removed_total,
        "backup_dir": str(backup_dir) if backup_dir is not None else None,
        "backups": backups,
        "remaining": remaining,
        "affected_harness_count": len(results) - len(failed),
    }


def format_removal_summary(report: dict[str, object]) -> str:
    """Human-readable result of ``remove_all_guard_hooks``."""

    harnesses = report.get("harnesses")
    items = [item for item in harnesses if isinstance(item, dict)] if isinstance(harnesses, list) else []
    names = ", ".join(str(item.get("harness")) for item in items) or "none"
    status = report.get("status")
    if report.get("dry_run"):
        if not items:
            return "No Guard hooks found. Nothing would be removed."
        return f"Dry run. Guard hooks would be removed from {len(items)} app(s): {names}."
    if status == "nothing_to_remove":
        return "No Guard hooks found. Nothing to remove."
    lines = [
        f"Guard hooks removed from {report.get('affected_harness_count', len(items))} app(s): {names}.",
        f"Hook handlers removed from config files: {report.get('removed_hook_count', 0)}.",
    ]
    backup_dir = report.get("backup_dir")
    if backup_dir:
        lines.append(f"Backups of every modified file: {backup_dir}")
    if status == "partial":
        lines.append("Some hooks could not be removed; see `--json` for details, then re-run this command.")
    lines.append(f"Reinstall: {report.get('reinstall_command', REINSTALL_COMMAND)}")
    return "\n".join(lines)


__all__ = [
    "REINSTALL_COMMAND",
    "HarnessPlan",
    "format_removal_summary",
    "plan_hook_removal",
    "remove_all_guard_hooks",
]
