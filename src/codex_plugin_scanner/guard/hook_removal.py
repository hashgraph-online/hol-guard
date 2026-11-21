"""Remove every Guard hook from every known harness, recorded or not.

Two passes per affected harness:

1. The harness adapter's own ``uninstall`` (through ``apply_managed_install``),
   which owns authenticated manifests, hook scripts, shims, and store state.
2. ``hook_removal_sweep``, which strips any Guard-signed handler still left in
   the harness's JSON/TOML config files (hooks Guard no longer has a record of).

Every config file of a harness is copied to a private backup directory before
anything edits it; a harness whose files cannot be copied is skipped.
Copies of files that did not change are dropped afterwards.
Non-Guard hook handlers are never touched. This module performs no
authorization; callers must have already passed step-up.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from .harness_context import HarnessContext
from .hook_removal_sweep import (
    BackupError,
    SweepUnavailableError,
    backup_harness_files,
    finalize_backups,
    harness_hook_files,
    removal_plans,
    sweep_harness,
)
from .native_harness_ops import list_harnesses

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
    harnesses = list_harnesses()
    try:
        return [_decode_plan(row, harnesses) for row in removal_plans(context, harnesses, active)]
    except SweepUnavailableError:
        # An unavailable scanner leaves the config state unknown.
        return [
            HarnessPlan(
                harness=harness,
                reasons=(["managed_install"] if harness in active else []) + ["hook_scan_unavailable"],
            )
            for harness in harnesses
        ]


def _decode_plan(row: object, harnesses: tuple[str, ...]) -> HarnessPlan:
    if not isinstance(row, dict):
        raise SweepUnavailableError("native hook removal plan malformed")
    harness = row.get("harness")
    reasons = row.get("reasons")
    files = row.get("files_with_hooks")
    count = row.get("hook_count")
    if (
        not isinstance(harness, str)
        or harness not in harnesses
        or not isinstance(reasons, list)
        or not all(isinstance(reason, str) for reason in reasons)
        or not isinstance(files, list)
        or not all(isinstance(file, str) for file in files)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
    ):
        raise SweepUnavailableError("native hook removal plan malformed")
    return HarnessPlan(harness, cast("list[str]", reasons), cast("list[str]", files), count)


def _error_text(error: BaseException) -> str:
    return f"{type(error).__name__}: {str(error)[:_MAX_ERROR_CHARS]}".strip()


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
    if any("hook_scan_unavailable" in plan.reasons for plan in plans):
        return {
            **base,
            "status": "partial",
            "harnesses": [
                {
                    "harness": plan.harness,
                    "reasons": list(plan.reasons),
                    "adapter_uninstall": "skipped",
                    "backup_error": "native hook removal plan unavailable",
                }
                for plan in plans
            ],
            "removed_hook_count": 0,
            "backup_dir": None,
            "backups": [],
            "remaining": [{"harness": plan.harness, "path": "", "hook_count": 0} for plan in plans],
            "affected_harness_count": 0,
        }

    from .cli.install_commands import apply_managed_install

    backup_dir = context.guard_home / "backups" / f"hook-removal-{stamp}"
    backed_up: dict[str, dict[str, str]] = {}
    workspace = str(context.workspace_dir) if context.workspace_dir is not None else None
    results: list[dict[str, object]] = []
    for plan in plans:
        entry: dict[str, object] = {"harness": plan.harness, "reasons": list(plan.reasons)}
        try:
            files = harness_hook_files(plan.harness, context)
            copies = backup_harness_files(backup_dir, plan.harness, files, skip=backed_up.keys())
        except (BackupError, SweepUnavailableError) as error:
            # Never edit a config file we could not restore.
            entry["adapter_uninstall"] = "skipped"
            entry["backup_error"] = str(error)
            results.append(entry)
            continue
        backed_up.update((copy["original_path"], copy) for copy in copies)
        try:
            apply_managed_install("uninstall", plan.harness, False, context, store, workspace, moment.isoformat())
            entry["adapter_uninstall"] = "ok"
        except Exception as error:  # one harness failing must not strand the others
            entry["adapter_uninstall"] = "error"
            entry["adapter_error"] = _error_text(error)
        try:
            swept = sweep_harness(plan.harness, context, dry_run=False)
        except SweepUnavailableError:
            entry["swept_hook_count"] = 0
            entry["sweep_errors"] = ["runtime_unavailable"]
        else:
            entry["swept_hook_count"] = swept.removed
            entry["sweep_errors"] = [f"{item.path.name}:{item.error}" for item in swept.files if item.error]
        results.append(entry)

    final_backup_dir, backups = finalize_backups(backup_dir, list(backed_up.values()), stamp=stamp)
    remaining: list[dict[str, object]] = []
    remaining_count = 0
    for plan in plans:
        try:
            rescanned = sweep_harness(plan.harness, context, dry_run=True).files
        except SweepUnavailableError:
            remaining.append({"harness": plan.harness, "path": "", "hook_count": plan.hook_count})
            remaining_count += plan.hook_count
            continue
        for item in rescanned:
            if item.removed:
                remaining.append({"harness": plan.harness, "path": str(item.path), "hook_count": item.removed})
                remaining_count += item.removed
    removed_total = max(0, sum(plan.hook_count for plan in plans) - remaining_count)
    failed = [item for item in results if item.get("adapter_uninstall") in {"error", "skipped"}]
    status = "removed" if not remaining and not failed else "partial"
    return {
        **base,
        "harnesses": results,
        "status": status,
        "removed_hook_count": removed_total,
        "backup_dir": str(final_backup_dir) if final_backup_dir is not None else None,
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
