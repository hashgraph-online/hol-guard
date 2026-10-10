"""``hol-guard repair``: one idempotent pass that fixes what commonly breaks.

Steps, each isolated so one failure never skips the rest:

1. ``daemon``: restart the local daemon when it is not healthy.
2. ``native_runtime``: prune dead ``resident-v3-*`` dirs and sockets (fail closed).
3. ``onefile_leaks``: reclaim leaked ``_MEI*`` Guard extraction dirs (fail closed).
4. ``hooks``: re-verify managed harness hooks and reinstall the broken ones.
5. ``package_shims`` and ``command_queue``: the same repairs as ``doctor --repair``.

Steps 2 and 3 are non-destructive to anything live and are also what the daemon
runs on its own (``run_safe_self_check``). The rest need a user (and the same
step-up as ``doctor --repair``), so only the CLI and the gated daemon endpoint
run them.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .adapters import get_adapter
from .adapters.base import HarnessContext

if TYPE_CHECKING:
    from .store import GuardStore

SCHEMA = "guard.repair.v1"
STEP_TITLES = {
    "daemon": "Guard daemon",
    "native_runtime": "Stale native runtime state",
    "onefile_leaks": "Leaked extraction folders",
    "hooks": "Harness hooks",
    "package_shims": "Package-manager shims",
    "command_queue": "Command queue",
}
_BROKEN_SETUP_STATUSES = frozenset({"broken", "partial", "not_found"})
_REPAIR_UNMARKED_BUDGET = 5000
_REPAIR_TIME_BUDGET = timedelta(minutes=3)
_MAX_ERROR_CHARS = 160


def owns_system_scope(guard_home: Path) -> bool:
    """True only for the account's real Guard home.

    The shared temp dir (leaked ``_MEI*`` folders, ``hgr-*`` socket dirs) is
    machine-wide, not per Guard home. A custom or temporary ``--guard-home``
    (tests, sandboxes) must never reclaim from it.
    """

    try:
        from .cli.commands_lifecycle_gate import canonical_lifecycle_home

        return guard_home.expanduser().resolve() == canonical_lifecycle_home().resolve()
    except Exception:
        return False


def _step(name: str, status: str, summary: str, **detail: object) -> dict[str, object]:
    return {"step": name, "title": STEP_TITLES[name], "status": status, "summary": summary, **detail}


def _error_step(name: str, error: BaseException) -> dict[str, object]:
    text = f"{type(error).__name__}: {str(error)[:_MAX_ERROR_CHARS]}".strip()
    return _step(name, "error", f"Could not complete: {text}", error=text)


def repair_daemon(guard_home: Path, *, home_dir: Path, dry_run: bool) -> dict[str, object]:
    if not (guard_home / "daemon-state.json").exists() and not owns_system_scope(guard_home):
        return _step("daemon", "ok", "No daemon is recorded for this Guard home.")
    try:
        if dry_run:
            from .daemon.live_identity import verified_live_guard_daemon_identity

            healthy = verified_live_guard_daemon_identity(guard_home) is not None
            if healthy:
                return _step("daemon", "ok", "Daemon is healthy.")
            return _step("daemon", "planned", "Daemon is not responding; it would be restarted.")
        from .daemon.runtime_repair import repair_guard_daemon_runtime

        result = repair_guard_daemon_runtime(guard_home, home_dir=home_dir)
        runtime_status = str(result.get("runtime_status", "unknown"))
        if runtime_status == "restarted":
            return _step(
                "daemon", "changed", "Daemon was not healthy and was restarted.", runtime_status=runtime_status
            )
        return _step("daemon", "ok", "Daemon is healthy.", runtime_status=runtime_status)
    except Exception as error:
        return _error_step("daemon", error)


def repair_native_runtime(guard_home: Path, *, dry_run: bool) -> dict[str, object]:
    try:
        from .resident_state_prune import prune_native_runtime

        report = prune_native_runtime(
            guard_home,
            dry_run=dry_run,
            socket_roots=None if owns_system_scope(guard_home) else (),
        )
    except Exception as error:
        return _error_step("native_runtime", error)
    detail = report.to_dict()
    dirs, sockets = len(report.removed_dirs), len(report.removed_sockets)
    if report.status in {"unsupported", "unavailable"}:
        return _step("native_runtime", "skipped", f"Not checked ({report.status}).", **detail)
    if not dirs and not sockets:
        return _step("native_runtime", "ok", "No stale native runtime state.", **detail)
    verb = "Would remove" if dry_run else "Removed"
    return _step(
        "native_runtime",
        "planned" if dry_run else "changed",
        f"{verb} {dirs} stale runtime folder(s) and {sockets} dead socket(s).",
        **detail,
    )


def repair_onefile_leaks(
    *,
    dry_run: bool,
    guard_home: Path | None = None,
    temp_root: Path | None = None,
    now: datetime | None = None,
    scanner: Callable[[Path], frozenset[str] | None] | None = None,
) -> dict[str, object]:
    if temp_root is None and guard_home is not None and not owns_system_scope(guard_home):
        return _step("onefile_leaks", "skipped", "Shared temp folders are only reclaimed for the default Guard home.")
    try:
        from .onefile_extraction import reclaim_orphaned_extraction_dirs
        from .onefile_open_paths import scan_open_extraction_dirs

        result = reclaim_orphaned_extraction_dirs(
            temp_root=temp_root if temp_root is not None else Path(tempfile.gettempdir()),
            current_meipass=getattr(sys, "_MEIPASS", None),
            now=now if now is not None else datetime.now(timezone.utc),
            open_path_scanner=scanner if scanner is not None else scan_open_extraction_dirs,
            max_unmarked_reclaims=_REPAIR_UNMARKED_BUDGET,
            unmarked_time_budget=_REPAIR_TIME_BUDGET,
            dry_run=dry_run,
        )
    except Exception as error:
        return _error_step("onefile_leaks", error)
    detail: dict[str, object] = {
        "reclaimed_count": result.reclaimed_count,
        "reclaimed_bytes": result.reclaimed_bytes,
        # Reclaimed (or, in a dry run, would-be reclaimed) dirs are never
        # counted in ``unmarked_count``, so it already is the remainder.
        "unmarked_remaining": result.unmarked_count,
        "unmarked_scan": result.unmarked_scan,
        "budget_exhausted": result.unmarked_budget_exhausted,
        "error_count": len(result.errors),
    }
    if result.unmarked_scan == "unavailable":
        return _step(
            "onefile_leaks",
            "skipped",
            "Could not prove unmarked folders unused (open-files scan unavailable); left in place.",
            **detail,
        )
    if not result.reclaimed_count:
        return _step("onefile_leaks", "ok", "No leaked extraction folders found.", **detail)
    megabytes = result.reclaimed_bytes // (1024 * 1024)
    verb = "Would reclaim" if dry_run else "Reclaimed"
    suffix = " Run repair again to continue." if result.unmarked_budget_exhausted else ""
    return _step(
        "onefile_leaks",
        "planned" if dry_run else "changed",
        f"{verb} {result.reclaimed_count} leaked folder(s), about {megabytes} MB.{suffix}",
        **detail,
    )


def broken_hook_harnesses(context: HarnessContext, store: GuardStore) -> list[dict[str, object]]:
    """Harnesses Guard manages whose registration is broken or incomplete."""

    from .adapters.diagnostic_probes import without_command_probes

    broken: list[dict[str, object]] = []
    managed = [
        str(item["harness"])
        for item in store.list_managed_installs()
        if bool(item.get("active")) and isinstance(item.get("harness"), str)
    ]
    with without_command_probes():
        for harness in managed:
            try:
                diagnostics = get_adapter(harness).diagnostics(context)
            except Exception as error:
                broken.append({"harness": harness, "setup_status": "unknown", "error": type(error).__name__})
                continue
            status = diagnostics.get("setup_status")
            if status in _BROKEN_SETUP_STATUSES:
                broken.append({"harness": harness, "setup_status": status})
    return broken


def repair_hooks(
    context: HarnessContext, store: GuardStore, *, dry_run: bool, harness: str | None = None
) -> dict[str, object]:
    try:
        broken = broken_hook_harnesses(context, store)
    except Exception as error:
        return _error_step("hooks", error)
    if harness is not None:
        broken = [item for item in broken if item.get("harness") == harness]
    if not broken:
        return _step("hooks", "ok", "Managed harness hooks look intact.", repaired=[], failed=[])
    names = [str(item["harness"]) for item in broken]
    if dry_run:
        return _step(
            "hooks", "planned", f"Would reinstall hooks for: {', '.join(names)}.", repaired=[], failed=[], broken=broken
        )
    from .cli.install_commands import apply_managed_install

    workspace = str(context.workspace_dir) if context.workspace_dir is not None else None
    repaired: list[str] = []
    failed: list[dict[str, str]] = []
    for harness in names:
        try:
            apply_managed_install(
                "install", harness, False, context, store, workspace, datetime.now(timezone.utc).isoformat()
            )
            repaired.append(harness)
        except Exception as error:
            failed.append({"harness": harness, "error": f"{type(error).__name__}: {str(error)[:_MAX_ERROR_CHARS]}"})
    if failed:
        failed_names = ", ".join(item["harness"] for item in failed)
        return _step(
            "hooks",
            "error",
            f"Reinstalled {len(repaired)} app(s); {len(failed)} failed: {failed_names}.",
            repaired=repaired,
            failed=failed,
        )
    return _step("hooks", "changed", f"Reinstalled hooks for: {', '.join(repaired)}.", repaired=repaired, failed=[])


def repair_package_shims(context: HarnessContext, *, dry_run: bool) -> dict[str, object]:
    try:
        from .shims import activate_package_shims, package_shim_dashboard_status

        status = package_shim_dashboard_status(context)
        installed = status.get("installed_managers")
        managers = (
            tuple(str(item) for item in installed if isinstance(item, str) and item.strip())
            if isinstance(installed, list)
            else ()
        )
        if not managers:
            return _step("package_shims", "ok", "No package-manager shims installed.")
        if dry_run:
            return _step("package_shims", "planned", f"Would regenerate shims for: {', '.join(managers)}.")
        payload = activate_package_shims(context, managers=managers, repair=True)
        return _step(
            "package_shims",
            "changed",
            f"Regenerated shims for: {', '.join(managers)}.",
            restart_shell_required=bool(payload.get("restart_shell_required")),
        )
    except Exception as error:
        return _error_step("package_shims", error)


def repair_command_queue(store: GuardStore, *, dry_run: bool) -> dict[str, object]:
    if dry_run:
        return _step("command_queue", "skipped", "Not checked in a dry run.")
    try:
        from .runtime.command_queue import repair_command_queue_state

        result = repair_command_queue_state(store)
    except Exception as error:
        return _error_step("command_queue", error)
    raw_count = result.get("repaired_count")
    count = raw_count if isinstance(raw_count, int) else 0
    if count:
        return _step("command_queue", "changed", f"Cleared {count} stuck queue item(s).")
    return _step("command_queue", "ok", "Command queue is healthy.")


def run_repair(
    *,
    guard_home: Path,
    context: HarnessContext,
    store: GuardStore,
    dry_run: bool = False,
    include_daemon: bool = True,
    skip_steps: frozenset[str] = frozenset(),
    harness: str | None = None,
) -> dict[str, object]:
    """Run every repair step and return the per-step report.

    ``skip_steps`` lets a caller that already ran a step (``doctor --repair``
    regenerates shims and the queue itself) avoid repeating it. ``harness``
    scopes the run to that app's hooks: the step-up grant covered only that
    app, so every other step is left out.
    """

    plan: list[tuple[str, Callable[[], dict[str, object]]]] = [
        ("daemon", lambda: repair_daemon(guard_home, home_dir=context.home_dir, dry_run=dry_run)),
        ("native_runtime", lambda: repair_native_runtime(guard_home, dry_run=dry_run)),
        ("onefile_leaks", lambda: repair_onefile_leaks(dry_run=dry_run, guard_home=guard_home)),
        ("hooks", lambda: repair_hooks(context, store, dry_run=dry_run, harness=harness)),
        ("package_shims", lambda: repair_package_shims(context, dry_run=dry_run)),
        ("command_queue", lambda: repair_command_queue(store, dry_run=dry_run)),
    ]
    if harness is not None:
        skip_steps = skip_steps | frozenset(name for name, _run in plan if name != "hooks")
    steps = [run() for name, run in plan if name not in skip_steps and (include_daemon or name != "daemon")]
    return build_report(steps, dry_run=dry_run)


def build_report(steps: list[dict[str, object]], *, dry_run: bool) -> dict[str, object]:
    statuses = [str(item["status"]) for item in steps]
    if "error" in statuses:
        status = "partial"
    elif "planned" in statuses:
        status = "needs_repair"
    elif "changed" in statuses:
        status = "repaired"
    else:
        status = "healthy"
    return {
        "schema": SCHEMA,
        "dry_run": dry_run,
        "status": status,
        "steps": steps,
        "summary": format_repair_summary(steps, status=status, dry_run=dry_run),
    }


_MARKS = {"ok": "ok", "changed": "fixed", "planned": "would fix", "skipped": "skipped", "error": "FAILED"}


def format_repair_summary(steps: list[dict[str, object]], *, status: str, dry_run: bool) -> str:
    lines = ["Guard repair (dry run, nothing changed)" if dry_run else "Guard repair"]
    for item in steps:
        mark = _MARKS.get(str(item["status"]), str(item["status"]))
        lines.append(f"  [{mark}] {item['title']}: {item['summary']}")
    if status == "partial":
        lines.append("Some steps failed. Re-run `hol-guard repair`; if it persists, run `hol-guard doctor --json`.")
    elif status == "needs_repair":
        lines.append("Run `hol-guard repair` to apply these fixes.")
    elif status == "repaired":
        lines.append("Guard was repaired. Restart any open coding-agent sessions that were blocked.")
    else:
        lines.append("Nothing needed repair.")
    return "\n".join(lines)


def run_safe_self_check(guard_home: Path) -> dict[str, object]:
    """The non-destructive subset the daemon runs by itself: no hooks, no restarts."""

    return {
        "native_runtime": repair_native_runtime(guard_home, dry_run=False),
        "onefile_leaks": repair_onefile_leaks(dry_run=False, guard_home=guard_home),
    }


__all__ = [
    "STEP_TITLES",
    "broken_hook_harnesses",
    "build_report",
    "format_repair_summary",
    "owns_system_scope",
    "repair_command_queue",
    "repair_daemon",
    "repair_hooks",
    "repair_native_runtime",
    "repair_onefile_leaks",
    "repair_package_shims",
    "run_repair",
    "run_safe_self_check",
]
