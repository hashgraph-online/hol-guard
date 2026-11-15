"""``hol-guard repair``: one idempotent pass that fixes what commonly breaks.

Steps, each isolated so one failure never skips the rest:

1. ``daemon``: restart the local daemon when it is not healthy.
2. ``native_runtime``: prune dead ``resident-v3-*`` dirs and sockets (fail closed).
3. ``native_install``: restore the execute bit Guard's own runtime copy lost;
   report an install only a reinstall can fix.
4. ``onefile_leaks``: reclaim leaked ``_MEI*`` Guard extraction dirs (fail closed).
5. ``hooks``: re-verify managed harness hooks and reinstall the broken ones.
6. ``package_shims`` and ``command_queue``: the same repairs as ``doctor --repair``.

Steps 2 and 4 are non-destructive to anything live. The rest need a user (and
the same step-up as ``doctor --repair``), so only the CLI and the gated daemon
endpoint run them.
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
    "native_install": "Native runtime install",
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


_REPORT_FEATURE = "native-guard-repair-report-v1"
_REPORT_SCHEMA = "guard-repair-report.v1"
_REPORT_OUTPUT_LIMIT = 512 * 1024
_REPORT_TIMEOUT_SECONDS = 10.0


def _raised(name: str, error: BaseException, **result: object) -> dict[str, object]:
    return {"step": name, "error_type": type(error).__name__, "error_message": str(error), **result}


def _daemon_result(guard_home: Path, *, home_dir: Path, dry_run: bool) -> dict[str, object]:
    if not (guard_home / "daemon-state.json").exists() and not owns_system_scope(guard_home):
        return {"step": "daemon", "probe": "unrecorded"}
    try:
        if dry_run:
            from .native_daemon_peer import verified_live_guard_daemon_identity

            healthy = verified_live_guard_daemon_identity(guard_home) is not None
            return {"step": "daemon", "probe": "healthy" if healthy else "unhealthy"}
        from .runtime_health.runtime_repair import repair_guard_daemon_runtime

        result = repair_guard_daemon_runtime(guard_home, home_dir=home_dir)
        return {"step": "daemon", "runtime_status": str(result.get("runtime_status", "unknown"))}
    except Exception as error:
        return _raised("daemon", error)


def _native_runtime_result(guard_home: Path, *, dry_run: bool) -> dict[str, object]:
    try:
        from .resident_state_prune import prune_native_runtime, prune_runtime_offered

        detail = prune_native_runtime(
            guard_home,
            dry_run=dry_run,
            include_system_sockets=owns_system_scope(guard_home),
        )
        result: dict[str, object] = {
            "step": "native_runtime",
            "detail": detail,
            "offered": detail is None and prune_runtime_offered(),
        }
    except Exception as error:
        result = _raised("native_runtime", error)
    if dry_run:
        return result
    from .durable_runtime_collapse import collapse_durable_runtimes

    try:
        # A failed or skipped collapse never changes the step: the copies it
        # would have shared stay as they are and still launch.
        collapse = collapse_durable_runtimes(guard_home)
    except Exception:
        collapse = None
    if collapse is not None:
        result["durable_runtimes"] = collapse
    return result


def _native_install_result(*, dry_run: bool) -> dict[str, object]:
    """Put back the execute bit Guard's own runtime copy lost; report what needs a reinstall.

    A runtime missing that bit cannot be launched, so it cannot restore the bit
    itself. Everything else wrong with an install -- a binary that disagrees
    with its manifest or with the package calling it -- is reported with the
    reinstall that clears it and left for the user, because replacing an
    installed binary is not something a repair pass should do unasked.
    """

    try:
        from .runtime_install_repair import repair_native_runtime_install

        report = repair_native_runtime_install(dry_run=dry_run)
    except Exception as error:
        return _raised("native_install", error)
    return {"step": "native_install", "report": dict(report)}


def _onefile_leaks_result(
    *,
    dry_run: bool,
    guard_home: Path | None = None,
    temp_root: Path | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    if temp_root is None and guard_home is not None and not owns_system_scope(guard_home):
        return {"step": "onefile_leaks", "not_owner": True}
    try:
        from .onefile_extraction import reclaim_orphaned_extraction_dirs

        result = reclaim_orphaned_extraction_dirs(
            temp_root=temp_root if temp_root is not None else Path(tempfile.gettempdir()),
            current_meipass=getattr(sys, "_MEIPASS", None),
            now=now if now is not None else datetime.now(timezone.utc),
            scan_open_paths=True,
            max_unmarked_reclaims=_REPAIR_UNMARKED_BUDGET,
            unmarked_time_budget=_REPAIR_TIME_BUDGET,
            dry_run=dry_run,
        )
    except Exception as error:
        return _raised("onefile_leaks", error)
    return {
        "step": "onefile_leaks",
        "result": {
            "reclaimed_count": result.reclaimed_count,
            "reclaimed_bytes": result.reclaimed_bytes,
            # Reclaimed (or, in a dry run, would-be reclaimed) dirs are never
            # counted in ``unmarked_count``, so it already is the remainder.
            "unmarked_count": result.unmarked_count,
            "unmarked_scan": result.unmarked_scan,
            "budget_exhausted": result.unmarked_budget_exhausted,
            "error_count": len(result.errors),
        },
    }


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


def _hooks_result(
    context: HarnessContext, store: GuardStore, *, dry_run: bool, harness: str | None = None
) -> dict[str, object]:
    try:
        broken = broken_hook_harnesses(context, store)
    except Exception as error:
        return _raised("hooks", error)
    if harness is not None:
        broken = [item for item in broken if item.get("harness") == harness]
    if dry_run or not broken:
        return {"step": "hooks", "broken": broken}
    from .cli.install_commands import apply_managed_install

    workspace = str(context.workspace_dir) if context.workspace_dir is not None else None
    repaired: list[str] = []
    failed: list[dict[str, str]] = []
    for name in (str(item["harness"]) for item in broken):
        try:
            apply_managed_install(
                "install", name, False, context, store, workspace, datetime.now(timezone.utc).isoformat()
            )
            repaired.append(name)
        except Exception as error:
            failed.append({"harness": name, "error_type": type(error).__name__, "error_message": str(error)})
    return {
        "step": "hooks",
        "broken": broken,
        "repaired": repaired,
        "failed": failed,
        "still_broken": _still_broken_after_reinstall(context, store, repaired),
    }


def _still_broken_after_reinstall(context: HarnessContext, store: GuardStore, reinstalled: list[str]) -> list[str]:
    """Reinstalled apps that stay broken, such as a missing binary or untrusted hooks.

    Reinstalling cannot fix those, so reporting them as repaired every run
    would hide a problem that needs the user.
    """

    if not reinstalled:
        return []
    try:
        remaining = {str(item["harness"]) for item in broken_hook_harnesses(context, store)}
    except Exception:
        # An unverified reinstall is not proof the hooks work again.
        return list(reinstalled)
    return [name for name in reinstalled if name in remaining]


def _package_shims_result(context: HarnessContext, *, dry_run: bool) -> dict[str, object]:
    package_shims = context.guard_home / "package-shims"
    # An empty home has nothing to regenerate. Asking the resident first would
    # fail a repair that only had stale runtime state when the runtime dir is
    # not yet owner-private.
    if not (package_shims / "manifest.json").exists() and not (package_shims / "bin").exists():
        return {"step": "package_shims", "managers": []}
    try:
        from .shims import activate_package_shims, package_shim_dashboard_status

        status = package_shim_dashboard_status(context)
        installed = status.get("installed_managers")
        managers = (
            tuple(str(item) for item in installed if isinstance(item, str) and item.strip())
            if isinstance(installed, list)
            else ()
        )
        if not managers or dry_run:
            return {"step": "package_shims", "managers": list(managers)}
        payload = activate_package_shims(context, managers=managers, repair=True)
        return {
            "step": "package_shims",
            "managers": list(managers),
            "restart_shell_required": bool(payload.get("restart_shell_required")),
        }
    except Exception as error:
        return _raised("package_shims", error)


def _command_queue_result(store: GuardStore, *, dry_run: bool) -> dict[str, object]:
    if dry_run:
        return {"step": "command_queue"}
    try:
        from .runtime.command_queue import repair_command_queue_state

        result = repair_command_queue_state(store)
    except Exception as error:
        return _raised("command_queue", error)
    raw_count = result.get("repaired_count")
    return {"step": "command_queue", "repaired_count": raw_count if isinstance(raw_count, int) else 0}


def build_report(results: list[dict[str, object]], *, dry_run: bool) -> dict[str, object]:
    """The runtime's report for what each step returned.

    Python runs the repairs; the runtime decides each step's status and the
    text ``hol-guard repair`` prints. When it does not answer, the report says
    which steps ran and that their outcome is unknown, rather than calling
    them healthy.
    """

    from .mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _REPORT_FEATURE,
        "guard-repair-report",
        {"schema": _REPORT_SCHEMA, "op": "report", "dry_run": dry_run, "results": results},
        output_limit=_REPORT_OUTPUT_LIMIT,
        timeout_seconds=_REPORT_TIMEOUT_SECONDS,
    )
    if answer is not None and answer.get("schema") == SCHEMA and isinstance(answer.get("steps"), list):
        return answer
    return _unreported(results, dry_run=dry_run)


def _unreported(results: list[dict[str, object]], *, dry_run: bool) -> dict[str, object]:
    steps: list[dict[str, object]] = []
    for result in results:
        name = str(result["step"])
        if "error_type" in result:
            text = f"{result['error_type']}: {str(result.get('error_message', ''))[:_MAX_ERROR_CHARS]}".strip()
            steps.append(
                {"step": name, "title": STEP_TITLES[name], "status": "error", "summary": f"Could not complete: {text}"}
            )
            continue
        steps.append(
            {
                "step": name,
                "title": STEP_TITLES[name],
                "status": "skipped",
                "summary": "Ran, but the native runtime did not answer to report the outcome.",
            }
        )
    lines = ["Guard repair (dry run, nothing changed)" if dry_run else "Guard repair"]
    lines.extend(
        f"  [{'FAILED' if item['status'] == 'error' else 'skipped'}] {item['title']}: {item['summary']}"
        for item in steps
    )
    lines.append("The native runtime did not answer. Run `hol-guard doctor --json` to see why.")
    return {"schema": SCHEMA, "dry_run": dry_run, "status": "partial", "steps": steps, "summary": "\n".join(lines)}


def _step(result: dict[str, object], *, dry_run: bool) -> dict[str, object]:
    steps = build_report([result], dry_run=dry_run)["steps"]
    assert isinstance(steps, list)
    step = steps[0]
    assert isinstance(step, dict)
    return step


def repair_daemon(guard_home: Path, *, home_dir: Path, dry_run: bool) -> dict[str, object]:
    return _step(_daemon_result(guard_home, home_dir=home_dir, dry_run=dry_run), dry_run=dry_run)


def repair_native_runtime(guard_home: Path, *, dry_run: bool) -> dict[str, object]:
    return _step(_native_runtime_result(guard_home, dry_run=dry_run), dry_run=dry_run)


def repair_native_install(*, dry_run: bool) -> dict[str, object]:
    return _step(_native_install_result(dry_run=dry_run), dry_run=dry_run)


def repair_onefile_leaks(
    *,
    dry_run: bool,
    guard_home: Path | None = None,
    temp_root: Path | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    result = _onefile_leaks_result(dry_run=dry_run, guard_home=guard_home, temp_root=temp_root, now=now)
    return _step(result, dry_run=dry_run)


def repair_hooks(
    context: HarnessContext, store: GuardStore, *, dry_run: bool, harness: str | None = None
) -> dict[str, object]:
    return _step(_hooks_result(context, store, dry_run=dry_run, harness=harness), dry_run=dry_run)


def repair_package_shims(context: HarnessContext, *, dry_run: bool) -> dict[str, object]:
    return _step(_package_shims_result(context, dry_run=dry_run), dry_run=dry_run)


def repair_command_queue(store: GuardStore, *, dry_run: bool) -> dict[str, object]:
    return _step(_command_queue_result(store, dry_run=dry_run), dry_run=dry_run)


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
        ("daemon", lambda: _daemon_result(guard_home, home_dir=context.home_dir, dry_run=dry_run)),
        ("native_runtime", lambda: _native_runtime_result(guard_home, dry_run=dry_run)),
        ("native_install", lambda: _native_install_result(dry_run=dry_run)),
        ("onefile_leaks", lambda: _onefile_leaks_result(dry_run=dry_run, guard_home=guard_home)),
        ("hooks", lambda: _hooks_result(context, store, dry_run=dry_run, harness=harness)),
        ("package_shims", lambda: _package_shims_result(context, dry_run=dry_run)),
        ("command_queue", lambda: _command_queue_result(store, dry_run=dry_run)),
    ]
    if harness is not None:
        skip_steps = skip_steps | frozenset(name for name, _run in plan if name != "hooks")
    results = [run() for name, run in plan if name not in skip_steps and (include_daemon or name != "daemon")]
    return build_report(results, dry_run=dry_run)


__all__ = [
    "STEP_TITLES",
    "broken_hook_harnesses",
    "build_report",
    "owns_system_scope",
    "repair_command_queue",
    "repair_daemon",
    "repair_hooks",
    "repair_native_install",
    "repair_native_runtime",
    "repair_onefile_leaks",
    "repair_package_shims",
    "run_repair",
]
