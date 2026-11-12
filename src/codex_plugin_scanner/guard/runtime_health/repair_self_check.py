"""Periodic, non-destructive self-check run by the daemon.

Every cycle it prunes provably stale native runtime state and looks for broken
managed hooks. It never reinstalls hooks, restarts anything, or removes
anything it cannot prove stale: a hook problem becomes a health finding with a
one-click "Repair Guard" action (``POST /v1/repair``) instead. The finding is
published in the daemon's detailed health payload.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..adapters.base import HarnessContext
from ..repair_engine import broken_hook_harnesses, repair_native_runtime, repair_onefile_leaks

if TYPE_CHECKING:
    from ..store import GuardStore

CHECK_INTERVAL_SECONDS = 600
_STARTUP_DELAY_SECONDS = 30  # let the daemon finish starting before probing
_LEAK_SCAN_EVERY = 6  # cycles; the open-files scan is the expensive part
REPAIR_ENDPOINT = "/v1/repair"


def build_finding(broken: list[dict[str, object]]) -> dict[str, object] | None:
    if not broken:
        return None
    names = [str(item.get("harness")) for item in broken]
    return {
        "code": "hooks_broken",
        "severity": "needs_attention",
        "harnesses": names,
        "message": f"Guard hooks are broken or incomplete for: {', '.join(names)}.",
        "action": {"label": "Repair Guard", "method": "POST", "endpoint": REPAIR_ENDPOINT},
        "cli": "hol-guard repair",
    }


def run_self_check_once(
    store: GuardStore,
    *,
    home_dir: Path | None = None,
    include_leaks: bool = False,
    now: datetime | None = None,
) -> dict[str, object]:
    """One cycle. Returns the status dict published to health details."""

    guard_home = store.guard_home
    context = HarnessContext(
        home_dir=(home_dir or Path.home()).resolve(),
        workspace_dir=None,
        guard_home=guard_home,
    )
    runtime_step = repair_native_runtime(guard_home, dry_run=False)
    steps: dict[str, dict[str, object]] = {"native_runtime": runtime_step}
    if include_leaks:
        steps["onefile_leaks"] = repair_onefile_leaks(dry_run=False, guard_home=guard_home)
    try:
        broken = broken_hook_harnesses(context, store)
        error = None
    except Exception as exc:
        broken, error = [], type(exc).__name__
    return {
        "checked_at": (now or datetime.now(timezone.utc)).isoformat(),
        "hooks_broken": broken,
        "hook_check_error": error,
        "finding": build_finding(broken),
        "steps": {name: {"status": step.get("status"), "summary": step.get("summary")} for name, step in steps.items()},
    }


def start_self_check(
    store: GuardStore,
    *,
    publish: Callable[[dict[str, object]], None],
    stop: threading.Event,
    on_error: Callable[[str], object],
    interval: float = CHECK_INTERVAL_SECONDS,
) -> threading.Thread:
    """Run the check on a daemon thread until ``stop`` is set."""

    def loop() -> None:
        cycle = 0
        if stop.wait(_STARTUP_DELAY_SECONDS):
            return
        while not stop.is_set():
            try:
                # The frozen daemon already reclaims leaks hourly on its own loop.
                leaks = cycle % _LEAK_SCAN_EVERY == 0 and not getattr(sys, "frozen", False)
                publish(run_self_check_once(store, include_leaks=leaks))
            except Exception:
                on_error("repair_self_check_failed")
            cycle += 1
            if stop.wait(interval):
                return

    thread = threading.Thread(target=loop, name="guard-repair-self-check", daemon=True)
    thread.start()
    return thread


__all__ = ["REPAIR_ENDPOINT", "build_finding", "run_self_check_once", "start_self_check"]
