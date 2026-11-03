"""Test-side control of the daemon runtime hook scheduler."""

from __future__ import annotations

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler


def set_active_limit(scheduler: RuntimeHookScheduler, active_limit: int) -> None:
    """Change how many hooks run at once and admit any queued hooks that now fit."""

    if active_limit < 0:
        raise ValueError("runtime hook scheduler active limit must not be negative")
    with scheduler._condition:
        scheduler._active_limit = active_limit
        scheduler._dispatch()
