"""Ownership-aware creation of isolated hook workers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from .hook_process_spawner import hook_worker_became_isolated
from .hook_process_worker import HookWorkerSlot

if TYPE_CHECKING:
    from .hook_process_runner import HookProcessRunner


def start_hook_worker_slot(
    runner: HookProcessRunner,
    *,
    generation: int,
    spawn: Callable[[Path | None], HookWorkerSlot],
    isolation_timeout: float,
) -> HookWorkerSlot:
    """Create and register one slot without allowing close to split ownership."""

    with runner._process_creation_lock:
        with runner._state_lock:
            if runner._closed or generation != runner._generation:
                raise RuntimeError("hook worker creation cancelled")
        slot = spawn(runner._guard_home)
        process = slot.process
        with runner._state_lock:
            stale = runner._closed or generation != runner._generation
            if not stale:
                runner._all_slots[process.pid or id(slot)] = slot
        if stale:
            _ = hook_worker_became_isolated(slot, isolation_timeout)
            if not runner._retire_slot(slot):
                with runner._state_lock:
                    runner._all_slots[process.pid or id(slot)] = slot
                runner._mark_containment_failed()
        return slot


__all__ = ["start_hook_worker_slot"]
