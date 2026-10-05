"""Cancelled startup must retain every live process until containment succeeds."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_process_creation as creation
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_spawner import spawn_hook_worker


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("boundary", ["isolation", "retirement"])
def test_cancelled_spawn_keeps_actual_worker_owned_when_cleanup_raises(
    tmp_path: Path,
    monkeypatch,
    failure_type,
    boundary,
):
    runner = HookProcessRunner(guard_home=tmp_path / "guard-home", process_limit=1)
    generation = runner._generation
    spawned = []

    def cancelled_spawn(home):
        slot = spawn_hook_worker(home)
        spawned.append(slot)
        with runner._state_lock:
            runner._closed = True
            runner._generation += 1
        return slot

    def interrupted(*_args, **_kwargs):
        raise failure_type("injected cleanup interruption")

    try:
        with monkeypatch.context() as fault:
            if boundary == "isolation":
                fault.setattr(creation, "hook_worker_became_isolated", interrupted)
            else:
                fault.setattr(runner, "_retire_slot", interrupted)
            with pytest.raises(failure_type, match="cleanup interruption"):
                creation.start_hook_worker_slot(
                    runner, generation=generation, spawn=cancelled_spawn, isolation_timeout=1
                )
        assert len(spawned) == 1
        slot = spawned[0]
        assert runner._all_slots.get(slot.process.pid) is slot, "a cancelled live child must remain owned"
        assert runner.stats()["workers"] == 1
    finally:
        # Even the pre-fix counterexample must clean up its exact generated
        # child. Restore only that fixture's lost owner before real retirement.
        # On fixed code this assignment preserves the existing owner unchanged.
        for slot in spawned:
            with runner._state_lock:
                runner._all_slots[slot.process.pid or id(slot)] = slot
        assert runner.close_contained(), "the generated child must be proven contained"
        assert runner.stats()["workers"] == 0
        assert all(not slot.process.is_alive() for slot in spawned)
