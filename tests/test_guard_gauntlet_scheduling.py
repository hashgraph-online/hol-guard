"""Scheduling-order, host-slot capacity and load-gate tests for ``--jobs``. No live inference is started."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet import parallel
from tests.test_guard_gauntlet_parallel import FakeWorker, _no_sleep


def test_spawn_order_follows_the_order_parameter() -> None:
    spawned: list[str] = []
    results = parallel.run_scheduled(
        list("abcd"),
        jobs=4,
        spawn=lambda name: (spawned.append(name), FakeWorker(name, [], 1))[1],
        order=[2, 0, 3, 1],
        sleep=_no_sleep,
    )
    assert spawned == ["c", "a", "d", "b"]
    assert results == ["a", "b", "c", "d"]


@pytest.mark.parametrize("order", [[0, 0], [0, 2], [1], ["a", "b"]])
def test_order_must_be_a_permutation_of_item_indices(order: Any) -> None:
    with pytest.raises(ValueError):
        parallel.run_scheduled(["a", "b"], jobs=1, spawn=lambda n: FakeWorker(n, [], 1), order=order)


def test_should_stop_drains_inflight_and_returns_none_for_unrun() -> None:
    log: list[str] = []
    workers = {"a": FakeWorker("a", log, 1), "b": FakeWorker("b", log, 3), "c": FakeWorker("c", log, 99)}
    spawned: list[str] = []

    def spawn(name: str) -> FakeWorker:
        spawned.append(name)
        return workers[name]

    results = parallel.run_scheduled(
        list(workers),
        jobs=2,
        spawn=spawn,
        sleep=_no_sleep,
        grace=0.0,
        should_stop=lambda _index, result: result == "a",
    )
    # c never starts; b finishes naturally instead of being terminated.
    assert results == ["a", "b", None]
    assert spawned == ["a", "b"]
    assert not any(line.startswith(("terminate:", "kill:")) for line in log)


def test_admit_gate_defers_spawn_until_load_drops() -> None:
    loads = iter([10.0, 10.0, 1.0, 1.0, 1.0])
    notes: list[str] = []
    gate = parallel.LoadGate(4.0, load=lambda: (next(loads, 1.0), 0.0, 0.0), notify=notes.append)
    results = parallel.run_scheduled(["a"], jobs=1, spawn=lambda n: FakeWorker(n, [], 1), admit=gate, sleep=_no_sleep)
    assert results == ["a"]
    assert notes == ["gauntlet: waiting for host load 10 <= 4", "gauntlet: host load 1 <= 4; resuming"]


def test_load_gate_reports_once_per_wait_episode() -> None:
    lines: list[str] = []
    values = iter([9.0, 9.0, 3.0, 8.0, 8.0, 2.0])
    gate = parallel.LoadGate(4.0, load=lambda: (next(values), 0.0, 0.0), notify=lines.append)
    assert [gate() for _ in range(6)] == [False, False, True, False, False, True]
    assert lines == [
        "gauntlet: waiting for host load 9 <= 4",
        "gauntlet: host load 3 <= 4; resuming",
        "gauntlet: waiting for host load 8 <= 4",
        "gauntlet: host load 2 <= 4; resuming",
    ]


def test_load_gate_proceeds_once_the_wait_budget_is_spent() -> None:
    now = [0.0]
    lines: list[str] = []
    gate = parallel.LoadGate(
        4.0, max_wait=600.0, clock=lambda: now[0], load=lambda: (9.0, 0.0, 0.0), notify=lines.append
    )
    assert gate() is False
    now[0] = 599.9
    assert gate() is False
    now[0] = 600.0
    assert gate() is True
    # The budget is spent: the gate admits unconditionally without notifying again.
    assert gate() is True
    assert lines == [
        "gauntlet: waiting for host load 9 <= 4",
        "gauntlet: host load still 9; waited 600s, proceeding",
    ]


def test_load_gate_budget_is_cumulative_across_episodes() -> None:
    now = [0.0]
    load = [9.0]
    lines: list[str] = []
    gate = parallel.LoadGate(
        4.0, max_wait=10.0, clock=lambda: now[0], load=lambda: (load[0], 0.0, 0.0), notify=lines.append
    )
    assert gate() is False
    now[0] = 7.0
    load[0] = 1.0
    assert gate() is True  # episode one banked seven blocked seconds
    load[0] = 9.0
    now[0] = 20.0
    assert gate() is False  # episode two resumes the same budget at 7s spent
    now[0] = 23.0
    assert gate() is True  # three more seconds exhaust the cumulative 10s
    assert lines == [
        "gauntlet: waiting for host load 9 <= 4",
        "gauntlet: host load 1 <= 4; resuming",
        "gauntlet: waiting for host load 9 <= 4",
        "gauntlet: host load still 9; waited 10s, proceeding",
    ]


def test_load_gate_admits_normally_before_the_budget() -> None:
    now = [0.0]
    load = [9.0]
    lines: list[str] = []
    gate = parallel.LoadGate(
        4.0, max_wait=10.0, clock=lambda: now[0], load=lambda: (load[0], 0.0, 0.0), notify=lines.append
    )
    assert gate() is False
    now[0] = 5.0
    load[0] = 1.0
    assert gate() is True
    assert lines == ["gauntlet: waiting for host load 9 <= 4", "gauntlet: host load 1 <= 4; resuming"]


@pytest.mark.skipif(os.name != "posix", reason="flock host slots")
def test_host_slots_share_one_inventory_and_release_on_collect(tmp_path: Path) -> None:
    slots_dir = tmp_path / "slots"
    holder = parallel.HostSlots(slots_dir, 2)
    held = holder.try_acquire()
    assert held is not None
    slots = parallel.HostSlots(slots_dir, 2)
    live: list[FakeWorker] = []
    peak = 0

    def spawn(name: str, _lease: parallel.Lease | None = None) -> FakeWorker:
        nonlocal peak
        worker = FakeWorker(name, [], 2)
        live.append(worker)
        peak = max(peak, sum(w.state == "running" for w in live))
        return worker

    results = parallel.run_scheduled(list("abc"), jobs=3, spawn=spawn, sleep=_no_sleep, slots=slots)
    assert results == ["a", "b", "c"]
    # One slot is held by ``holder`` the entire run, so at most one case runs.
    assert peak == 1
    # Collected leases are released: one slot is free while ``held`` pins the other.
    extra = slots.try_acquire()
    assert extra is not None and slots.try_acquire() is None
    extra.release()
    held.release()
    assert slots.try_acquire() is not None


@pytest.mark.skipif(os.name != "posix", reason="flock host slots")
def test_host_slot_leases_survive_cancel_and_spawn_failure(tmp_path: Path) -> None:
    slots_dir = tmp_path / "slots"
    holder = parallel.HostSlots(slots_dir, 3)
    slots = parallel.HostSlots(slots_dir, 3)
    log: list[str] = []
    with pytest.raises(KeyboardInterrupt):
        parallel.run_scheduled(
            ["a", "b"],
            jobs=2,
            spawn=lambda n, _lease: FakeWorker(n, log, 99),
            sleep=lambda _s: (_ for _ in ()).throw(KeyboardInterrupt()),
            grace=0.0,
            slots=slots,
        )
    # Killed workers' leases are released: all three slots are free again.
    held = [holder.try_acquire() for _ in range(3)]
    assert all(lease is not None for lease in held) and holder.try_acquire() is None
    for lease in held:
        lease.release()

    def spawn(name: str, _lease: parallel.Lease | None = None) -> FakeWorker:
        raise OSError("cannot start")

    with pytest.raises(OSError):
        parallel.run_scheduled(["x"], jobs=1, spawn=spawn, sleep=_no_sleep, slots=slots)
    lease = slots.try_acquire()
    assert lease is not None
    lease.release()


@pytest.mark.skipif(os.name != "posix", reason="flock host slots")
def test_host_slots_validation_and_idempotent_release(tmp_path: Path) -> None:
    for count in (0, -1, parallel.MAX_SLOTS + 1, True):
        with pytest.raises(ValueError):
            parallel.HostSlots(tmp_path / f"s{count}", count)
    slots = parallel.HostSlots(tmp_path / "slots", 1)
    lease = slots.try_acquire()
    assert lease is not None and slots.try_acquire() is None
    lease.release()
    lease.release()
    assert slots.acquire(sleep=_no_sleep) is not None


@pytest.mark.skipif(os.name != "posix", reason="flock host slots")
def test_host_slots_follow_the_latest_shared_capacity(tmp_path: Path) -> None:
    slots_dir = tmp_path / "slots"
    narrow = parallel.HostSlots(slots_dir, 4)
    parallel.HostSlots(slots_dir, 8)  # the latest requester sets the shared pool
    # Every holder now probes the widened pool: slots 4-7 are available to A too.
    held = [narrow.try_acquire() for _ in range(8)]
    assert all(lease is not None for lease in held)
    assert narrow.try_acquire() is None
    # A lowered pool only throttles new acquisitions; existing holders drain.
    low = parallel.HostSlots(slots_dir, 2)
    assert low.try_acquire() is None
    for lease in held[:4]:
        lease.release()
    freed = [low.try_acquire() for _ in range(3)]
    assert freed[0] is not None and freed[1] is not None
    assert freed[2] is None
    for lease in [*freed[:2], *held[4:]]:
        lease.release()


@pytest.mark.skipif(os.name != "posix", reason="flock host slots")
def test_host_slots_create_a_private_directory_tree(tmp_path: Path) -> None:
    slots_dir = tmp_path / "nested" / "slots"
    parallel.HostSlots(slots_dir, 1)
    for level in (tmp_path / "nested", slots_dir):
        assert (level.stat().st_mode & 0o777) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="flock host slots")
def test_slot_stays_held_while_a_child_keeps_the_lease_fd(tmp_path: Path) -> None:
    slots_dir = tmp_path / "slots"
    slots = parallel.HostSlots(slots_dir, 1)
    lease = slots.try_acquire()
    assert lease is not None and lease.fd is not None
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], pass_fds=(lease.fd,))
    try:
        lease.release()
        assert slots.try_acquire() is None
    finally:
        child.terminate()
        child.wait(timeout=30)
    freed = slots.try_acquire()
    assert freed is not None
    freed.release()


@pytest.mark.skipif(os.name != "posix", reason="flock host slots")
def test_host_slots_fall_back_to_their_own_count_when_capacity_is_invalid(tmp_path: Path) -> None:
    slots_dir = tmp_path / "slots"
    slots = parallel.HostSlots(slots_dir, 2)
    (slots_dir / "capacity").write_text("garbage", encoding="utf-8")
    held = [slots.try_acquire() for _ in range(2)]
    assert all(lease is not None for lease in held)
    assert slots.try_acquire() is None
    for lease in held:
        lease.release()
    (slots_dir / "capacity").unlink()
    assert slots.try_acquire() is not None
