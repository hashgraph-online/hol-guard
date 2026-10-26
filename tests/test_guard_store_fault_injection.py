"""Opt-in fault injection against real GuardStore storage.

These tests kill processes, race concurrent recovery, and block the storage
gate. They are skipped unless GUARD_FAULT_INJECTION=1 and repeat the kill
loop GUARD_FAULT_ITERATIONS times (default 50).
"""

from __future__ import annotations

import os
import random
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.fault_injection

_FAULT_ITERATIONS = int(os.environ.get("GUARD_FAULT_ITERATIONS", "50"))

_CHILD_WRITER = """
import os
import sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore

store = GuardStore(Path(sys.argv[1]), prime_policy_integrity=False)
store.upsert_runtime_state(
    session_id="fault-injection",
    daemon_host="127.0.0.1",
    daemon_port=1,
    started_at="2026-01-01T00:00:00+00:00",
    last_heartbeat_at="2026-01-01T00:00:00+00:00",
)
print("ready", flush=True)
payload = "x" * 4000
iteration = 0
while True:
    iteration += 1
    store.upsert_runtime_state(
        session_id="fault-injection",
        daemon_host="127.0.0.1",
        daemon_port=1,
        started_at="2026-01-01T00:00:00+00:00",
        last_heartbeat_at=f"{payload}{iteration}",
    )
    with store._connect() as connection:
        connection.execute(
            "update guard_runtime_state set last_heartbeat_at = ? where state_key = 'runtime'",
            (f"{payload}{iteration}-raw",),
        )
"""

_CHILD_RECOVER = """
import sqlite3
import sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore

store = GuardStore(Path(sys.argv[1]), prime_policy_integrity=False)
with store._connect() as connection:
    row = connection.execute("pragma quick_check").fetchone()
assert row is not None and row[0] == "ok", row[0]
"""


def _quarantine_bases(guard_home: Path) -> set[str]:
    bases: set[str] = set()
    for entry in guard_home.glob("guard.db.corrupt-*"):
        name = entry.name
        for ending in ("-wal", "-shm", ".forensics.json"):
            if name.endswith(ending):
                name = name[: -len(ending)]
                break
        bases.add(name)
    return bases


def _quick_check(path: Path) -> list[str]:
    with sqlite3.connect(path, timeout=10) as connection:
        return [str(row[0]) for row in connection.execute("pragma quick_check")]


def test_sigkilled_writer_never_leaves_a_malformed_store(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    malformed: list[str] = []
    started = time.monotonic()
    for iteration in range(_FAULT_ITERATIONS):
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", _CHILD_WRITER, str(guard_home)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready = process.stdout.readline() if process.stdout is not None else ""
            assert ready.strip() == "ready", f"child failed to start: {process.stderr.read() if process.stderr else ''}"
            # Kill at a random point inside the write loop.
            time.sleep(random.uniform(0.001, 0.05))
            process.kill()
        finally:
            process.wait(timeout=30)
        database = guard_home / "guard.db"
        if database.exists():
            rows = _quick_check(database)
            if rows != ["ok"]:
                quarantined = sorted(p.name for p in guard_home.glob("guard.db.corrupt-*"))
                malformed.append(f"iteration {iteration}: quick_check={rows[:5]} quarantined={quarantined}")
    elapsed = time.monotonic() - started
    assert not malformed, (
        f"SIGKILL left a malformed store ({_FAULT_ITERATIONS} iterations, {elapsed:.1f}s):\n" + "\n".join(malformed)
    )


def test_concurrent_processes_perform_one_quarantine(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    (guard_home / "guard.db").write_bytes(b"not-a-sqlite-database\x00fault-injection")

    processes = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD_RECOVER, str(guard_home)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    failures = []
    for index, process in enumerate(processes):
        _, stderr = process.communicate(timeout=120)
        if process.returncode != 0:
            failures.append(f"child {index} exited {process.returncode}: {stderr[-500:]}")

    assert not failures, "\n".join(failures)
    assert len(_quarantine_bases(guard_home)) == 1
    forensics = list(guard_home.glob("guard.db.corrupt-*.forensics.json"))
    assert len(forensics) == 1
    assert _quick_check(guard_home / "guard.db") == ["ok"]


def test_exclusive_quarantine_waits_for_heartbeat_shared_gate(tmp_path: Path) -> None:
    """The gated rename hazard: quarantine must wait behind a held shared gate."""

    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    store.path.write_bytes(b"not-a-sqlite-database\x00gate-held")

    gate_held = threading.Event()
    release = threading.Event()

    def hold_shared_gate() -> None:
        with store._try_hold_storage_gate(exclusive=False) as held:  # pyright: ignore[reportPrivateUsage]
            assert held
            gate_held.set()
            assert release.wait(timeout=30)

    holder = threading.Thread(target=hold_shared_gate)
    holder.start()
    assert gate_held.wait(timeout=10)

    recovered: list[bool] = []
    recovery = threading.Thread(
        target=lambda: recovered.append(
            store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
                sqlite3.DatabaseError("database disk image is malformed")
            )
        )
    )
    recovery.start()
    # While the shared gate is held the exclusive quarantine must be blocked —
    # no renamed snapshot may appear.
    time.sleep(0.2)
    assert recovery.is_alive()
    assert _quarantine_bases(tmp_path / "guard") == set()

    release.set()
    holder.join(timeout=10)
    recovery.join(timeout=60)

    assert recovered == [True]
    assert len(_quarantine_bases(tmp_path / "guard")) == 1
    assert _quick_check(store.path) == ["ok"]
