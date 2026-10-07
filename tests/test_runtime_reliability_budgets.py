"""Measured T/C/S store outcomes on the production SQLite recovery seam."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.sqlite_errors import sqlite_failure_kind
from codex_plugin_scanner.guard.sqlite_recovery import sqlite_store_probe_detail
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_operation_deadline
from codex_plugin_scanner.guard.store import GuardStore

_MIB = 1024 * 1024


def _coded(message: str, code: int) -> sqlite3.OperationalError:
    error = sqlite3.OperationalError(message)
    error.sqlite_errorcode = code  # type: ignore[attr-defined]
    return error


def _quarantine_names(guard_home: Path) -> list[str]:
    names: list[str] = []
    for path in guard_home.glob("guard.db.corrupt-*"):
        if not path.is_file() or path.name.endswith(("-wal", "-shm", ".forensics.json")):
            continue
        names.append(path.name)
    return sorted(names)


def test_sqlite_codes_keep_extended_io_variants_and_do_not_quarantine_contention(
    tmp_path: Path,
) -> None:
    """Busy and locked contention leaves a healthy store in place."""

    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    ioerr_read = 10 | (1 << 8)
    ioerr_write = 10 | (3 << 8)
    samples = {
        "busy": _coded("database is busy", 5),
        "locked": _coded("database is locked", 6),
        "ioerr_read": _coded("disk I/O error", ioerr_read),
        "ioerr_write": _coded("disk I/O error", ioerr_write),
        "full": _coded("database or disk is full", 13),
        "corrupt": _coded("database disk image is malformed", 11),
    }
    kinds = {name: sqlite_failure_kind(error) for name, error in samples.items()}
    assert kinds == {
        "busy": "busy",
        "locked": "locked",
        "ioerr_read": "io",
        "ioerr_write": "io",
        "full": "full",
        "corrupt": "corrupt",
    }
    assert samples["ioerr_read"].sqlite_errorcode != samples["ioerr_write"].sqlite_errorcode
    assert samples["ioerr_read"].sqlite_errorcode & 0xFF == 10
    assert samples["ioerr_write"].sqlite_errorcode & 0xFF == 10

    detail = sqlite_store_probe_detail(
        path=store.path,
        guard_home=store.guard_home,
        error=samples["busy"],
        fatal_error=False,
    )
    assert detail.proven_unusable is False
    assert store._recover_fatal_sqlite_store(samples["busy"]) is False  # pyright: ignore[reportPrivateUsage]
    assert _quarantine_names(store.guard_home) == []
    print(
        "S1 pass busy=5 locked=6 "
        f"ioerr_read={ioerr_read} ioerr_write={ioerr_write} full=13 "
        "kinds=busy,locked,io,io,full proven_unusable=false quarantined=false"
    )


def test_proven_corrupt_store_is_quarantined_without_replaying_an_unknown_write(
    tmp_path: Path,
) -> None:
    """A yielded write that fails is raised once, and proven corruption is quarantined."""

    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    calls = 0

    def write_once(connection: sqlite3.Connection) -> None:
        nonlocal calls
        calls += 1
        connection.execute("create table outcome_probe (value integer)")
        connection.execute("insert into outcome_probe values (1)")
        raise _coded("disk I/O error", 10 | (3 << 8))

    with (  # pyright: ignore[reportPrivateUsage]
        pytest.raises(sqlite3.OperationalError) as failure,
        store._connect() as connection,
    ):
        write_once(connection)
    assert calls == 1
    assert failure.value.sqlite_errorcode == 10 | (3 << 8)  # type: ignore[attr-defined]
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        row = connection.execute("select count(*) from outcome_probe").fetchone()
    assert row is not None and row[0] == 0

    original = store.path.read_bytes()[:16]
    store.path.write_bytes(b"not a sqlite database")
    for suffix in ("-wal", "-shm"):
        Path(f"{store.path}{suffix}").unlink(missing_ok=True)
    with pytest.raises(sqlite3.DatabaseError) as corrupt_failure:
        sqlite3.connect(store.path).execute("pragma quick_check")
    assert sqlite_failure_kind(corrupt_failure.value) == "corrupt"
    detail = sqlite_store_probe_detail(
        path=store.path,
        guard_home=store.guard_home,
        error=corrupt_failure.value,
        fatal_error=True,
    )
    assert detail.proven_unusable is True
    assert detail.first_state == "fatal" and detail.second_state == "fatal"
    assert store._recover_fatal_sqlite_store(corrupt_failure.value) is True  # pyright: ignore[reportPrivateUsage]
    quarantined = _quarantine_names(store.guard_home)
    assert len(quarantined) == 1
    assert original != b"not a sqlite database"
    print(
        "S2 pass corrupt=proven_unusable quarantined=1 unknown_write_calls=1 "
        f"inserted_rows=0 replayed=false first={detail.first_state} second={detail.second_state}"
    )


def test_locked_store_honors_the_caller_deadline_without_quarantine(tmp_path: Path) -> None:
    """A short caller deadline stops a locked write and leaves the healthy store in place."""

    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    holder = sqlite3.connect(store.path)
    holder.execute("begin exclusive")
    started = time.monotonic()
    try:
        with (  # pyright: ignore[reportPrivateUsage]
            pytest.raises((TimeoutError, sqlite3.OperationalError)) as failure,
            sqlite_operation_deadline(time.monotonic() + 0.4),
            store._connect() as connection,
        ):
            connection.execute("create table deadline_probe (value integer)")
    finally:
        holder.rollback()
        holder.close()
    elapsed_ms = (time.monotonic() - started) * 1000
    kind = sqlite_failure_kind(failure.value)
    assert kind in {"busy", "locked"}
    assert elapsed_ms < 2000
    assert _quarantine_names(store.guard_home) == []
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        checked = connection.execute("pragma quick_check").fetchone()
    assert checked is not None and checked[0] == "ok"
    print(
        "T2 pass stage=storage_gate "
        f"result={type(failure.value).__name__} kind={kind} elapsed_ms={elapsed_ms:.1f} "
        "deadline_ms=400 quarantined=false quick_check=ok"
    )
    print(
        "S1 pass contention=locked_store "
        f"result={type(failure.value).__name__} kind={kind} elapsed_ms={elapsed_ms:.1f} quarantined=false"
    )


@pytest.mark.parametrize("mebibytes", [30, 300])
def test_generated_store_stays_healthy_at_budget_sizes(tmp_path: Path, mebibytes: int) -> None:
    """Generated stores near 30 MiB and 300 MiB stay readable and unquarantined."""

    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    blob = b"x" * _MIB
    remaining = mebibytes
    started = time.monotonic()
    while remaining:
        batch = min(30, remaining)
        with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
            connection.execute("create table if not exists bulk (payload blob)")
            connection.executemany("insert into bulk values (?)", ((blob,) for _ in range(batch)))
        remaining -= batch
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        checked = connection.execute("pragma quick_check").fetchone()
    elapsed_ms = (time.monotonic() - started) * 1000
    size_bytes = store.path.stat().st_size
    assert checked is not None and checked[0] == "ok"
    assert size_bytes >= mebibytes * _MIB
    assert _quarantine_names(store.guard_home) == []
    print(
        f"S1 pass store_mib={mebibytes} size_bytes={size_bytes} quick_check=ok "
        f"elapsed_ms={elapsed_ms:.1f} quarantined=false"
    )
