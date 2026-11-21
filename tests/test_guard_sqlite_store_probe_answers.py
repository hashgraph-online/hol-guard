from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import sqlite_recovery
from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_operation_deadline


@pytest.mark.parametrize("op", ["detail", "restore"])
def test_store_probe_obeys_the_operation_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    op: str,
) -> None:
    requests: list[dict[str, object]] = []
    deadlines: list[float] = []

    def answer(_feature: str, _command: str, request: dict[str, object], **kwargs: float) -> dict[str, object]:
        requests.append(request)
        deadlines.append(kwargs["deadline"])
        return {"restored": False}

    monkeypatch.setattr(runtime_request, "runtime_answer", answer)

    def probe() -> None:
        if op == "detail":
            _ = sqlite_recovery.sqlite_store_probe_detail(
                path=tmp_path / "guard.db",
                guard_home=tmp_path,
                error=sqlite3.DatabaseError("database disk image is malformed"),
                fatal_error=True,
            )
        else:
            _ = sqlite_recovery.restore_readable_sqlite_store(
                destination=tmp_path / "guard.db", quarantined=tmp_path / "guard.db.corrupt-1"
            )

    with sqlite_operation_deadline(time.monotonic() - 1), pytest.raises(TimeoutError, match="deadline expired"):
        probe()
    assert requests == []

    operation_deadline = time.monotonic() + 2
    with sqlite_operation_deadline(operation_deadline):
        probe()
    assert [request["op"] for request in requests] == [op]
    wait = requests[0]["wait_seconds"]
    assert isinstance(wait, float) and 0 < wait <= 2
    assert deadlines == [operation_deadline]


def test_unanswered_store_probe_proves_nothing_and_restores_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: None)
    quarantined = tmp_path / "guard.db.corrupt-1"
    quarantined.write_bytes(b"store")

    detail = sqlite_recovery.sqlite_store_probe_detail(
        path=tmp_path / "guard.db",
        guard_home=tmp_path,
        error=sqlite3.DatabaseError("database disk image is malformed"),
        fatal_error=True,
    )
    assert detail.proven_unusable is False
    assert (
        sqlite_recovery.restore_readable_sqlite_store(destination=tmp_path / "guard.db", quarantined=quarantined)
        is False
    )

    # A lost answer after the native move still reports the restore.
    quarantined.replace(tmp_path / "guard.db")
    assert (
        sqlite_recovery.restore_readable_sqlite_store(destination=tmp_path / "guard.db", quarantined=quarantined)
        is True
    )


def test_lost_restore_answer_returns_sidecars_moved_ahead_of_the_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: None)
    destination = tmp_path / "guard.db"
    quarantined = tmp_path / "guard.db.corrupt-1"
    quarantined.write_bytes(b"store")
    Path(f"{quarantined}-shm").write_bytes(b"shm")
    # The helper moved the WAL and stopped before the shared memory and store.
    Path(f"{destination}-wal").write_bytes(b"wal")

    assert sqlite_recovery.restore_readable_sqlite_store(destination=destination, quarantined=quarantined) is False

    assert Path(f"{quarantined}-wal").read_bytes() == b"wal"
    assert Path(f"{quarantined}-shm").read_bytes() == b"shm"
    assert not Path(f"{destination}-wal").exists() and not destination.exists()


def test_unanswered_store_probe_removes_the_write_probe_it_left(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: None)
    for name in ("storage-probe-ab.db", "storage-probe-ab.db-journal"):
        (tmp_path / name).write_bytes(b"")
    (tmp_path / "guard.db").write_bytes(b"store")

    detail = sqlite_recovery.sqlite_store_probe_detail(
        path=tmp_path / "guard.db",
        guard_home=tmp_path,
        error=sqlite3.DatabaseError("database disk image is malformed"),
        fatal_error=True,
    )

    assert detail.proven_unusable is False
    assert sorted(path.name for path in tmp_path.iterdir()) == ["guard.db"]
