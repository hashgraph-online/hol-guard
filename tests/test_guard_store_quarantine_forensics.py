"""Forensic records written when a Guard store is quarantined."""

from __future__ import annotations

import json
import sqlite3
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.store import GuardStore


def _corrupt_store(path: Path) -> bytes:
    corrupt_bytes = b"not-a-sqlite-database\x00guard-recovery-fixture"
    path.write_bytes(corrupt_bytes)
    return corrupt_bytes


def _quarantined_databases(guard_home: Path) -> list[Path]:
    return sorted(path for path in guard_home.glob("guard.db.corrupt-*") if not path.name.endswith(".forensics.json"))


def _forensics_records(guard_home: Path) -> list[Path]:
    return sorted(guard_home.glob("guard.db.corrupt-*.forensics.json"))


def test_quarantine_writes_an_owner_only_forensics_record(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    corrupt_bytes = _corrupt_store(guard_home / "guard.db")

    GuardStore(guard_home, prime_policy_integrity=False)

    records = _forensics_records(guard_home)
    assert len(records) == 1
    record = records[0]
    assert stat.S_IMODE(record.stat().st_mode) == 0o600
    payload = json.loads(record.read_text(encoding="utf-8"))
    assert payload["schema"] == "guard.store-quarantine-forensics.v1"
    quarantined = _quarantined_databases(guard_home)
    assert len(quarantined) == 1
    assert record.name == f"{quarantined[0].name}.forensics.json"
    assert payload["quarantine_id"] in quarantined[0].name
    assert payload["quarantined_at"]
    assert payload["error_class"] in {"DatabaseError", "OperationalError"}
    assert payload["outcome"] in {"restored", "reinitialized", "reinitialized_salvaged"}
    probe = payload["probe"]
    assert probe["first_state"] == "fatal"
    assert probe["guard_home_accepts_write"] is True
    files = payload["files"]
    assert files["db"]["size"] == len(corrupt_bytes)
    assert set(files["db"]) == {"size", "dev", "ino", "mtime_ns"}
    assert isinstance(payload["pid"], int)
    assert payload["guard_version"]
    # Forensics must never leak absolute paths.
    assert str(guard_home) not in record.read_text(encoding="utf-8")


def test_recovery_runs_a_single_probe_sequence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    _corrupt_store(guard_home / "guard.db")

    calls = 0
    original = store_connection_schema.sqlite_store_probe_detail

    def counted(**kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(**kwargs)

    monkeypatch.setattr(store_connection_schema, "sqlite_store_probe_detail", counted)
    GuardStore(guard_home, prime_policy_integrity=False)

    assert calls == 1


def test_forensics_error_message_redacts_guard_home(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    from codex_plugin_scanner.guard.sqlite_quarantine_forensics import write_quarantine_forensics
    from codex_plugin_scanner.guard.sqlite_recovery import SQLiteStoreProbeDetail

    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    write_quarantine_forensics(
        guard_home=guard_home,
        quarantine_id="20260101T000000000000Z-test",
        quarantined_at=datetime.now(timezone.utc),
        error=sqlite3.DatabaseError(f"{guard_home}/guard.db: database disk image is malformed"),
        probe=SQLiteStoreProbeDetail(
            proven_unusable=True,
            first_state="fatal",
            second_state="fatal",
            guard_home_accepts_write=True,
            identity_stable=True,
        ),
        files={},
    )

    record = guard_home / "guard.db.corrupt-20260101T000000000000Z-test.forensics.json"
    payload = json.loads(record.read_text(encoding="utf-8"))
    assert payload["error_message"] == "<guard_home>/guard.db: database disk image is malformed"
    assert str(guard_home) not in payload["error_message"]
    assert stat.S_IMODE(record.stat().st_mode) == 0o600


def test_forensics_write_failure_does_not_block_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    corrupt_bytes = _corrupt_store(guard_home / "guard.db")

    monkeypatch.setattr(
        store_connection_schema,
        "write_quarantine_forensics",
        lambda **kwargs: (_ for _ in ()).throw(OSError("forensics volume full")),
    )

    store = GuardStore(guard_home, prime_policy_integrity=False)

    quarantined = _quarantined_databases(guard_home)
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == corrupt_bytes
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma quick_check").fetchone() == ("ok",)


def test_restored_recovery_marks_the_forensics_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    monkeypatch.setattr(store, "_store_is_proven_unusable", lambda _error: True)

    recovered = store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
        sqlite3.DatabaseError("database disk image is malformed")
    )

    assert recovered is True
    records = _forensics_records(store.guard_home)
    assert len(records) == 1
    payload = json.loads(records[0].read_text(encoding="utf-8"))
    assert payload["outcome"] == "restored"
    # A monkeypatched decision supplies no probe detail, so the record is null.
    assert payload["probe"] is None


def test_forensics_record_header_diagnosis_and_sqlite_version(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    page = bytearray(4096)
    page[0:8] = bytes([0x0D, 0, 0, 0, 1, 0x0F, 0x85, 0])
    (guard_home / "guard.db").write_bytes(bytes(page) * 3)

    GuardStore(guard_home, prime_policy_integrity=False)

    record = json.loads(_forensics_records(guard_home)[0].read_text(encoding="utf-8"))
    assert record["sqlite_version"] == sqlite3.sqlite_version
    assert isinstance(record["sqlite_wal_reset_bug_possible"], bool)
    assert record["header"]["header_magic_ok"] is False
    assert record["header"]["page1_looks_like_btree_page"] == "leaf-table"
    assert record["header"]["file_size"] == 3 * 4096


def test_header_diagnosis_accepts_a_real_database_and_flags_zeroed_files(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.sqlite_quarantine_forensics import (
        sqlite_header_diagnosis,
        sqlite_wal_reset_bug_possible,
    )

    good = tmp_path / "good.db"
    with sqlite3.connect(good) as connection:
        connection.execute("create table t (v integer)")
    diagnosis = sqlite_header_diagnosis(good)
    assert diagnosis["header_magic_ok"] is True
    assert diagnosis["size_multiple_of_page"] is True
    assert "page1_looks_like_btree_page" not in diagnosis

    zeroed = tmp_path / "zero.db"
    zeroed.write_bytes(bytes(4096))
    assert sqlite_header_diagnosis(zeroed)["header_zeroed"] is True
    assert sqlite_header_diagnosis(tmp_path / "missing.db") == {}
    assert sqlite_wal_reset_bug_possible((3, 45, 0)) is True
    assert sqlite_wal_reset_bug_possible((3, 51, 3)) is False
