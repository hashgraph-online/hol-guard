from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore


def test_fatal_error_requires_two_stable_fatal_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    probes = iter(["fatal", "healthy"])
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.sqlite_recovery._probe_sqlite_store",
        lambda _path: next(probes),
    )

    assert (
        store._store_is_proven_unusable(  # pyright: ignore[reportPrivateUsage]
            sqlite3.DatabaseError("database disk image is malformed")
        )
        is False
    )


@pytest.mark.parametrize("restore_mtime", [False, True])
def test_fatal_error_recovery_rejects_sidecar_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    restore_mtime: bool,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    wal = Path(f"{store.path}-wal")
    wal.write_bytes(b"first")
    original_stat = wal.stat()
    probe_count = 0

    def fatal_probe(_path: Path) -> str:
        nonlocal probe_count
        probe_count += 1
        if probe_count == 1:
            wal.write_bytes(b"other")
            if restore_mtime:
                os.utime(wal, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        return "fatal"

    monkeypatch.setattr("codex_plugin_scanner.guard.sqlite_recovery._probe_sqlite_store", fatal_probe)

    assert (
        store._store_is_proven_unusable(  # pyright: ignore[reportPrivateUsage]
            sqlite3.DatabaseError("database disk image is malformed")
        )
        is False
    )
    assert probe_count == 1
