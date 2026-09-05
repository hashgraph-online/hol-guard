"""Quarantined store snapshots must not accumulate for the life of the install."""

from __future__ import annotations

import os
from pathlib import Path

from codex_plugin_scanner.guard.sqlite_recovery import prune_quarantined_store_snapshots
from codex_plugin_scanner.guard.update_staging import prune_stale_update_staging


def _write_snapshot(guard_home: Path, name: str, *, age_seconds: int = 0) -> None:
    path = guard_home / name
    path.write_bytes(b"snapshot")
    stamp = path.stat().st_mtime - age_seconds
    os.utime(path, (stamp, stamp))


def test_prune_keeps_the_newest_two_quarantine_events(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-a", age_seconds=500)
    _write_snapshot(tmp_path, "guard.db.corrupt-a-wal", age_seconds=500)
    _write_snapshot(tmp_path, "guard.db.corrupt-b", age_seconds=300)
    _write_snapshot(tmp_path, "guard.db.corrupt-c", age_seconds=100)
    _write_snapshot(tmp_path, "guard.db.corrupt-c-shm", age_seconds=100)
    _write_snapshot(tmp_path, "guard.db.corrupt-d", age_seconds=50)
    (tmp_path / "guard.db").write_bytes(b"live")

    removed = prune_quarantined_store_snapshots(tmp_path, keep=2)

    # Event "a" removes its base plus -wal sidecar, event "b" its base.
    assert removed == 3
    assert not (tmp_path / "guard.db.corrupt-a").exists()
    assert not (tmp_path / "guard.db.corrupt-a-wal").exists()
    assert not (tmp_path / "guard.db.corrupt-b").exists()
    # The two newest events survive with their sidecars, for support.
    assert (tmp_path / "guard.db.corrupt-c").exists()
    assert (tmp_path / "guard.db.corrupt-c-shm").exists()
    assert (tmp_path / "guard.db.corrupt-d").exists()
    # The live database is never touched.
    assert (tmp_path / "guard.db").read_bytes() == b"live"


def test_prune_is_a_noop_below_the_retention_count(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-only")

    assert prune_quarantined_store_snapshots(tmp_path, keep=2) == 0
    assert (tmp_path / "guard.db.corrupt-only").exists()


def test_prune_ignores_missing_directory_and_symlinks(tmp_path: Path) -> None:
    assert prune_quarantined_store_snapshots(tmp_path / "does-not-exist") == 0

    _write_snapshot(tmp_path, "guard.db.corrupt-real")
    link = tmp_path / "guard.db.corrupt-link"
    link.symlink_to(tmp_path / "guard.db.corrupt-real")
    _write_snapshot(tmp_path, "guard.db.corrupt-new", age_seconds=1)

    prune_quarantined_store_snapshots(tmp_path, keep=1)

    # The symlink is never followed or deleted through the retention sweep.
    assert link.is_symlink()


def _age(path: Path, *, age_seconds: int) -> None:
    stamp = path.stat().st_mtime - age_seconds
    os.utime(path, (stamp, stamp))


def test_stale_update_staging_is_pruned_but_recent_staging_stays(tmp_path: Path) -> None:
    runtime = tmp_path / "guard-home" / "update-runtime"
    stale_home = runtime / "home" / "Library"
    fresh_tmp = runtime / "tmp" / "in-flight"
    stale_wheels = runtime / "wheels" / "artifact-stale"
    fresh_wheels = runtime / "wheels" / "artifact-fresh"
    for directory in (stale_home, fresh_tmp, stale_wheels, fresh_wheels):
        directory.mkdir(parents=True)
    stale_home.joinpath("cache.db").write_bytes(b"stale")
    stale_wheels.joinpath("hol_guard.whl").write_bytes(b"stale")
    fresh_tmp.joinpath("partial.tmp").write_bytes(b"fresh")
    fresh_wheels.joinpath("hol_guard.whl").write_bytes(b"fresh")
    for stale in (stale_home, stale_wheels):
        _age(stale, age_seconds=8 * 24 * 60 * 60)

    prune_stale_update_staging(tmp_path / "guard-home")

    assert not stale_home.exists()
    assert not stale_wheels.exists()
    # Recent staging — an update that is still running — is never touched.
    assert fresh_tmp.joinpath("partial.tmp").read_bytes() == b"fresh"
    assert fresh_wheels.joinpath("hol_guard.whl").read_bytes() == b"fresh"


def test_stale_update_staging_prune_tolerates_missing_directories(tmp_path: Path) -> None:
    prune_stale_update_staging(tmp_path / "guard-home")
    assert not (tmp_path / "guard-home").exists()
