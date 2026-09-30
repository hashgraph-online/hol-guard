"""Quarantined store snapshots must not accumulate for the life of the install."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from codex_plugin_scanner.guard.sqlite_recovery import (
    prune_quarantined_store_snapshots,
    quarantined_store_summary,
)
from codex_plugin_scanner.guard.update_staging import prune_stale_update_staging


def _write_snapshot(guard_home: Path, name: str, *, age_seconds: int = 0, size: int = 8) -> Path:
    path = guard_home / name
    path.write_bytes(b"snapshot"[:size] if size <= 8 else b"s" * size)
    stamp = path.stat().st_mtime - age_seconds
    os.utime(path, (stamp, stamp))
    return path


def test_prune_keeps_the_newest_two_quarantine_events(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-a", age_seconds=500)
    _write_snapshot(tmp_path, "guard.db.corrupt-a-wal", age_seconds=500)
    _write_snapshot(tmp_path, "guard.db.corrupt-b", age_seconds=300)
    _write_snapshot(tmp_path, "guard.db.corrupt-c", age_seconds=100)
    _write_snapshot(tmp_path, "guard.db.corrupt-c-shm", age_seconds=100)
    _write_snapshot(tmp_path, "guard.db.corrupt-d", age_seconds=50)
    (tmp_path / "guard.db").write_bytes(b"live")

    removed = prune_quarantined_store_snapshots(tmp_path, min_keep=2, max_age=timedelta(seconds=0))

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

    assert prune_quarantined_store_snapshots(tmp_path, min_keep=2) == 0
    assert (tmp_path / "guard.db.corrupt-only").exists()


def test_prune_ignores_missing_directory_and_symlinks(tmp_path: Path) -> None:
    assert prune_quarantined_store_snapshots(tmp_path / "does-not-exist") == 0

    _write_snapshot(tmp_path, "guard.db.corrupt-real")
    link = tmp_path / "guard.db.corrupt-link"
    link.symlink_to(tmp_path / "guard.db.corrupt-real")
    _write_snapshot(tmp_path, "guard.db.corrupt-new", age_seconds=1)

    prune_quarantined_store_snapshots(tmp_path, min_keep=1, max_age=timedelta(seconds=0))

    # The symlink is never followed or deleted through the retention sweep.
    assert link.is_symlink()


def test_prune_keeps_recent_events_within_age_and_budget(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-old", age_seconds=10 * 24 * 60 * 60)
    _write_snapshot(tmp_path, "guard.db.corrupt-recent-a", age_seconds=100)
    _write_snapshot(tmp_path, "guard.db.corrupt-recent-b", age_seconds=200)
    _write_snapshot(tmp_path, "guard.db.corrupt-new", age_seconds=0)

    # min_keep=1 protects only the newest; the two recent events stay because
    # they are inside max_age and the byte budget, while the aged-out event
    # is swept.
    removed = prune_quarantined_store_snapshots(
        tmp_path,
        min_keep=1,
        max_age=timedelta(days=7),
    )

    assert removed == 1
    assert not (tmp_path / "guard.db.corrupt-old").exists()
    assert (tmp_path / "guard.db.corrupt-recent-a").exists()
    assert (tmp_path / "guard.db.corrupt-recent-b").exists()
    assert (tmp_path / "guard.db.corrupt-new").exists()


def test_prune_evicts_events_over_the_byte_budget(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-new", age_seconds=0, size=100)
    _write_snapshot(tmp_path, "guard.db.corrupt-middle", age_seconds=10, size=100)
    _write_snapshot(tmp_path, "guard.db.corrupt-oldest", age_seconds=20, size=100)

    # min_keep=1 keeps the newest; the budget of 250 bytes then admits the
    # 100-byte middle event but not the oldest.
    removed = prune_quarantined_store_snapshots(
        tmp_path,
        min_keep=1,
        max_age=timedelta(days=7),
        max_total_bytes=250,
    )

    assert removed == 1
    assert (tmp_path / "guard.db.corrupt-new").exists()
    assert (tmp_path / "guard.db.corrupt-middle").exists()
    assert not (tmp_path / "guard.db.corrupt-oldest").exists()


def test_prune_never_deletes_forensics_records(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-old", age_seconds=60)
    _write_snapshot(tmp_path, "guard.db.corrupt-old-wal", age_seconds=60)
    _write_snapshot(tmp_path, "guard.db.corrupt-old.forensics.json", age_seconds=60)
    _write_snapshot(tmp_path, "guard.db.corrupt-new", age_seconds=0)

    removed = prune_quarantined_store_snapshots(tmp_path, min_keep=1, max_age=timedelta(seconds=0))

    assert removed == 2
    assert not (tmp_path / "guard.db.corrupt-old").exists()
    assert not (tmp_path / "guard.db.corrupt-old-wal").exists()
    # The forensic record belongs to the swept event but always survives.
    assert (tmp_path / "guard.db.corrupt-old.forensics.json").exists()


def test_quarantined_store_summary_reports_events_and_forensics(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-20260101T000000000000Z-aaa", age_seconds=0, size=16)
    _write_snapshot(tmp_path, "guard.db.corrupt-20260101T000000000000Z-aaa-wal", age_seconds=0, size=8)
    _write_snapshot(tmp_path, "guard.db.corrupt-20260101T000000000000Z-aaa.forensics.json", age_seconds=0, size=4)
    _write_snapshot(tmp_path, "guard.db.corrupt-20260905T132908303335Z-bbb", age_seconds=0, size=32)
    _write_snapshot(tmp_path, "guard.db.corrupt-20260905T132908303335Z-bbb.forensics.json", age_seconds=0, size=4)
    (tmp_path / "guard.db").write_bytes(b"live")

    summary = quarantined_store_summary(tmp_path)

    assert summary["count"] == 2
    assert summary["total_bytes"] == 16 + 8 + 4 + 32 + 4
    assert summary["forensic_record_count"] == 2
    assert str(summary["newest_quarantined_at"]).startswith("2026-09-05")


def test_quarantined_store_summary_handles_an_empty_guard_home(tmp_path: Path) -> None:
    summary = quarantined_store_summary(tmp_path / "missing")

    assert summary == {
        "count": 0,
        "total_bytes": 0,
        "newest_quarantined_at": None,
        "forensic_record_count": 0,
    }


def test_prune_orders_events_by_quarantine_stamp_not_file_mtime(tmp_path: Path) -> None:
    # Path.replace preserves the source database's mtime, so a freshly
    # quarantined long-idle database must not sort older than an earlier
    # event whose database was written until it died.
    _write_snapshot(tmp_path, "guard.db.corrupt-20260101T000000000000Z-old-event", age_seconds=0)
    _write_snapshot(tmp_path, "guard.db.corrupt-20260905T132908303335Z-new-event", age_seconds=30 * 24 * 60 * 60)

    prune_quarantined_store_snapshots(tmp_path, min_keep=1, max_age=timedelta(seconds=0))

    assert (tmp_path / "guard.db.corrupt-20260905T132908303335Z-new-event").exists()
    assert not (tmp_path / "guard.db.corrupt-20260101T000000000000Z-old-event").exists()


def test_prune_keeps_unstamped_snapshots_furthest_back(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-20260905T132908303335Z-stamped", age_seconds=100 * 24 * 60 * 60)
    _write_snapshot(tmp_path, "guard.db.corrupt-legacy-unstamped", age_seconds=60)

    prune_quarantined_store_snapshots(tmp_path, min_keep=1, max_age=timedelta(seconds=0))

    # A parseable quarantine stamp always outranks a legacy name, whatever
    # the moved files' mtimes say.
    assert (tmp_path / "guard.db.corrupt-20260905T132908303335Z-stamped").exists()
    assert not (tmp_path / "guard.db.corrupt-legacy-unstamped").exists()


def test_stale_update_staging_is_pruned_but_recent_staging_stays(tmp_path: Path) -> None:
    runtime = tmp_path / "guard-home" / "update-runtime"
    stale_home = runtime / "home"
    fresh_tmp = runtime / "tmp"
    for directory in (stale_home, fresh_tmp):
        directory.mkdir(parents=True)
    stale_home.joinpath("Library").mkdir()
    stale_home.joinpath("Library").joinpath("cache.db").write_bytes(b"stale")
    fresh_tmp.joinpath("in-flight.tmp").write_bytes(b"fresh")
    _age(stale_home, age_seconds=8 * 24 * 60 * 60)

    prune_stale_update_staging(tmp_path / "guard-home")

    assert not stale_home.exists()
    # Recent staging — an update that is still running — is never touched.
    assert fresh_tmp.joinpath("in-flight.tmp").read_bytes() == b"fresh"


def test_fresh_update_activity_marker_blocks_the_staging_sweep(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    runtime = guard_home / "update-runtime"
    stale_home = runtime / "home"
    stale_home.mkdir(parents=True)
    _age(stale_home, age_seconds=8 * 24 * 60 * 60)
    marker = runtime / "active.json"
    marker.write_text('{"staging": "active"}\n', encoding="utf-8")

    prune_stale_update_staging(guard_home)

    # Reused staging roots keep old mtimes while an update writes deep inside
    # them; the fresh marker is what protects the tree.
    assert stale_home.exists()

    _age(marker, age_seconds=8 * 24 * 60 * 60)
    prune_stale_update_staging(guard_home)

    assert not stale_home.exists()
    assert marker.exists()


def test_stale_update_staging_prune_tolerates_missing_directories(tmp_path: Path) -> None:
    prune_stale_update_staging(tmp_path / "guard-home")
    assert not (tmp_path / "guard-home").exists()


def test_malformed_digit_led_quarantine_name_does_not_outrank_real_stamps(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, "guard.db.corrupt-9-legacy", age_seconds=0)
    _write_snapshot(tmp_path, "guard.db.corrupt-20260905T132908303335Z-real", age_seconds=30 * 24 * 60 * 60)

    prune_quarantined_store_snapshots(tmp_path, min_keep=1, max_age=timedelta(seconds=0))

    # The real quarantine event survives even with an older file mtime.
    assert (tmp_path / "guard.db.corrupt-20260905T132908303335Z-real").exists()
    assert not (tmp_path / "guard.db.corrupt-9-legacy").exists()


def test_staging_sweep_refuses_a_linked_runtime_tree(tmp_path: Path) -> None:
    import os

    if os.name == "nt":
        import pytest

        pytest.skip("symlink creation may require elevated privileges on Windows")
    guard_home = tmp_path / "guard-home"
    target = tmp_path / "target-tree"
    stale = target / "home"
    stale.mkdir(parents=True)
    _age(stale, age_seconds=30 * 24 * 60 * 60)
    guard_home.mkdir()
    (guard_home / "update-runtime").symlink_to(target, target_is_directory=True)

    from codex_plugin_scanner.guard.update_staging import prune_stale_update_staging

    prune_stale_update_staging(guard_home)

    # The sweep must not follow the link: the target tree stays untouched.
    assert stale.exists()


def test_truncated_quarantine_stamp_is_ignored_without_raising(tmp_path: Path) -> None:
    # A 21-character digit-led name (everything but the trailing Z) must not
    # reach the stamp comparison and crash the sweep.
    _write_snapshot(tmp_path, "guard.db.corrupt-20260101T00000000000", age_seconds=0)
    _write_snapshot(tmp_path, "guard.db.corrupt-20260905T132908303335Z-real", age_seconds=99 * 24 * 60 * 60)

    removed = prune_quarantined_store_snapshots(tmp_path, min_keep=1, max_age=timedelta(seconds=0))

    assert removed == 1
    assert (tmp_path / "guard.db.corrupt-20260905T132908303335Z-real").exists()


def _age(path: Path, *, age_seconds: int) -> None:
    stamp = path.stat().st_mtime - age_seconds
    os.utime(path, (stamp, stamp))
