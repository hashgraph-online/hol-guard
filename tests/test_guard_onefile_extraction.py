"""Onefile extraction-dir owner markers and orphan reclamation."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import onefile_extraction
from codex_plugin_scanner.guard.onefile_extraction import (
    OWNER_MARKER_NAME,
    ExtractionReclaimResult,
    is_onefile_extraction_dir,
    reclaim_orphaned_extraction_dirs,
    record_extraction_owner,
)

_SENTINEL_PARTS = ("codex_plugin_scanner", "guard", "daemon", "static", "index.html")
_NOW = datetime(2026, 2, 1, tzinfo=timezone.utc)
_OLD_AGE_SECONDS = 20 * 60


def _extraction_dir(temp_root: Path, name: str = "_MEIabc123") -> Path:
    directory = temp_root / name
    directory.mkdir(parents=True)
    return directory


def _age_directory(directory: Path) -> None:
    """Backdate dir mtime after contents are written; file writes bump it."""

    stamp = _NOW.timestamp() - _OLD_AGE_SECONDS
    os.utime(directory, (stamp, stamp))


def _write_marker(directory: Path, *, pid: int = 4242, parent_pid: int = 4241) -> Path:
    marker = directory / OWNER_MARKER_NAME
    marker.write_text(
        json.dumps(
            {
                "schema": "guard.onefile-extraction-owner.v1",
                "pid": pid,
                "parent_pid": parent_pid,
                "started_at": _NOW.isoformat(),
                "guard_version": "0.0.0-test",
            }
        ),
        encoding="utf-8",
    )
    return marker


def _no_live_pids(pid: int) -> bool:
    return False


def _all_live_pids(pid: int) -> bool:
    return True


def test_is_onefile_extraction_dir_requires_mei_name_and_real_directory(tmp_path: Path) -> None:
    extraction = _extraction_dir(tmp_path)
    assert is_onefile_extraction_dir(extraction, tmp_path)
    assert not is_onefile_extraction_dir(tmp_path / "_MEImissing0", tmp_path)
    assert not is_onefile_extraction_dir(_extraction_dir(tmp_path, "other"), tmp_path)
    assert not is_onefile_extraction_dir(_extraction_dir(tmp_path, "_MEIab"), tmp_path)

    not_a_dir = tmp_path / "_MEIfile000"
    not_a_dir.write_text("x", encoding="utf-8")
    assert not is_onefile_extraction_dir(not_a_dir, tmp_path)

    nested_root = tmp_path / "nested"
    nested = _extraction_dir(nested_root)
    assert not is_onefile_extraction_dir(nested, tmp_path)


def test_is_onefile_extraction_dir_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = tmp_path / "_MEIlink99"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert not is_onefile_extraction_dir(link, tmp_path)


def test_record_extraction_owner_marks_real_extraction_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    extraction = _extraction_dir(tmp_path)

    assert record_extraction_owner(meipass=str(extraction), temp_root=tmp_path)

    marker = extraction / OWNER_MARKER_NAME
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["schema"] == "guard.onefile-extraction-owner.v1"
    assert payload["pid"] == os.getpid()
    assert payload["parent_pid"] == os.getppid()
    assert isinstance(payload["started_at"], str)
    assert isinstance(payload["guard_version"], str) and payload["guard_version"]
    assert str(tmp_path) not in marker.read_text(encoding="utf-8")
    mode = stat.S_IMODE(marker.stat().st_mode)
    if os.name != "nt":
        assert mode == 0o600


def test_record_extraction_owner_skips_onedir_and_non_frozen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extraction = _extraction_dir(tmp_path)

    monkeypatch.delattr(sys, "frozen", raising=False)
    assert not record_extraction_owner(meipass=str(extraction), temp_root=tmp_path)

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    onedir = tmp_path / "hol-guard"
    onedir.mkdir()
    assert not record_extraction_owner(meipass=str(onedir), temp_root=tmp_path)
    assert not record_extraction_owner(meipass=None, temp_root=tmp_path)
    assert not record_extraction_owner(meipass="", temp_root=tmp_path)
    outside_root = tmp_path / "other-root"
    nested = _extraction_dir(outside_root)
    assert not record_extraction_owner(meipass=str(nested), temp_root=tmp_path)
    assert not (extraction / OWNER_MARKER_NAME).exists()


def test_record_extraction_owner_never_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert not record_extraction_owner(meipass=str(tmp_path / "_MEImissing0"), temp_root=tmp_path)


def test_reclaim_deletes_dead_owner_dir_and_counts_bytes(tmp_path: Path) -> None:
    extraction = _extraction_dir(tmp_path)
    (extraction / "blob.bin").write_bytes(b"x" * 100)
    _write_marker(extraction, pid=4242, parent_pid=4241)
    _age_directory(extraction)

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.reclaimed_count == 1
    assert result.killed_launches == 1
    assert result.reclaimed_bytes >= 100
    assert not extraction.exists()
    assert result.errors == []


def test_reclaim_keeps_dirs_whose_owner_or_parent_is_alive(tmp_path: Path) -> None:
    pid_alive_dir = _extraction_dir(tmp_path, "_MEIalive00")
    _write_marker(pid_alive_dir, pid=1, parent_pid=2)
    parent_alive_dir = _extraction_dir(tmp_path, "_MEIparent0")
    _write_marker(parent_alive_dir, pid=3, parent_pid=4)
    _age_directory(pid_alive_dir)
    _age_directory(parent_alive_dir)

    live = {1, 4}
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=lambda pid: pid in live,
    )

    assert result.reclaimed_count == 0
    assert pid_alive_dir.exists()
    assert parent_alive_dir.exists()


def test_reclaim_skips_young_and_current_extraction_dirs(tmp_path: Path) -> None:
    young = _extraction_dir(tmp_path, "_MEIyoung00")
    _write_marker(young, pid=5, parent_pid=6)
    current = _extraction_dir(tmp_path, "_MEIcurrent")
    _write_marker(current, pid=7, parent_pid=8)
    _age_directory(current)

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=str(current),
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.reclaimed_count == 0
    assert young.exists()
    assert current.exists()


def test_reclaim_counts_unmarked_guard_dirs_without_deleting(tmp_path: Path) -> None:
    legacy = _extraction_dir(tmp_path, "_MEIlegacy0")
    sentinel = legacy.joinpath(*_SENTINEL_PARTS)
    sentinel.parent.mkdir(parents=True)
    sentinel.write_bytes(b"<html></html>")
    non_guard = _extraction_dir(tmp_path, "_MEIother00")
    (non_guard / "unrelated.bin").write_bytes(b"y" * 10)
    _age_directory(legacy)
    _age_directory(non_guard)

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.unmarked_count == 1
    assert result.unmarked_bytes_estimate >= len(b"<html></html>")
    assert result.reclaimed_count == 0
    assert legacy.exists()
    assert non_guard.exists()


def test_reclaim_unmarked_byte_sampling_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for index in range(15):
        legacy = _extraction_dir(tmp_path, f"_MEIlegacy{index}")
        sentinel = legacy.joinpath(*_SENTINEL_PARTS)
        sentinel.parent.mkdir(parents=True)
        sentinel.write_bytes(b"<html></html>")
        _age_directory(legacy)

    walks: list[Path] = []
    original = onefile_extraction._dir_bytes

    def counting_walk(root: Path) -> int:
        walks.append(root)
        return original(root)

    monkeypatch.setattr(onefile_extraction, "_dir_bytes", counting_walk)
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.unmarked_count == 15
    assert len(walks) == 10
    assert result.unmarked_bytes_estimate == round(sum(original(path) for path in walks) / 10 * 15)


def test_reclaim_ignores_symlinked_extraction_dirs(tmp_path: Path) -> None:
    nested_root = tmp_path / "real"
    target = _extraction_dir(nested_root, "_MEItarget0")
    _write_marker(target, pid=9, parent_pid=10)
    link = tmp_path / "_MEIlink000"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert link.is_symlink()
    assert result.reclaimed_count == 0
    assert result.unmarked_count == 0
    assert target.exists()


def test_reclaim_stops_when_should_stop_flips(tmp_path: Path) -> None:
    dirs = [_extraction_dir(tmp_path, f"_MEIdead{index:03d}") for index in range(5)]
    for directory in dirs:
        _write_marker(directory, pid=20, parent_pid=21)
        _age_directory(directory)

    checks = 0

    def stop_after_two() -> bool:
        nonlocal checks
        checks += 1
        return checks > 2

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
        should_stop=stop_after_two,
    )

    assert result.reclaimed_count == 2
    assert sum(directory.exists() for directory in dirs) == 3


def test_pid_alive_fails_closed_on_malformed_pid() -> None:
    assert onefile_extraction._pid_alive(0)  # pyright: ignore[reportPrivateUsage]
    assert onefile_extraction._pid_alive(-42)  # pyright: ignore[reportPrivateUsage]


def test_reclaim_rechecks_marker_before_deleting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extraction = _extraction_dir(tmp_path)
    _write_marker(extraction, pid=11, parent_pid=12)
    _age_directory(extraction)

    original = onefile_extraction._read_owner_marker
    calls: list[Path] = []

    def flaky_marker(marker_path: Path) -> dict[str, int] | None:
        calls.append(marker_path)
        if len(calls) > 1:
            return None
        return original(marker_path)

    monkeypatch.setattr(onefile_extraction, "_read_owner_marker", flaky_marker)
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.reclaimed_count == 0
    assert extraction.exists()
    assert len(calls) == 2


def test_is_onefile_extraction_dir_survives_resolve_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extraction = _extraction_dir(tmp_path)
    original_resolve = Path.resolve

    def broken_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self.name.startswith("_MEI"):
            raise OSError("vanishing mount")
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", broken_resolve)
    assert not is_onefile_extraction_dir(extraction, tmp_path)


def test_record_extraction_owner_reports_unknown_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delattr("codex_plugin_scanner.version.__version__")
    extraction = _extraction_dir(tmp_path)

    assert record_extraction_owner(meipass=str(extraction), temp_root=tmp_path)
    payload = json.loads((extraction / OWNER_MARKER_NAME).read_text(encoding="utf-8"))
    assert payload["guard_version"] == "unknown"


def test_record_extraction_owner_returns_false_on_write_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    extraction = _extraction_dir(tmp_path)
    monkeypatch.setattr(
        onefile_extraction.json,
        "dumps",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("encode failed")),
    )

    assert not record_extraction_owner(meipass=str(extraction), temp_root=tmp_path)
    assert not (extraction / OWNER_MARKER_NAME).exists()


def test_pid_alive_with_real_processes() -> None:
    assert onefile_extraction._pid_alive(os.getpid())  # pyright: ignore[reportPrivateUsage]
    exited = subprocess.Popen([sys.executable, "-c", "pass"])
    exited.wait()
    assert not onefile_extraction._pid_alive(exited.pid)  # pyright: ignore[reportPrivateUsage]


def test_pid_alive_fail_closed_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        onefile_extraction.os,
        "kill",
        lambda pid, sig: (_ for _ in ()).throw(PermissionError("denied")),
    )
    assert onefile_extraction._pid_alive(12345)  # pyright: ignore[reportPrivateUsage]

    # Any error other than "definitely dead" fails closed to alive.
    monkeypatch.setattr(
        onefile_extraction.os,
        "kill",
        lambda pid, sig: (_ for _ in ()).throw(OSError("weird")),
    )
    assert onefile_extraction._pid_alive(12345)  # pyright: ignore[reportPrivateUsage]


def test_pid_alive_windows_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import windows_paths

    monkeypatch.setattr(onefile_extraction.os, "name", "nt")
    monkeypatch.setattr(windows_paths, "windows_process_is_running", lambda pid: False)
    assert not onefile_extraction._pid_alive(12345)  # pyright: ignore[reportPrivateUsage]

    def boom(pid: int) -> bool:
        raise RuntimeError("win32 api unavailable")

    monkeypatch.setattr(windows_paths, "windows_process_is_running", boom)
    assert onefile_extraction._pid_alive(12345)  # pyright: ignore[reportPrivateUsage]


def test_read_owner_marker_rejects_bad_records(tmp_path: Path) -> None:
    read = onefile_extraction._read_owner_marker  # pyright: ignore[reportPrivateUsage]
    marker = tmp_path / "marker.json"

    assert read(tmp_path / "missing.json") is None

    marker.mkdir()
    assert read(marker) is None
    marker.rmdir()

    marker.write_bytes(b"x" * 5000)
    assert read(marker) is None

    marker.write_text("not json", encoding="utf-8")
    assert read(marker) is None

    marker.write_text(json.dumps([1, 2]), encoding="utf-8")
    assert read(marker) is None

    marker.write_text(json.dumps({"schema": "other-schema", "pid": 1, "parent_pid": 2}), encoding="utf-8")
    assert read(marker) is None

    marker.write_text(
        json.dumps({"schema": "guard.onefile-extraction-owner.v1", "pid": "x", "parent_pid": 2}),
        encoding="utf-8",
    )
    assert read(marker) is None

    marker.write_text(
        json.dumps({"schema": "guard.onefile-extraction-owner.v1", "pid": 1, "parent_pid": 2}),
        encoding="utf-8",
    )
    assert read(marker) == {"pid": 1, "parent_pid": 2}


def test_dir_bytes_tolerates_lstat_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = tmp_path / "walk"
    directory.mkdir()
    (directory / "f.bin").write_bytes(b"x" * 8)
    monkeypatch.setattr(
        onefile_extraction.os,
        "lstat",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("gone")),
    )
    assert onefile_extraction._dir_bytes(directory) == 0  # pyright: ignore[reportPrivateUsage]


def test_reclaim_temp_root_errors(tmp_path: Path) -> None:
    missing = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path / "missing",
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )
    assert missing.errors == ["temp_root_unavailable"]

    not_a_dir = tmp_path / "afile"
    not_a_dir.write_text("x", encoding="utf-8")
    listing = reclaim_orphaned_extraction_dirs(
        temp_root=not_a_dir,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )
    assert listing.errors == ["temp_root_listing_failed"]


def test_reclaim_tolerates_unresolvable_current_meipass(tmp_path: Path) -> None:
    extraction = _extraction_dir(tmp_path)
    _write_marker(extraction, pid=30, parent_pid=31)
    _age_directory(extraction)

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=str(tmp_path / "no-such-dir"),
        now=_NOW,
        pid_alive=_no_live_pids,
    )
    assert result.reclaimed_count == 1


def test_reclaim_skips_dirs_with_stat_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broken = _extraction_dir(tmp_path, "_MEIbroken0")
    _write_marker(broken, pid=40, parent_pid=41)
    _age_directory(broken)

    original_lstat = Path.lstat

    def flaky_lstat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        if self == broken:
            raise OSError("lstat failed")
        return original_lstat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", flaky_lstat)
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )
    assert result.reclaimed_count == 0
    assert broken.exists()


def test_reclaim_skips_dirs_with_resolve_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broken = _extraction_dir(tmp_path, "_MEIbroken0")
    elsewhere = _extraction_dir(tmp_path, "_MEIother00")

    original_resolve = Path.resolve

    def flaky_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self == broken:
            raise OSError("resolve failed")
        if self == elsewhere:
            return Path("/not-the-temp-root") / self.name
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", flaky_resolve)
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )
    assert result.reclaimed_count == 0
    assert broken.exists()
    assert elsewhere.exists()


def test_reclaim_records_rmtree_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extraction = _extraction_dir(tmp_path)
    _write_marker(extraction, pid=50, parent_pid=51)
    _age_directory(extraction)

    monkeypatch.setattr(
        onefile_extraction.shutil,
        "rmtree",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("device busy")),
    )
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )
    assert result.reclaimed_count == 0
    assert result.errors == ["rmtree:OSError"]
    assert extraction.exists()


def test_remember_error_list_is_bounded() -> None:
    result = ExtractionReclaimResult()
    for index in range(12):
        onefile_extraction._remember_error(result, f"e{index}")  # pyright: ignore[reportPrivateUsage]
    assert result.errors == [f"e{index}" for index in range(8)]
