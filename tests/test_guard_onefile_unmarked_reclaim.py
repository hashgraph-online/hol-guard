"""Reclamation of unmarked Guard onefile extraction dirs behind an open-files scan."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.onefile_extraction import (
    OWNER_MARKER_NAME,
    reclaim_orphaned_extraction_dirs,
)
from codex_plugin_scanner.guard.onefile_open_paths import scan_open_extraction_dirs
from codex_plugin_scanner.guard.onefile_unmarked import (
    BUNDLE,
    PARTIAL,
    classify_unmarked_extraction,
)

_NOW = datetime(2026, 2, 1, tzinfo=timezone.utc)
_THREE_HOURS = 3 * 3600


def _bundle(root: Path, name: str, *, age: int = _THREE_HOURS) -> Path:
    directory = root / name
    static = directory / "codex_plugin_scanner" / "guard" / "daemon" / "static"
    static.mkdir(parents=True)
    (static / "index.html").write_text("<html></html>", encoding="utf-8")
    _age(directory, age)
    return directory


def _partial(root: Path, name: str, *, age: int = _THREE_HOURS) -> Path:
    directory = root / name
    (directory / "codex_plugin_scanner").mkdir(parents=True)
    (directory / "codex_plugin_scanner" / "x.so").write_bytes(b"x")
    _age(directory, age)
    return directory


def _age(directory: Path, seconds: int) -> None:
    stamp = _NOW.timestamp() - seconds
    os.utime(directory, (stamp, stamp))


def _scanner(in_use: set[str] | None):
    calls: list[Path] = []

    def scan(root: Path) -> frozenset[str] | None:
        calls.append(root)
        return None if in_use is None else frozenset(in_use)

    scan.calls = calls  # type: ignore[attr-defined]
    return scan


def _run(root: Path, scanner, **kwargs):
    return reclaim_orphaned_extraction_dirs(
        temp_root=root,
        current_meipass=None,
        now=_NOW,
        open_path_scanner=scanner,
        **kwargs,
    )


def test_classify_signatures(tmp_path: Path) -> None:
    assert classify_unmarked_extraction(_bundle(tmp_path, "_MEIbundle1")) == BUNDLE
    assert classify_unmarked_extraction(_partial(tmp_path, "_MEIpartial")) == PARTIAL

    mypyc = tmp_path / "_MEImypyc1"
    (mypyc / "Python.framework").mkdir(parents=True)
    (mypyc / "abc123__mypyc.cpython-312-darwin.so").write_bytes(b"x")
    # Other onefile apps with mypyc-compiled dependencies share this layout.
    assert classify_unmarked_extraction(mypyc) is None

    mypyc_only = tmp_path / "_MEImypyc2"
    mypyc_only.mkdir()
    (mypyc_only / "abc123__mypyc.cpython-312-darwin.so").write_bytes(b"x")
    assert classify_unmarked_extraction(mypyc_only) is None

    other_app = tmp_path / "_MEIother1"
    (other_app / "Python.framework").mkdir(parents=True)
    assert classify_unmarked_extraction(other_app) is None
    (tmp_path / "_MEIempty01").mkdir()
    assert classify_unmarked_extraction(tmp_path / "_MEIempty01") is None
    assert classify_unmarked_extraction(tmp_path / "missing") is None


def test_unmarked_dirs_are_kept_without_a_scanner(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, "_MEIbundle1")
    result = _run(tmp_path, None)
    assert bundle.exists()
    assert result.unmarked_count == 1
    assert result.unmarked_reclaimed_count == 0
    assert result.unmarked_scan == "disabled"


def test_reclaims_unused_bundle_and_partial_dirs(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, "_MEIbundle1")
    partial = _partial(tmp_path, "_MEIpartial")
    scan = _scanner(set())
    result = _run(tmp_path, scan)
    assert not bundle.exists()
    assert not partial.exists()
    assert result.unmarked_reclaimed_count == 2
    assert result.partial_reclaimed_count == 1
    assert result.reclaimed_count == 2
    assert result.unmarked_reclaimed_bytes > 0
    assert result.unmarked_scan == "ok"
    assert result.unmarked_count == 0
    # One system-wide scan per sweep, not one per directory.
    assert len(scan.calls) == 1  # type: ignore[attr-defined]


def test_dirs_in_use_by_a_live_process_are_kept(tmp_path: Path) -> None:
    live = _bundle(tmp_path, "_MEIlive001")
    dead = _bundle(tmp_path, "_MEIdead001")
    result = _run(tmp_path, _scanner({"_MEIlive001"}))
    assert live.exists()
    assert not dead.exists()
    assert result.unmarked_count == 1


def test_scan_failure_skips_all_unmarked_reclamation(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, "_MEIbundle1")
    partial = _partial(tmp_path, "_MEIpartial")
    result = _run(tmp_path, _scanner(None))
    assert bundle.exists() and partial.exists()
    assert result.unmarked_scan == "unavailable"
    assert "open_path_scan_unavailable" in result.errors
    assert result.unmarked_count == 2


def test_young_current_marked_and_unidentified_dirs_are_not_unmarked_candidates(tmp_path: Path) -> None:
    young = _bundle(tmp_path, "_MEIyoung01", age=3600)
    current = _bundle(tmp_path, "_MEIcurrent")
    unidentified = tmp_path / "_MEIunknown"
    unidentified.mkdir()
    (unidentified / "data.bin").write_bytes(b"x")
    _age(unidentified, _THREE_HOURS)
    scan = _scanner(set())
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=str(current),
        now=_NOW,
        open_path_scanner=scan,
    )
    assert young.exists() and current.exists() and unidentified.exists()
    assert result.unmarked_reclaimed_count == 0
    # The only candidate is too young, so no scan is ever needed.
    assert result.unmarked_scan == "not_needed"
    assert not scan.calls  # type: ignore[attr-defined]


def test_unmarked_min_age_is_configurable_and_marker_dirs_use_pid_path(tmp_path: Path) -> None:
    middle = _bundle(tmp_path, "_MEImiddle1", age=3600)
    assert _run(tmp_path, _scanner(set())).unmarked_reclaimed_count == 0
    assert middle.exists()
    result = _run(tmp_path, _scanner(set()), unmarked_min_age=timedelta(minutes=30))
    assert result.unmarked_reclaimed_count == 1
    assert not middle.exists()


def test_sweep_is_bounded_by_count_and_time(tmp_path: Path) -> None:
    for index in range(5):
        _bundle(tmp_path, f"_MEIbatch{index}")
    result = _run(tmp_path, _scanner(set()), max_unmarked_reclaims=2)
    assert result.unmarked_reclaimed_count == 2
    assert result.unmarked_budget_exhausted
    assert result.unmarked_count == 3

    ticks = iter([0.0, 0.0, 1000.0, 2000.0, 3000.0, 4000.0])
    result = _run(
        tmp_path,
        _scanner(set()),
        unmarked_time_budget=timedelta(seconds=10),
        monotonic=lambda: next(ticks),
    )
    assert result.unmarked_reclaimed_count == 1
    assert result.unmarked_budget_exhausted


def test_dir_touched_after_listing_is_not_deleted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle(tmp_path, "_MEIbundle1")

    def scan_then_touch(root: Path) -> frozenset[str]:
        os.utime(bundle, (_NOW.timestamp(), _NOW.timestamp()))
        return frozenset()

    result = _run(tmp_path, scan_then_touch)
    assert bundle.exists()
    assert result.unmarked_reclaimed_count == 0


def test_dir_that_gains_a_marker_is_not_deleted(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, "_MEIbundle1")

    def scan_then_mark(root: Path) -> frozenset[str]:
        (bundle / OWNER_MARKER_NAME).write_text("{}", encoding="utf-8")
        _age(bundle, _THREE_HOURS)
        return frozenset()

    result = _run(tmp_path, scan_then_mark)
    # A marker file (even an invalid one) means ownership is not ours to guess.
    assert bundle.exists()
    assert result.unmarked_reclaimed_count == 0


def test_rmtree_failure_is_recorded_and_dir_is_still_counted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle(tmp_path, "_MEIbundle1")

    def fail(path: Path) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr("codex_plugin_scanner.guard.onefile_extraction.shutil.rmtree", fail)
    result = _run(tmp_path, _scanner(set()))
    assert bundle.exists()
    assert "rmtree:PermissionError" in result.errors
    assert result.unmarked_count == 1


@pytest.mark.skipif(os.name == "nt", reason="uid ownership is POSIX only")
def test_dirs_owned_by_other_users_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle(tmp_path, "_MEIbundle1")
    monkeypatch.setattr(os, "getuid", lambda: os.stat(bundle).st_uid + 1)
    result = _run(tmp_path, _scanner(set()))
    assert bundle.exists()
    assert result.unmarked_scan == "not_needed"


# --- open-path scanner -------------------------------------------------------


def _completed(stdout: bytes, returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=["lsof"], returncode=returncode, stdout=stdout, stderr=b"")


def test_lsof_scan_extracts_extraction_names_and_ignores_other_paths(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    output = (
        f"p100\nn{root}/_MEIaaaa11/Python.framework/Python\n"
        f"n{root}/_MEIbbbb22\n"
        f"n{root}/other/_MEIcccc33/x\n"
        "n/usr/lib/libSystem.dylib\n"
        f"n{root}/_MEIshort/x\n"
    ).encode()
    seen: list[list[str]] = []

    def runner(argv, **kwargs):
        seen.append(argv)
        return _completed(output)

    found = scan_open_extraction_dirs(tmp_path, runner=runner, lsof_path="/fake/lsof", platform="darwin")
    assert found == frozenset({"_MEIaaaa11", "_MEIbbbb22", "_MEIshort"})
    assert seen[0][0] == "/fake/lsof"
    assert "-F" in seen[0]


def test_lsof_scan_fails_closed(tmp_path: Path) -> None:
    def boom(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 1)

    assert scan_open_extraction_dirs(tmp_path, runner=boom, lsof_path="/fake/lsof", platform="darwin") is None

    def missing(argv, **kwargs):
        raise FileNotFoundError(argv[0])

    assert scan_open_extraction_dirs(tmp_path, runner=missing, lsof_path="/fake/lsof", platform="darwin") is None
    assert (
        scan_open_extraction_dirs(
            tmp_path, runner=lambda argv, **kw: _completed(b"", 0), lsof_path="/fake/lsof", platform="darwin"
        )
        is None
    )
    assert (
        scan_open_extraction_dirs(
            tmp_path, runner=lambda argv, **kw: _completed(b"n/x\n", 2), lsof_path="/fake/lsof", platform="darwin"
        )
        is None
    )
    assert (
        scan_open_extraction_dirs(
            tmp_path, runner=lambda argv, **kw: _completed(b"n/x\n", 1), lsof_path="/fake/lsof", platform="darwin"
        )
        is None
    )
    assert scan_open_extraction_dirs(tmp_path, platform="win32") is None


def test_proc_scan_reads_maps_cwd_and_fds(tmp_path: Path) -> None:
    root = tmp_path / "tmp"
    root.mkdir()
    proc = tmp_path / "proc"
    first = proc / "10"
    (first / "fd").mkdir(parents=True)
    (first / "maps").write_text(
        f"7f00-7f01 r-xp 00000000 00:01 5 {root}/_MEImaps001/libpython3.12.so (deleted)\n", encoding="utf-8"
    )
    (first / "cwd").symlink_to(root / "_MEIcwd0001")
    (first / "fd" / "3").symlink_to(root / "_MEIfd00001" / "data")
    second = proc / "11"
    (second / "fd").mkdir(parents=True)
    (second / "maps").write_text("", encoding="utf-8")
    (proc / "self-not-numeric").mkdir()
    found = scan_open_extraction_dirs(root, proc_root=proc, platform="linux")
    assert found == frozenset({"_MEImaps001", "_MEIcwd0001", "_MEIfd00001"})


def test_proc_scan_unreadable_own_process_fails_closed_to_lsof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "tmp"
    root.mkdir()
    proc = tmp_path / "proc"
    (proc / "10" / "fd").mkdir(parents=True)
    # No maps file: FileNotFoundError means the process vanished, which is fine.
    assert scan_open_extraction_dirs(root, proc_root=proc, platform="linux") == frozenset()

    original = Path.read_text

    def deny(self: Path, *args, **kwargs):
        if self.name == "maps":
            raise PermissionError("denied")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny)
    (proc / "10" / "maps").write_text("", encoding="utf-8")
    monkeypatch.setattr("codex_plugin_scanner.guard.onefile_open_paths.shutil.which", lambda name: None)
    monkeypatch.setattr("codex_plugin_scanner.guard.onefile_open_paths.os.path.isfile", lambda path: False)
    assert scan_open_extraction_dirs(root, proc_root=proc, platform="linux") is None
