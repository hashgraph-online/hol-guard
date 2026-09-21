"""Security regressions for shared path containment helpers."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner import path_support
from codex_plugin_scanner.path_support import (
    FileChangedDuringReadError,
    read_bytes_file_within_root,
    resolve_path_within_allowed_roots,
)


def test_resolve_path_within_allowed_roots_accepts_contained_directory(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    workspace = allowed_root / "workspace"
    workspace.mkdir(parents=True)

    assert resolve_path_within_allowed_roots(str(workspace), (allowed_root,), require_exists=True) == workspace


def test_resolve_path_within_allowed_roots_rejects_traversal(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    traversal = f"{allowed_root}/../{outside.name}"

    assert resolve_path_within_allowed_roots(traversal, (allowed_root,), require_exists=True) is None


def test_resolve_path_within_allowed_roots_rejects_symlink_escape(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = allowed_root / "workspace"
    link.symlink_to(outside, target_is_directory=True)

    assert resolve_path_within_allowed_roots(str(link), (allowed_root,), require_exists=True) is None


def test_resolve_path_within_allowed_roots_accepts_symlinked_allowed_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real-root"
    workspace = real_root / "workspace"
    workspace.mkdir(parents=True)
    allowed_root = tmp_path / "allowed-root"
    allowed_root.symlink_to(real_root, target_is_directory=True)

    selected = allowed_root / workspace.name

    assert resolve_path_within_allowed_roots(str(selected), (allowed_root,), require_exists=True) == workspace


@pytest.mark.parametrize("mutation", [None, "descriptor_change_time", "path_identity"])
def test_safe_read_keeps_same_api_changes_with_windows_timestamp_semantics(tmp_path, monkeypatch, mutation):
    monkeypatch.setattr(path_support, "sys", SimpleNamespace(platform="win32"))
    victim = tmp_path / "copied.json"
    payload = b'{"valid":true}\r\n'
    victim.write_bytes(payload)
    real_lstat = Path.lstat
    real_fstat = path_support.os.fstat
    path_calls = descriptor_calls = 0

    def metadata(original, change_time, *, replaced=False):
        return SimpleNamespace(
            st_dev=original.st_dev,
            st_ino=original.st_ino + int(replaced),
            st_mode=original.st_mode,
            st_size=original.st_size,
            st_mtime_ns=original.st_mtime_ns,
            st_ctime_ns=change_time,
            st_birthtime_ns=100,
        )

    def lstat(path, *args, **kwargs):
        nonlocal path_calls
        original = real_lstat(path, *args, **kwargs)
        if path != victim:
            return original
        path_calls += 1
        return metadata(original, 100, replaced=mutation == "path_identity" and path_calls > 1)

    def fstat(descriptor):
        nonlocal descriptor_calls
        descriptor_calls += 1
        changed = mutation == "descriptor_change_time" and descriptor_calls > 1
        return metadata(real_fstat(descriptor), 200 + int(changed))

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(path_support.os, "fstat", fstat)
    if mutation is None:
        assert read_bytes_file_within_root(tmp_path, victim) == payload
    else:
        with pytest.raises(FileChangedDuringReadError):
            read_bytes_file_within_root(tmp_path, victim)
    assert path_calls == descriptor_calls == 2


def test_nonwindows_reader_keeps_cross_api_change_time_with_birthtime(tmp_path, monkeypatch):
    monkeypatch.setattr(path_support, "sys", SimpleNamespace(platform="linux"))
    victim = tmp_path / "input.json"
    victim.write_bytes(b"unchanged length")
    original_lstat = Path.lstat
    original_fstat = path_support.os.fstat

    def with_birthtime(original, *, changed=False):
        return SimpleNamespace(
            st_dev=original.st_dev,
            st_ino=original.st_ino,
            st_mode=original.st_mode,
            st_size=original.st_size,
            st_mtime_ns=original.st_mtime_ns,
            st_ctime_ns=original.st_ctime_ns + int(changed),
            st_birthtime_ns=100,
        )

    def lstat(path, *args, **kwargs):
        original = original_lstat(path, *args, **kwargs)
        return with_birthtime(original) if path == victim else original

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(path_support.os, "fstat", lambda fd: with_birthtime(original_fstat(fd), changed=True))
    with pytest.raises(FileChangedDuringReadError, match="changed while opening"):
        read_bytes_file_within_root(tmp_path, victim)
