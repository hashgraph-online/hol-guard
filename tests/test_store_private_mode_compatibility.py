"""Compatibility boundaries for idempotent private-mode repair."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import store_base, store_private_mode


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are required")
@pytest.mark.parametrize("extra_bits", [stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX])
def test_special_permission_bits_are_removed(tmp_path: Path, extra_bits: int) -> None:
    path = tmp_path / "special-mode-target"
    path.write_bytes(b"synthetic-private-mode-control")
    path.chmod(0o600 | extra_bits)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 | extra_bits
    store_base._set_private_mode(path, 0o600)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission repair is required")
def test_unavailable_metadata_keeps_real_chmod_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "unobserved-mode-target"
    path.write_bytes(b"synthetic-private-mode-control")
    path.chmod(0o666)
    observed: list[bool] = []

    def unavailable(_path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        assert _path == path and follow_symlinks
        observed.append(True)
        raise PermissionError("synthetic metadata refusal")

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "stat", unavailable)
        store_base._set_private_mode(path, 0o600)
    assert observed == [True]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_windows_returns_before_stat_or_chmod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "windows-noop-target"

    def forbidden_stat(_path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        raise AssertionError("Windows permission repair must not read metadata")

    def forbidden_chmod(_path: Path, _mode: int) -> None:
        raise AssertionError("Windows permission repair must not invoke chmod")

    with monkeypatch.context() as scoped:
        scoped.setattr(store_private_mode, "os", SimpleNamespace(name="nt", chmod=forbidden_chmod))
        scoped.setattr(Path, "stat", forbidden_stat)
        store_base._set_private_mode(path, 0o600)
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission repair is required")
def test_chmod_failure_remains_best_effort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "refused-mode-target"
    path.write_bytes(b"synthetic-private-mode-control")
    path.chmod(0o666)
    calls: list[bool] = []

    def refused(target: Path, mode: int) -> None:
        calls.append(target == path and mode == 0o600)
        raise PermissionError("synthetic permission refusal")

    monkeypatch.setattr(store_private_mode.os, "chmod", refused)
    store_base._set_private_mode(path, 0o600)
    assert calls == [True]
    assert stat.S_IMODE(path.stat().st_mode) == 0o666
