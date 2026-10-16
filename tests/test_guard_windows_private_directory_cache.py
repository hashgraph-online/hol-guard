"""The store's Windows guard-home repair cache, judged without Windows APIs."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_windows_directory_repair_is_not_repeated_for_the_same_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_policy_snapshot_windows_state, store_base

    bound: list[Path] = []
    monkeypatch.setattr(native_policy_snapshot_windows_state, "_windows_ensure_private_directory", bound.append)
    monkeypatch.setattr(store_base, "_windows_private_directory_bound", {})
    clock = [100.0]
    monkeypatch.setattr(store_base.time, "monotonic", lambda: clock[0])
    home = tmp_path / "guard-home"
    home.mkdir()

    store_base._set_windows_private_directory(home)
    store_base._set_windows_private_directory(home)
    assert bound == [home]

    clock[0] += store_base._WINDOWS_PRIVATE_DIRECTORY_RECHECK_SECONDS
    store_base._set_windows_private_directory(home)
    assert bound == [home, home]

    # A directory swapped in under the same path is bound again at once.
    home.rename(tmp_path / "guard-home-old")
    home.mkdir()
    store_base._set_windows_private_directory(home)
    assert bound == [home, home, home]

    def fail(path: Path) -> None:
        bound.append(path)
        raise OSError("denied")

    monkeypatch.setattr(native_policy_snapshot_windows_state, "_windows_ensure_private_directory", fail)
    clock[0] += store_base._WINDOWS_PRIVATE_DIRECTORY_RECHECK_SECONDS
    store_base._set_windows_private_directory(home)
    store_base._set_windows_private_directory(home)
    assert len(bound) == 5


def test_windows_directory_behind_a_junction_is_bound_every_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_policy_snapshot_windows_state, store_base

    bound: list[Path] = []
    monkeypatch.setattr(native_policy_snapshot_windows_state, "_windows_ensure_private_directory", bound.append)
    monkeypatch.setattr(store_base, "_windows_private_directory_bound", {})
    home = tmp_path / "parent" / "guard-home"
    home.mkdir(parents=True)
    store_base._set_windows_private_directory(home)
    store_base._set_windows_private_directory(home)
    assert bound == [home]

    # An ancestor swapped for a junction to the same directory keeps the final
    # identity, so only the component walk can see it.
    junction = os.path.normcase(os.path.abspath(home.parent))
    real_lstat = os.lstat

    def lstat(path: os.PathLike[str] | str) -> object:
        info = real_lstat(path)
        if os.path.normcase(os.path.abspath(path)) != junction:
            return info
        return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)

    monkeypatch.setattr(store_base.os, "lstat", lstat)
    store_base._set_windows_private_directory(home)
    store_base._set_windows_private_directory(home)
    assert bound == [home, home, home]
