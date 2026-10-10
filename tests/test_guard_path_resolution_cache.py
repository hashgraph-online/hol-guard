from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import path_resolution_cache as cache


@pytest.fixture(autouse=True)
def _clear() -> None:
    cache.clear_cached_realpaths()


def test_matches_realpath_for_symlinked_directory(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    assert cache.cached_realpath(os.fspath(link)) == os.path.realpath(link)
    assert cache.cached_realpath(os.fspath(link)) == os.path.realpath(link)


def test_repointed_symlink_is_resolved_again(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    link = tmp_path / "link"
    link.symlink_to(first)
    assert cache.cached_realpath(os.fspath(link)) == os.path.realpath(first)
    link.unlink()
    link.symlink_to(second)
    assert cache.cached_realpath(os.fspath(link)) == os.path.realpath(second)


def test_missing_path_is_never_remembered(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert cache.cached_realpath(os.fspath(missing)) == os.path.realpath(missing)
    missing.mkdir()
    assert cache.cached_realpath(os.fspath(missing)) == os.path.realpath(missing)
    with pytest.raises(FileNotFoundError):
        cache.cached_realpath(os.fspath(tmp_path / "other"), strict=True)


def test_renamed_directory_replaced_by_a_symlink_is_resolved_again(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    directory = root / "workspace"
    directory.mkdir()
    remembered = cache.cached_realpath(os.fspath(directory))
    moved = outside / "workspace"
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)

    resolved = cache.cached_realpath(os.fspath(directory))

    assert resolved == os.path.realpath(directory)
    assert resolved != remembered


def test_ancestor_replaced_by_a_symlink_is_resolved_again(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    elsewhere = tmp_path / "elsewhere"
    allowed.mkdir()
    elsewhere.mkdir()
    workspace = allowed / "workspace"
    workspace.mkdir()
    remembered = cache.cached_realpath(os.fspath(workspace))
    moved = elsewhere / "allowed"
    allowed.rename(moved)
    allowed.symlink_to(moved, target_is_directory=True)

    resolved = cache.cached_realpath(os.fspath(workspace))

    assert resolved == os.path.realpath(workspace)
    assert resolved != remembered


def test_remembered_spelling_expires(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = tmp_path / "dir"
    directory.mkdir()
    now = [100.0]
    monkeypatch.setattr(cache.time, "monotonic", lambda: now[0])
    calls: list[str] = []
    real = os.path.realpath

    def counting(path: str, *, strict: bool = False) -> str:
        calls.append(path)
        return real(path, strict=strict)

    monkeypatch.setattr(cache.os.path, "realpath", counting)
    cache.cached_realpath(os.fspath(directory))
    cache.cached_realpath(os.fspath(directory))
    assert len(calls) == 1
    now[0] += cache._RESOLUTION_LIFETIME_SECONDS + 0.1
    cache.cached_realpath(os.fspath(directory))
    assert len(calls) == 2
