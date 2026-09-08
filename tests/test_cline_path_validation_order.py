"""Validate persisted Cline paths before querying their filesystem nodes."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_paths import ensure_safe_cline_destination


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    monkeypatch.delenv("CLINE_DIR", raising=False)
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home, None, tmp_path / "guard")


@pytest.mark.parametrize("suffix", ["../outside/hook", "nested/../hook", "nested/../../outside/hook"])
def test_parent_segments_are_rejected_before_resolving_untrusted_paths(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    destination = context.home_dir / suffix
    resolve = Path.resolve

    def trusted_resolve(path: Path, *args, **kwargs):
        if ".." in path.parts:
            raise AssertionError("parent traversal reached filesystem resolution")
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", trusted_resolve)
    with pytest.raises(RuntimeError, match="escapes"):
        ensure_safe_cline_destination(context, destination)


@pytest.mark.parametrize("outside", [False, True])
@pytest.mark.parametrize("dangling", [False, True])
def test_symlink_ancestors_are_rejected_before_resolution(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch, outside: bool, dangling: bool
) -> None:
    target = (context.home_dir.parent if outside else context.home_dir) / "target"
    if not dangling:
        target.mkdir()
    link = context.home_dir / "hooks"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    resolve = Path.resolve

    def trusted_resolve(path: Path, *args, **kwargs):
        if path == link or path.is_relative_to(link):
            raise AssertionError("symlink ancestor was resolved before rejection")
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", trusted_resolve)
    with pytest.raises(RuntimeError, match="symlink"):
        ensure_safe_cline_destination(context, link / "PreToolUse")


@pytest.mark.parametrize("root_name", ["home", "guard"])
def test_missing_destination_under_each_trusted_root_is_valid(context: HarnessContext, root_name: str) -> None:
    root = context.home_dir if root_name == "home" else context.guard_home
    destination = root / "nested" / "hook"
    ensure_safe_cline_destination(context, destination)
    assert not destination.exists()


def test_untrusted_destination_is_rejected_before_lstat(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = context.home_dir.parent / "home-other" / "hook"
    is_symlink = Path.is_symlink

    def trusted_is_symlink(path: Path):
        if path == outside or path == outside.parent:
            raise AssertionError("out-of-root path reached a filesystem probe")
        return is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", trusted_is_symlink)
    with pytest.raises(RuntimeError, match="escapes"):
        ensure_safe_cline_destination(context, outside)


def test_outer_symlink_is_rejected_before_probing_descendants(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = context.home_dir.parent / "outside"
    (target / "nested").mkdir(parents=True)
    link = context.home_dir / "hooks"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    is_symlink = Path.is_symlink

    def trusted_is_symlink(path: Path):
        if path != link and path.is_relative_to(link):
            raise AssertionError("descendant probe traversed an unchecked symlink")
        return is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", trusted_is_symlink)
    with pytest.raises(RuntimeError, match="symlink"):
        ensure_safe_cline_destination(context, link / "nested" / "PreToolUse")
