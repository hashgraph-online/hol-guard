"""Cline file operands must be rebuilt beneath a trusted, checked root."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_paths import (
    _checked_cline_destination,
    ensure_safe_cline_destination,
)
from codex_plugin_scanner.guard.adapters.cline_state_paths import _canonical_saved_hook_root


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    monkeypatch.delenv("CLINE_DIR", raising=False)
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home, None, tmp_path / "guard")


@pytest.mark.parametrize("root_name", ["home", "guard"])
def test_trusted_root_itself_is_not_a_destination(context: HarnessContext, root_name: str) -> None:
    root = context.home_dir if root_name == "home" else context.guard_home
    with pytest.raises(RuntimeError, match="escapes"):
        ensure_safe_cline_destination(context, root)


def test_null_byte_is_rejected_before_any_filesystem_probe(context: HarnessContext, monkeypatch) -> None:
    def unexpected_probe(*args, **kwargs):
        raise AssertionError("invalid destination reached a filesystem probe")

    monkeypatch.setattr(Path, "resolve", unexpected_probe)
    with pytest.raises(RuntimeError, match="escapes"):
        ensure_safe_cline_destination(context, context.home_dir / "hook\x00other")


def test_relative_destination_returns_its_absolute_checked_operand(context: HarnessContext, monkeypatch) -> None:
    monkeypatch.chdir(context.home_dir)
    checked = ensure_safe_cline_destination(context, Path("hooks") / "PreToolUse")
    assert checked == context.home_dir / "hooks" / "PreToolUse"


@pytest.mark.parametrize("root_name", ["home", "guard"])
def test_reconstruction_preserves_non_ascii_and_dotted_basenames(context: HarnessContext, root_name: str) -> None:
    root = context.home_dir if root_name == "home" else context.guard_home
    destination = root / "Cline user data" / "hooks.v2" / "pré-tool.py"
    assert ensure_safe_cline_destination(context, destination) == destination


@pytest.mark.parametrize("component", ["..", "/"])
def test_reconstruction_rejects_parent_or_root_components(context: HarnessContext, component: str) -> None:
    with pytest.raises(RuntimeError, match="unsafe path component"):
        _checked_cline_destination(context.home_dir, Path(component), context.home_dir, context.guard_home)


def test_final_resolution_must_still_stay_within_trusted_roots(context: HarnessContext, monkeypatch) -> None:
    destination = context.home_dir / "hooks" / "PreToolUse"
    resolve = Path.resolve

    def changed_parent(path: Path, *args, **kwargs):
        if path == destination.parent:
            return context.home_dir.parent / "outside"
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", changed_parent)
    with pytest.raises(RuntimeError, match="escapes"):
        ensure_safe_cline_destination(context, destination)


@pytest.mark.parametrize("root_name", ["home", "guard"])
def test_symlink_trusted_root_is_rejected_before_descendant_probe(
    context: HarnessContext, monkeypatch, root_name
) -> None:
    root = context.home_dir if root_name == "home" else context.guard_home
    alias = root.parent / (root.name + "-alias")
    try:
        alias.symlink_to(root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    aliased = HarnessContext(
        alias if root_name == "home" else context.home_dir,
        None,
        alias if root_name == "guard" else context.guard_home,
    )
    is_symlink = Path.is_symlink

    def checked_probe(path: Path):
        if path != alias and path.is_relative_to(alias):
            raise AssertionError("descendant was probed before the root")
        return is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", checked_probe)
    with pytest.raises(RuntimeError, match="symlink"):
        ensure_safe_cline_destination(aliased, alias / "hook")


def test_saved_custom_root_uses_the_rebuilt_operand(context: HarnessContext) -> None:
    hooks = context.home_dir / "custom data" / "Hooks"
    hooks.mkdir(parents=True)
    assert _canonical_saved_hook_root(context, str(hooks)) == hooks
    assert _canonical_saved_hook_root(context, str(hooks / "missing" / "Hooks")) is None
    assert _canonical_saved_hook_root(context, str(context.guard_home / "Hooks")) is None
