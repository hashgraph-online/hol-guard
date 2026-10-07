"""Request directory validation retains its trusted-root boundaries."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import directory_path_authority
from codex_plugin_scanner.guard.daemon import server as server_module
from codex_plugin_scanner.path_support import resolve_path_within_allowed_roots


def test_trusted_guard_directory_roots_omits_redundant_child_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(directory_path_authority.Path, "home", classmethod(lambda cls: home))

    assert directory_path_authority.trusted_guard_directory_roots(home / ".hol-guard" / "config.toml") == (home,)
    assert directory_path_authority.trusted_guard_directory_roots(tmp_path / "external" / "config.toml") == (
        home,
        tmp_path / "external",
    )


@pytest.mark.parametrize("relative", [".", "workspace", "workspace/../workspace"])
def test_directory_validators_accept_only_canonical_paths_inside_selected_root(tmp_path: Path, relative: str) -> None:
    root = tmp_path / "root"
    (root / "workspace").mkdir(parents=True)
    candidate = root / relative
    handler = object.__new__(server_module._GuardDaemonHandler)

    assert handler._validate_hook_directory_path("home", str(candidate), roots=(root,)) == candidate.resolve()
    assert resolve_path_within_allowed_roots(str(candidate), (root,), require_exists=True) == candidate.resolve()


@pytest.mark.parametrize("relative", ["root-other", "root/../outside"])
def test_directory_validators_reject_prefix_collisions_and_traversal(tmp_path: Path, relative: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    candidate = tmp_path / relative
    candidate.mkdir(parents=True, exist_ok=True)
    handler = object.__new__(server_module._GuardDaemonHandler)

    with pytest.raises(server_module._HookPathValidationError, match="invalid_hook_home_path"):
        handler._validate_hook_directory_path("home", str(candidate), roots=(root,))
    assert resolve_path_within_allowed_roots(str(candidate), (root,), require_exists=True) is None


def test_directory_validators_resolve_symlinks_before_authorizing_the_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "workspace"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    handler = object.__new__(server_module._GuardDaemonHandler)

    with pytest.raises(server_module._HookPathValidationError, match="invalid_hook_home_path"):
        handler._validate_hook_directory_path("home", str(link), roots=(root,))
    assert resolve_path_within_allowed_roots(str(link), (root,), require_exists=True) is None


def test_supply_chain_directory_validation_preserves_relative_path_and_existence_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.chdir(tmp_path)

    assert resolve_path_within_allowed_roots("root", (root,), require_exists=True) == root.resolve()
    assert resolve_path_within_allowed_roots("root/missing", (root,)) == root / "missing"
    assert resolve_path_within_allowed_roots("root/missing", (root,), require_exists=True) is None
    assert resolve_path_within_allowed_roots("root", (), require_exists=True) is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner-checked temporary workspace")
def test_temporary_workspace_requires_existing_owned_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    handler = object.__new__(server_module._GuardDaemonHandler)

    assert handler._validate_hook_directory_path("workspace", str(workspace), roots=()) == workspace.resolve()
    assert handler._validated_owned_temporary_hook_workspace(str(tmp_path / "missing")) is None
    file_path = tmp_path / "file"
    file_path.write_text("not a directory", encoding="utf-8")
    assert handler._validated_owned_temporary_hook_workspace(str(file_path)) is None
    owner = workspace.stat().st_uid
    monkeypatch.setattr(server_module.os, "getuid", lambda: owner + 1)
    assert handler._validated_owned_temporary_hook_workspace(str(workspace)) is None


def test_temporary_root_is_not_itself_a_hook_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    handler = object.__new__(server_module._GuardDaemonHandler)
    monkeypatch.setattr(server_module.tempfile, "gettempdir", lambda: str(tmp_path))

    assert handler._normalized_hook_workspace_string(str(tmp_path)) is None
    assert handler._validated_owned_temporary_hook_workspace(str(tmp_path)) is None
