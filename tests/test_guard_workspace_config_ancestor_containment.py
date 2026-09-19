"""Ancestor replacement must not redirect an admitted workspace config read."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from tests.test_guard_workspace_config_symlink_containment import _observe_target_opens


def _admit_nested_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    authorized_home = tmp_path / "authorized-home"
    workspace = authorized_home / "parent" / "workspace"
    workspace.mkdir(parents=True)
    handler = object.__new__(_GuardDaemonHandler)
    monkeypatch.setattr(handler, "_hook_safe_roots", lambda: (authorized_home,))
    admitted_workspace, admitted_home = handler._validated_fail_safe_hook_paths(
        {"workspace": [str(workspace)], "home": [str(authorized_home)]}
    )
    assert admitted_workspace is not None
    assert admitted_workspace == workspace.resolve()
    assert admitted_home == authorized_home.resolve()
    return admitted_workspace


@pytest.mark.skipif(os.name != "posix", reason="Exercises a POSIX ancestor replacement.")
@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
def test_admitted_workspace_ancestor_swap_never_opens_outside_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    workspace = _admit_nested_workspace(tmp_path, monkeypatch)
    (workspace / filename).write_text('workspace_marker = "inside"\n', encoding="utf-8")
    outside_parent = tmp_path / "outside-parent"
    outside_workspace = outside_parent / "workspace"
    outside_workspace.mkdir(parents=True)
    outside_target = outside_workspace / filename
    outside_target.write_text('workspace_marker = "outside"\n', encoding="utf-8")
    target_identity = outside_target.stat()
    assert not outside_target.is_relative_to(workspace.parent.parent)

    parent = workspace.parent
    parent.rename(parent.with_name("retired-parent"))
    parent.symlink_to(outside_parent, target_is_directory=True)
    assert parent.is_symlink()
    assert not workspace.is_symlink()
    assert workspace.is_dir()

    with monkeypatch.context() as observation:
        was_target_opened = _observe_target_opens(observation, target_identity)
        loaded = config._load_workspace_guard_config(workspace)

    opened_outside = was_target_opened()
    loaded_outside = loaded.get("workspace_marker") == "outside"
    print(f"ANCESTOR_SWAP outside_open={opened_outside} outside_content={loaded_outside}")
    assert opened_outside is False
    assert loaded_outside is False


@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
def test_admitted_workspace_unchanged_ancestor_loads_regular_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    workspace = _admit_nested_workspace(tmp_path, monkeypatch)
    (workspace / filename).write_text(
        'workspace_marker = "inside"\nmode = "observe"\nprotection_posture = "off"\n',
        encoding="utf-8",
    )

    loaded = config._load_workspace_guard_config(workspace)

    assert loaded == {"workspace_marker": "inside"}
