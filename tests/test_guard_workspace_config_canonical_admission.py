"""Aliases admitted canonically still load their workspace configuration."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from tests.test_guard_workspace_config_ancestor_containment import _admit_nested_workspace


@pytest.mark.skipif(os.name != "posix", reason="Exercises a POSIX directory alias.")
@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
def test_existing_ancestor_alias_remains_readable_after_canonical_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    workspace = _admit_nested_workspace(tmp_path, monkeypatch)
    authorized_home = workspace.parent.parent
    alias_parent = authorized_home / "alias-parent"
    alias_parent.symlink_to(workspace.parent, target_is_directory=True)
    aliased_workspace = alias_parent / workspace.name
    (workspace / filename).write_text(
        'workspace_marker = "inside"\nmode = "observe"\nprotection_posture = "off"\n',
        encoding="utf-8",
    )
    handler = object.__new__(_GuardDaemonHandler)
    monkeypatch.setattr(handler, "_hook_safe_roots", lambda: (authorized_home,))
    admitted_workspace, admitted_home = handler._validated_fail_safe_hook_paths(
        {"workspace": [str(aliased_workspace)], "home": [str(authorized_home)]}
    )
    assert admitted_workspace is not None
    assert admitted_workspace == workspace
    assert admitted_home == authorized_home

    assert config._load_workspace_guard_config(admitted_workspace) == {"workspace_marker": "inside"}


@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
def test_plain_relative_parent_segment_keeps_workspace_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    workspace = _admit_nested_workspace(tmp_path, monkeypatch)
    (workspace / "child").mkdir()
    (workspace / filename).write_text(
        'workspace_marker = "inside"\nmode = "observe"\nprotection_posture = "off"\n',
        encoding="utf-8",
    )

    with monkeypatch.context() as location:
        location.chdir(workspace)
        loaded = config._load_workspace_guard_config(Path("child") / "..")

    assert loaded == {"workspace_marker": "inside"}
