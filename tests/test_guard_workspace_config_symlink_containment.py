"""Workspace config reads must stay within the admitted workspace."""

from __future__ import annotations

import builtins
import io
import os
from collections.abc import Callable
from pathlib import Path
from typing import ParamSpec, TypeVar

import pytest

from codex_plugin_scanner.guard import config
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

_P = ParamSpec("_P")
_T = TypeVar("_T")


def _admitted_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    authorized_home = tmp_path / "authorized-home"
    workspace = authorized_home / "workspace"
    workspace.mkdir(parents=True)
    handler = object.__new__(_GuardDaemonHandler)
    # Supply a hermetic trusted root while retaining actual directory admission.
    monkeypatch.setattr(handler, "_hook_safe_roots", lambda: (authorized_home,))
    admitted_workspace, admitted_home = handler._validated_fail_safe_hook_paths(
        {"workspace": [str(workspace)], "home": [str(authorized_home)]}
    )
    assert admitted_workspace is not None
    assert admitted_workspace == workspace.resolve()
    assert admitted_home == authorized_home.resolve()
    return admitted_workspace


def _observe_target_opens(monkeypatch: pytest.MonkeyPatch, target: os.stat_result) -> Callable[[], bool]:
    opened_target = False

    def observe(open_function: Callable[_P, _T]) -> Callable[_P, _T]:
        def call(*args: _P.args, **kwargs: _P.kwargs) -> _T:
            nonlocal opened_target
            handle = open_function(*args, **kwargs)
            if isinstance(handle, int):
                descriptor = handle
            elif isinstance(handle, io.IOBase):
                descriptor = handle.fileno()
            else:
                raise AssertionError("The real open returned an unexpected handle.")
            actual = os.fstat(descriptor)
            if (actual.st_dev, actual.st_ino) == (target.st_dev, target.st_ino):
                opened_target = True
            return handle

        return call

    monkeypatch.setattr(io, "open", observe(io.open))
    monkeypatch.setattr(builtins, "open", observe(builtins.open))
    monkeypatch.setattr(os, "open", observe(os.open))
    return lambda: opened_target


@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
def test_admitted_workspace_never_opens_config_symlink_outside_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    workspace = _admitted_workspace(tmp_path, monkeypatch)
    outside_root = tmp_path / "outside-workspace"
    outside_root.mkdir()
    outside_target = outside_root / "sentinel.toml"
    outside_target.write_text('workspace_marker = "outside"\n', encoding="utf-8")
    assert not outside_target.is_relative_to(workspace.parent)
    (workspace / filename).symlink_to(outside_target)
    target_identity = outside_target.stat()

    with monkeypatch.context() as observation:
        was_target_opened = _observe_target_opens(observation, target_identity)
        loaded = config._load_workspace_guard_config(workspace)

    # Failures expose only a boolean; the observer never supplies or blocks data.
    assert was_target_opened() is False
    assert "workspace_marker" not in loaded


@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
def test_admitted_workspace_loads_regular_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    workspace = _admitted_workspace(tmp_path, monkeypatch)
    (workspace / filename).write_text(
        'workspace_marker = "inside"\nmode = "observe"\nprotection_posture = "off"\n',
        encoding="utf-8",
    )

    loaded = config._load_workspace_guard_config(workspace)

    assert loaded == {"workspace_marker": "inside"}
