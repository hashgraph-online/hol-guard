"""Windows native snapshot storage-binding tests."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module
import codex_plugin_scanner.guard.native_policy_snapshot_windows_state as windows_state

__test__ = False


def test_windows_private_state_binding_closes_replaced_state_handle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kernel32 = object()
    guard_handle = object()
    initial_state_handle = object()
    replacement_state_handle = object()
    closed: list[object] = []

    @contextmanager
    def private_descriptor(_directory: bool):
        yield object(), object(), object(), "S-1-5-21-1"

    def bind_path(*_args: object, **_kwargs: object) -> windows_state._WindowsDirectoryBinding:
        return windows_state._WindowsDirectoryBinding(tmp_path / "guard", [(kernel32, guard_handle)])

    def bind_component(*_args: object, **_kwargs: object) -> tuple[bool, tuple[object, object]]:
        return False, (kernel32, initial_state_handle)

    monkeypatch.setattr(snapshot_module, "_windows_private_descriptor", private_descriptor)
    monkeypatch.setattr(windows_state, "_windows_bind_directory_path", bind_path)
    monkeypatch.setattr(windows_state, "_windows_bind_directory_component", bind_component)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_close_handle",
        lambda _kernel, handle: closed.append(handle),
    )

    with windows_state._windows_private_state_binding(tmp_path / "guard") as binding:
        assert binding.handles[-1] == (kernel32, initial_state_handle)
        binding.handles.pop()
        binding.handles.append((kernel32, replacement_state_handle))

    assert closed == [replacement_state_handle, guard_handle]
