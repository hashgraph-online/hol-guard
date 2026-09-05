"""Windows native-policy state binding ownership regressions."""

from __future__ import annotations

import types
from contextlib import contextmanager
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_windows_state as windows_state
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError


def _install_state_binding_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    closed: list[tuple[object, object]],
) -> tuple[types.SimpleNamespace, tuple[object, object], tuple[object, object], set[object]]:
    guard_handle = (object(), object())
    state_handle = (object(), object())
    live_handles = {guard_handle[1], state_handle[1]}

    @contextmanager
    def private_descriptor(_directory: bool):
        yield object(), object(), object(), "S-1-5-21-1"

    def close_handle(kernel32: object, handle: object) -> None:
        if handle not in live_handles:
            raise NativePolicySnapshotError("native_policy_windows_handle_close_failed")
        live_handles.remove(handle)
        closed.append((kernel32, handle))

    api = types.SimpleNamespace(
        _windows_private_descriptor=private_descriptor,
        _windows_close_handle=close_handle,
    )
    monkeypatch.setattr(windows_state, "_snapshot_api", lambda: api)
    monkeypatch.setattr(
        windows_state,
        "_windows_bind_directory_path",
        lambda *_args, **_kwargs: windows_state._WindowsDirectoryBinding(Path("C:/Guard"), [guard_handle]),
    )
    monkeypatch.setattr(
        windows_state,
        "_windows_bind_directory_component",
        lambda *_args, **_kwargs: (False, state_handle),
    )
    return api, guard_handle, state_handle, live_handles


def test_windows_private_state_binding_closes_refreshed_barrier_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[tuple[object, object]] = []
    api, guard_handle, original_state_handle, live_handles = _install_state_binding_fakes(monkeypatch, closed=closed)
    restored_state_handle = (object(), object())

    with windows_state._windows_private_state_binding(Path("C:/Guard")) as binding:
        released = binding.handles.pop()
        assert released == original_state_handle
        api._windows_close_handle(*released)
        live_handles.add(restored_state_handle[1])
        binding.handles.append(restored_state_handle)

    assert closed == [original_state_handle, restored_state_handle, guard_handle]


def test_windows_private_state_binding_does_not_reclose_released_barrier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[tuple[object, object]] = []
    api, guard_handle, original_state_handle, _live_handles = _install_state_binding_fakes(monkeypatch, closed=closed)

    with windows_state._windows_private_state_binding(Path("C:/Guard")) as binding:
        released = binding.handles.pop()
        assert released == original_state_handle
        api._windows_close_handle(*released)

    assert closed == [original_state_handle, guard_handle]
