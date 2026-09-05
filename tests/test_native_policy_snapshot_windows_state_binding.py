"""Windows native-policy state binding ownership regressions."""

from __future__ import annotations

import types
from contextlib import contextmanager
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_windows_atomic as windows_atomic
import codex_plugin_scanner.guard.native_policy_snapshot_windows_state as windows_state
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError


def _install_state_binding_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    closed: list[tuple[object, object]],
) -> tuple[types.SimpleNamespace, tuple[object, object], tuple[object, object], set[object]]:
    """Install deterministic handle ownership fakes for state-binding tests."""

    guard_handle = (object(), object())
    state_handle = (object(), object())
    live_handles = {guard_handle[1], state_handle[1]}

    @contextmanager
    def private_descriptor(_directory: bool):
        """Yield a minimal private-descriptor contract for the binding."""

        yield object(), object(), object(), "S-1-5-21-1"

    def close_handle(kernel32: object, handle: object) -> None:
        """Close each synthetic handle exactly once and record ownership release."""

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
    """Close the live replacement handle rather than the released stale barrier."""

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
    """Avoid a second close when a released state barrier has no replacement."""

    closed: list[tuple[object, object]] = []
    api, guard_handle, original_state_handle, _live_handles = _install_state_binding_fakes(monkeypatch, closed=closed)

    with windows_state._windows_private_state_binding(Path("C:/Guard")) as binding:
        released = binding.handles.pop()
        assert released == original_state_handle
        api._windows_close_handle(*released)

    assert closed == [original_state_handle, guard_handle]


def test_windows_rename_barrier_retains_handle_when_release_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain barrier ownership until CloseHandle succeeds so outer cleanup retries."""

    closed: list[tuple[object, object]] = []
    api, guard_handle, original_state_handle, _live_handles = _install_state_binding_fakes(monkeypatch, closed=closed)
    original_close = api._windows_close_handle
    failed_release = False

    def fail_first_state_close(kernel32: object, handle: object) -> None:
        """Fail the first state-barrier release while allowing cleanup retry."""

        nonlocal failed_release
        if handle == original_state_handle[1] and not failed_release:
            failed_release = True
            raise NativePolicySnapshotError("native_policy_windows_handle_close_failed")
        original_close(kernel32, handle)

    api._windows_close_handle = fail_first_state_close
    monkeypatch.setattr(
        windows_atomic,
        "_windows_rename_file_handle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("rename must not run after failed release")),
    )

    with pytest.raises(NativePolicySnapshotError, match="handle_close_failed"):
        with windows_state._windows_private_state_binding(Path("C:/Guard")) as binding:
            windows_atomic._windows_rename_releasing_barrier(
                api=api,
                kernel32=object(),
                source_handle=object(),
                parent_path=binding.path,
                parent_handle=binding.handle,
                destination_name="snapshot.json",
                replace_existing=True,
                directory_handles=binding.handles,
            )

    assert failed_release
    assert closed == [original_state_handle, guard_handle]


def test_windows_rename_barrier_preserves_rename_failure_after_restoring_barrier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Propagate rename failure while restoring and later closing a new barrier handle."""

    closed: list[tuple[object, object]] = []
    api, guard_handle, original_state_handle, live_handles = _install_state_binding_fakes(monkeypatch, closed=closed)
    rename_handle = (object(), object())
    restored_state_handle = (object(), object())
    opened = 0

    def open_handle(*_args: object, **kwargs: object) -> tuple[object, object, object]:
        """Open the temporary rename parent first and restored exclusive barrier second."""

        nonlocal opened
        opened += 1
        selected = rename_handle if kwargs.get("rename_parent") else restored_state_handle
        live_handles.add(selected[1])
        return selected[0], selected[1], object()

    api._windows_open_handle = open_handle
    monkeypatch.setattr(
        windows_atomic,
        "_windows_rename_file_handle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            NativePolicySnapshotError("native_policy_windows_replace_failed")
        ),
    )

    with pytest.raises(NativePolicySnapshotError, match="replace_failed"):
        with windows_state._windows_private_state_binding(Path("C:/Guard")) as binding:
            windows_atomic._windows_rename_releasing_barrier(
                api=api,
                kernel32=object(),
                source_handle=object(),
                parent_path=binding.path,
                parent_handle=binding.handle,
                destination_name="snapshot.json",
                replace_existing=True,
                directory_handles=binding.handles,
            )

    assert opened == 2
    assert closed == [original_state_handle, rename_handle, restored_state_handle, guard_handle]
