"""Windows private directory provisioning and handle-bound ancestry."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .native_policy_snapshot_constants import (
    _WINDOWS_ERROR_ALREADY_EXISTS,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    NativePolicySnapshotError,
)


@dataclass
class _WindowsDirectoryBinding:
    """Open directory ancestry held until the caller finishes its mutation."""

    path: Path
    handles: list[tuple[Any, Any]]

    @property
    def kernel32(self) -> Any:
        return self.handles[-1][0]

    @property
    def handle(self) -> Any:
        return self.handles[-1][1]


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily, preserving established monkeypatch seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _windows_create_directory(path: Path, descriptor: Any, api: Any) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = api._windows_dll("kernel32")
    create_directory = kernel32.CreateDirectoryW
    create_directory.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    create_directory.restype = wintypes.BOOL
    security_attributes_type = api._windows_security_attributes_type()
    security_attributes = security_attributes_type(
        ctypes.sizeof(security_attributes_type), descriptor, wintypes.BOOL(False)
    )
    if create_directory(str(path), ctypes.byref(security_attributes)):
        return True
    if ctypes.get_last_error() == _WINDOWS_ERROR_ALREADY_EXISTS:
        return False
    raise NativePolicySnapshotError("native_policy_windows_state_directory_create_failed")


def _windows_bind_directory_component(
    path: Path,
    *,
    api: Any,
    descriptor: Any,
    dacl: Any,
    owner_sid: str,
    private: bool,
) -> tuple[bool, tuple[Any, Any]]:
    created = _windows_create_directory(path, descriptor, api)
    kernel32, handle, _information = api._windows_open_handle(
        path,
        directory=True,
        repair=False,
        lock=True,
        add_file=private,
    )
    opened = True
    try:
        if private:
            if not created:
                api._windows_verify_private_owner(handle, owner_sid=owner_sid)
                try:
                    api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=True)
                except NativePolicySnapshotError:
                    api._windows_close_handle(kernel32, handle)
                    opened = False
                    kernel32, handle, _information = api._windows_open_handle(
                        path,
                        directory=True,
                        repair=True,
                        lock=True,
                        add_file=private,
                    )
                    opened = True
                    api._windows_verify_private_owner(handle, owner_sid=owner_sid)
                    api._windows_apply_private_dacl(kernel32, handle, descriptor, dacl, True)
                    api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=True)
                    api._windows_close_handle(kernel32, handle)
                    opened = False
                    kernel32, handle, _information = api._windows_open_handle(
                        path,
                        directory=True,
                        repair=False,
                        lock=True,
                        add_file=private,
                    )
                    opened = True
                    api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=True)
            else:
                api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=True)
        return created, (kernel32, handle)
    except BaseException:
        if opened:
            with suppress(BaseException):
                api._windows_close_handle(kernel32, handle)
        raise


def _windows_bind_directory_path(
    path: Path,
    *,
    api: Any,
    descriptor: Any,
    dacl: Any,
    owner_sid: str,
) -> _WindowsDirectoryBinding:
    absolute = Path(os.path.abspath(path))
    if not absolute.anchor:
        raise NativePolicySnapshotError("native_policy_windows_state_directory_invalid")
    current = Path(absolute.anchor)
    handles: list[tuple[Any, Any]] = []
    try:
        for part in absolute.parts[1:]:
            current /= part
            _created, opened = _windows_bind_directory_component(
                current,
                api=api,
                descriptor=descriptor,
                dacl=dacl,
                owner_sid=owner_sid,
                private=current == absolute,
            )
            handles.append(opened)
        if not handles:
            raise NativePolicySnapshotError("native_policy_windows_state_directory_invalid")
        return _WindowsDirectoryBinding(absolute, handles)
    except BaseException:
        for kernel32, handle in reversed(handles):
            with suppress(BaseException):
                api._windows_close_handle(kernel32, handle)
        raise


def _windows_close_directory_binding(binding: _WindowsDirectoryBinding, api: Any) -> None:
    close_error: NativePolicySnapshotError | None = None
    for kernel32, handle in reversed(binding.handles):
        try:
            api._windows_close_handle(kernel32, handle)
        except NativePolicySnapshotError as error:
            close_error = close_error or error
    if close_error is not None:
        raise close_error


@contextmanager
def _windows_private_directory_binding(path: Path) -> Iterator[_WindowsDirectoryBinding]:
    """Bind a private directory and every existing ancestor until exit."""

    api = _snapshot_api()
    with api._windows_private_descriptor(True) as (_advapi32, descriptor, dacl, owner_sid):
        binding = _windows_bind_directory_path(
            path,
            api=api,
            descriptor=descriptor,
            dacl=dacl,
            owner_sid=owner_sid,
        )
        try:
            yield binding
        finally:
            _windows_close_directory_binding(binding, api)


@contextmanager
def _windows_private_state_binding(guard_home: Path) -> Iterator[_WindowsDirectoryBinding]:
    """Hold guard-home and runtime-state directory identities across writes."""

    api = _snapshot_api()
    with api._windows_private_descriptor(True) as (_advapi32, descriptor, dacl, owner_sid):
        guard_binding = _windows_bind_directory_path(
            guard_home,
            api=api,
            descriptor=descriptor,
            dacl=dacl,
            owner_sid=owner_sid,
        )
        binding: _WindowsDirectoryBinding | None = None
        try:
            state_path = guard_binding.path / NATIVE_RUNTIME_STATE_DIRECTORY
            _created, state_handle = _windows_bind_directory_component(
                state_path,
                api=api,
                descriptor=descriptor,
                dacl=dacl,
                owner_sid=owner_sid,
                private=True,
            )
            binding = _WindowsDirectoryBinding(
                state_path,
                [*guard_binding.handles, state_handle],
            )
            yield binding
        finally:
            try:
                if binding is not None:
                    state_handles = binding.handles[len(guard_binding.handles) :]
                    _windows_close_directory_binding(_WindowsDirectoryBinding(binding.path, state_handles), api)
            finally:
                _windows_close_directory_binding(guard_binding, api)


def _windows_ensure_private_directory(path: Path) -> None:
    try:
        with _windows_private_directory_binding(path):
            pass
    except NativePolicySnapshotError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_windows_state_directory_invalid") from error
