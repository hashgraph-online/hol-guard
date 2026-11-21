"""The storage gate takes a real shared lock on Windows, matching Rust fs2."""

from __future__ import annotations

import ctypes
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_command_control_windows_lock as lock
from codex_plugin_scanner.guard import store_storage_gate as gate

_FAIL_IMMEDIATELY = 0x1
_EXCLUSIVE = 0x2
_FS2_RANGE = 0xFFFFFFFF


@pytest.mark.parametrize(("shared", "expected_flags"), [(True, 1), (False, 3)])
def test_whole_file_lease_uses_the_fs2_range(monkeypatch, shared, expected_flags) -> None:
    calls = []

    def acquire(handle, flags, reserved, low, high, overlapped):
        record = ctypes.cast(overlapped, ctypes.POINTER(lock._Overlapped)).contents
        calls.append((handle, flags, reserved, low, high, record.Offset, record.OffsetHigh))
        return 1

    def release(handle, reserved, low, high, overlapped):
        calls.append((handle, reserved, low, high))
        return 1

    monkeypatch.setattr(lock, "_os_handle", lambda fd: {17: 0x1234}[fd])
    monkeypatch.setattr(lock, "_kernel32", lambda: SimpleNamespace(LockFileEx=acquire, UnlockFileEx=release))
    lock.try_lock_whole_file(17, shared=shared)
    lock.unlock_whole_file(17)
    assert calls == [
        (0x1234, expected_flags, 0, _FS2_RANGE, _FS2_RANGE, 0, 0),
        (0x1234, 0, _FS2_RANGE, _FS2_RANGE),
    ]


@pytest.mark.parametrize("exclusive", [False, True])
def test_windows_gate_takes_the_whole_file_lease(monkeypatch, tmp_path: Path, exclusive) -> None:
    calls = []
    monkeypatch.setattr(gate, "os", SimpleNamespace(name="nt", path=os.path))
    monkeypatch.setattr(lock, "try_lock_whole_file", lambda fd, *, shared: calls.append(("lock", shared)))
    monkeypatch.setattr(lock, "unlock_whole_file", lambda fd: calls.append(("unlock",)))
    with gate.hold_storage_gate(tmp_path, exclusive=exclusive):
        assert calls == [("lock", not exclusive)]
    assert calls == [("lock", not exclusive), ("unlock",)]
    # Nothing is written into the gate file; a lock range needs no content.
    assert (tmp_path / "storage-access.lock").read_bytes() == b""


def _fs2_hold(path: Path, *, exclusive: bool):
    """Lock a second handle exactly as Rust ``fs2`` does on Windows."""

    handle = path.open("a+b")
    overlapped = lock._Overlapped()
    flags = _FAIL_IMMEDIATELY | (_EXCLUSIVE if exclusive else 0)
    os_handle = lock._os_handle(handle.fileno())
    if not lock._kernel32().LockFileEx(os_handle, flags, 0, _FS2_RANGE, _FS2_RANGE, ctypes.byref(overlapped)):
        handle.close()
        return None
    return handle


def _release(handle) -> None:
    lock.unlock_whole_file(handle.fileno())
    handle.close()


@pytest.mark.skipif(os.name != "nt", reason="real Windows LockFileEx contention")
def test_rust_shared_hold_admits_python_readers_promptly(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(gate, "sqlite_connect_timeout_seconds", lambda: 2.0)
    rust = _fs2_hold(tmp_path / "storage-access.lock", exclusive=False)
    assert rust is not None
    try:
        started = time.monotonic()
        with gate.hold_storage_gate(tmp_path, exclusive=False):
            assert time.monotonic() - started < 0.5
            # A second Rust reader still joins while Python reads.
            other = _fs2_hold(tmp_path / "storage-access.lock", exclusive=False)
            assert other is not None
            _release(other)
        with gate.try_hold_storage_gate(tmp_path, exclusive=True) as held:
            assert held is False
    finally:
        _release(rust)
    with gate.try_hold_storage_gate(tmp_path, exclusive=True) as held:
        assert held is True
        assert _fs2_hold(tmp_path / "storage-access.lock", exclusive=False) is None
