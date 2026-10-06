"""Exact Win32 lease ABI and an independent real Windows process oracle."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard import native_command_control_windows_lock as lock


@pytest.mark.parametrize(("shared", "expected_flags"), [(True, 1), (False, 3)])
def test_lock_binds_verified_handle_nonblocking_range_and_shared_flag(monkeypatch, shared, expected_flags) -> None:
    calls = []

    def acquire(handle, flags, reserved, low, high, overlapped):
        record = ctypes.cast(overlapped, ctypes.POINTER(lock._Overlapped)).contents
        calls.append((handle, flags, reserved, low, high, record.Offset, record.OffsetHigh, record.hEvent))
        return 1

    monkeypatch.setattr(lock, "_os_handle", lambda fd: {17: 0x12345678}[fd])
    monkeypatch.setattr(lock, "_kernel32", lambda: SimpleNamespace(LockFileEx=acquire))
    lock.try_lock_authority_file(17, shared=shared)
    assert calls == [(0x12345678, expected_flags, 0, 1, 0, 0, 0, None)]


def test_unlock_uses_same_exact_range_and_handle(monkeypatch) -> None:
    calls = []

    def release(handle, reserved, low, high, overlapped):
        record = ctypes.cast(overlapped, ctypes.POINTER(lock._Overlapped)).contents
        calls.append((handle, reserved, low, high, record.Offset, record.OffsetHigh))
        return 1

    monkeypatch.setattr(lock, "_os_handle", lambda fd: {17: 0x12345678}[fd])
    monkeypatch.setattr(lock, "_kernel32", lambda: SimpleNamespace(UnlockFileEx=release))
    lock.unlock_authority_file(17)
    assert calls == [(0x12345678, 0, 1, 0, 0, 0)]


@pytest.mark.parametrize("operation", ["shared", "exclusive", "unlock"])
def test_win32_failure_does_not_admit_a_lease(monkeypatch, operation) -> None:
    expected = OSError("injected handle or lock failure")
    monkeypatch.setattr(lock, "_os_handle", lambda fd: fd)
    monkeypatch.setattr(
        lock, "_kernel32", lambda: SimpleNamespace(LockFileEx=lambda *args: 0, UnlockFileEx=lambda *args: 0)
    )
    monkeypatch.setattr(lock, "_last_error", lambda: expected)
    with pytest.raises(OSError) as raised:
        if operation == "unlock":
            lock.unlock_authority_file(17)
        else:
            lock.try_lock_authority_file(17, shared=operation == "shared")
    assert raised.value is expected


def test_overlapped_uses_windows_32_bit_dwords_on_every_host() -> None:
    pointer = ctypes.sizeof(ctypes.c_void_p)
    assert lock._Overlapped.Offset.offset == 2 * pointer
    assert lock._Overlapped.OffsetHigh.offset == 2 * pointer + 4
    assert lock._Overlapped.hEvent.offset == 2 * pointer + 8
    assert ctypes.sizeof(lock._Overlapped) == 3 * pointer + 8


def test_independent_child_open_shares_delete_with_live_private_creation_handle(tmp_path: Path) -> None:
    from ci.native_runtime import probe_installed_command_control_lock as probe

    calls = []

    def create(path, access, share, security, disposition, attributes, template):
        calls.append((path, access, share, security, disposition, attributes, template))
        # Model an existing parent handle retaining DELETE access. Rejecting
        # that sharing mode would prevent the independent lock oracle running.
        return 91 if share & 4 else ctypes.c_void_p(-1).value

    kernel32 = SimpleNamespace(CreateFileW=Mock(side_effect=create))
    path = tmp_path / "extension-control-authority.lock"
    assert probe._raw_child_file(kernel32, path) == 91
    assert calls == [(str(path), 0xC0000000, 7, None, 3, 0x00200080, None)]
    assert kernel32.CreateFileW.restype is ctypes.c_void_p


@pytest.mark.parametrize("invalid", [None, ctypes.c_void_p(-1).value])
def test_independent_child_open_failure_is_never_reported_as_lock_contention(tmp_path: Path, invalid) -> None:
    from ci.native_runtime import probe_installed_command_control_lock as probe

    kernel32 = SimpleNamespace(CreateFileW=Mock(return_value=invalid))
    with pytest.raises(RuntimeError, match="child_open_failed"):
        probe._raw_child_file(kernel32, tmp_path / "extension-control-authority.lock")


@pytest.mark.skipif(os.name != "nt", reason="real Windows LockFileEx process boundary")
def test_real_windows_authority_leases_against_independent_whole_file_child(tmp_path: Path, monkeypatch) -> None:
    from ci.native_runtime import probe_installed_command_control_lock as probe

    # Source regression invocation retains the independent child ABI but cannot
    # assert installed provenance; the installed -I probe does that in wheel CI.
    monkeypatch.setattr(probe, "_child_result", _source_child_result)
    assert len(probe.exercise_windows_leases(tmp_path)) == 4


def _source_child_result(path: Path, *, shared: bool) -> bool:
    import json
    import subprocess
    import sys

    code = (
        "from pathlib import Path; "
        "from ci.native_runtime.probe_installed_command_control_lock import _raw_child; "
        "import sys; raise SystemExit(_raw_child(Path(sys.argv[1]), sys.argv[2] == 'shared'))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(path), "shared" if shared else "exclusive"],
        check=True,
        capture_output=True,
        timeout=5,
        cwd=Path(__file__).parents[1],
    )
    assert not result.stderr
    return json.loads(result.stdout)["acquired"]
