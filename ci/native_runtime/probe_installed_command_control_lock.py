"""Prove installed Windows authority leases against an independent Win32 child."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard import native_command_control_authority_io as authority_io


def _raw_child_file(kernel32: Any, path: Path) -> int:
    create = kernel32.CreateFileW
    create.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    # A newly created private parent handle retains DELETE access for atomic
    # rollback. CRT os.open does not share DELETE, so it can fail before the
    # child reaches LockFileEx. Match Rust's read/write/delete open sharing;
    # lock contention is still decided independently by the byte-range lease.
    handle = create(str(path), 0xC0000000, 0x00000007, None, 3, 0x00200080, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise RuntimeError("installed_command_control_lock_child_open_failed")
    return int(handle)


def _raw_child(path: Path, shared: bool) -> int:
    # This independent binding intentionally does not call the implementation
    # under test. Its whole-file range matches Rust fs2, overlapping byte zero.
    class Overlapped(ctypes.Structure):
        _fields_ = [
            ("internal", ctypes.c_size_t),
            ("internal_high", ctypes.c_size_t),
            ("offset", ctypes.c_uint32),
            ("offset_high", ctypes.c_uint32),
            ("event", ctypes.c_void_p),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    lock = kernel32.LockFileEx
    lock.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(Overlapped),
    ]
    lock.restype = ctypes.c_int
    close = kernel32.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    handle = _raw_child_file(kernel32, path)
    try:
        record = Overlapped()
        acquired = bool(lock(handle, 1 if shared else 3, 0, 0xFFFFFFFF, 0xFFFFFFFF, ctypes.byref(record)))
        code = 0 if acquired else ctypes.get_last_error()
        if not acquired and code != 33:  # ERROR_LOCK_VIOLATION only
            raise RuntimeError("installed_command_control_lock_unexpected_win32_error")
        print(json.dumps({"acquired": acquired, "win32_error": code}))
        return 0
    finally:
        # Closing releases the child's lease, including the success case.
        if not close(handle):
            raise RuntimeError("installed_command_control_lock_child_close_failed")


def _child_result(path: Path, *, shared: bool) -> bool:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--child",
            str(path),
            "--shared" if shared else "--exclusive",
        ],
        capture_output=True,
        timeout=5,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 1024:
        raise RuntimeError("installed_command_control_lock_child_failed")
    try:
        result = json.loads(completed.stdout)
    except (ValueError, UnicodeError) as error:
        raise RuntimeError("installed_command_control_lock_child_invalid") from error
    if result not in ({"acquired": True, "win32_error": 0}, {"acquired": False, "win32_error": 33}):
        raise RuntimeError("installed_command_control_lock_child_invalid")
    return result["acquired"]


def exercise_windows_leases(home: Path) -> list[dict[str, object]]:
    path = home / "extension-control-authority.lock"
    receipts: list[dict[str, object]] = []
    for parent_shared, child_shared, expected in (
        (True, True, True),
        (True, False, False),
        (False, True, False),
        (False, False, False),
    ):
        with authority_io.hold_command_control_authority_lock(home, shared=parent_shared, timeout_seconds=0):
            acquired = _child_result(path, shared=child_shared)
            if acquired != expected:
                raise RuntimeError("installed_command_control_lock_exclusion_failed")
        # A released parent must never leave its lease live in the child.
        if not _child_result(path, shared=False):
            raise RuntimeError("installed_command_control_lock_release_failed")
        receipts.append(
            {"parent_shared": parent_shared, "child_shared": child_shared, "child_acquired": acquired, "released": True}
        )
    return receipts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--json", type=Path)
    flags = parser.add_mutually_exclusive_group()
    flags.add_argument("--shared", action="store_true")
    flags.add_argument("--exclusive", action="store_true")
    options = parser.parse_args()
    if os.name != "nt":
        raise RuntimeError("installed_command_control_lock_requires_windows")
    origin = Path(authority_io.__file__).resolve()
    if not origin.is_relative_to(Path(sys.prefix).resolve()) or not sys.flags.isolated:
        raise RuntimeError("installed_command_control_lock_requires_isolated_install")
    if options.child is not None:
        return _raw_child(options.child, options.shared)
    with tempfile.TemporaryDirectory(prefix="hg-lock-") as temporary:
        receipts = exercise_windows_leases(Path(temporary))
    rendered = json.dumps(
        {
            "schema": "hol-guard.installed-command-control-lock.v1",
            "scope": "installed_python_authority_lease_vs_independent_win32_child",
            "cases": receipts,
            "rust_publisher_interop": "separate_default_auto_probe",
        },
        sort_keys=True,
    )
    if options.json is not None:
        options.json.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
