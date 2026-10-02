"""Fail-closed Linux filesystem/exec restrictions layered inside namespaces.

This module is not an authorization mechanism. The execution owner must supply
an independently validated plan and create the mount/network namespace first.
Landlock grants reads and execution separately, so mounting a runtime library
tree never grants permission to execute arbitrary programs from that tree.
"""

from __future__ import annotations

import ctypes
import os
import platform
import stat
from collections.abc import Sequence
from pathlib import Path

_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_REFER = 1 << 13
_TRUNCATE = 1 << 14
_HANDLED = (1 << 15) - 1
_WRITE_DIRECTORY = _HANDLED & ~(_EXECUTE | _READ_FILE | _READ_DIR)
_MAX_RULES = 250_000


class LinuxContainmentUnavailableError(RuntimeError):
    """No repository code may run when the required kernel boundary fails."""


class _Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def enforce_landlock(
    *,
    read_roots: Sequence[Path],
    read_files: Sequence[Path],
    list_roots: Sequence[Path],
    write_roots: Sequence[Path],
    executables: Sequence[Path],
) -> None:
    """Irreversibly restrict this single-threaded launcher and future children.

    Workspace reads must be individual, nonsensitive files, not a blanket
    read_roots grant. READ_DIR only permits listing, not reading child contents.
    No exec grant is inherited from a read/write directory. ABI 3 is mandatory
    because older kernels do not enforce truncation of already-existing files.
    """
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64"}:
        raise LinuxContainmentUnavailableError("Unsupported Linux syscall architecture; execution was not started.")
    if sum(map(len, (read_roots, read_files, list_roots, write_roots, executables))) > _MAX_RULES:
        raise LinuxContainmentUnavailableError("Linux access plan exceeds its rule budget.")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # Linux generic syscall numbers on the two explicitly supported architectures.
    create, add, restrict = 444, 445, 446
    abi = libc.syscall(create, None, 0, 1)
    if abi < 3:
        raise LinuxContainmentUnavailableError("Landlock ABI 3 or later is required; execution was not started.")
    ruleset = _Ruleset(_HANDLED)
    descriptor = libc.syscall(create, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    if descriptor < 0:
        raise LinuxContainmentUnavailableError("Could not create the Linux access boundary.")

    def grant(path: Path, access: int, *, directory: bool | None = None) -> None:
        if not path.is_absolute():
            raise LinuxContainmentUnavailableError("Linux access plans require absolute paths.")
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            is_directory = stat.S_ISDIR(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode) or (directory is not None and directory != is_directory):
                raise LinuxContainmentUnavailableError("Linux access target changed or has an unexpected type.")
            if not is_directory:
                access &= _EXECUTE | _READ_FILE | _WRITE_FILE | _TRUNCATE
            rule = _PathRule(access, fd)
            if libc.syscall(add, descriptor, 1, ctypes.byref(rule), 0) != 0:
                raise LinuxContainmentUnavailableError("Could not install the Linux access boundary.")
        finally:
            os.close(fd)

    try:
        for path in read_roots:
            grant(path, _READ_FILE | _READ_DIR, directory=True)
        for path in read_files:
            grant(path, _READ_FILE, directory=False)
        for path in list_roots:
            grant(path, _READ_DIR, directory=True)
        for path in write_roots:
            grant(path, _WRITE_DIRECTORY | _READ_FILE | _READ_DIR, directory=True)
        for path in executables:
            grant(path, _EXECUTE | _READ_FILE, directory=False)
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise LinuxContainmentUnavailableError("Could not prohibit privilege escalation.")
        if libc.syscall(restrict, descriptor, 0) != 0:
            raise LinuxContainmentUnavailableError("Could not enforce the Linux access boundary.")
    except OSError as error:
        raise LinuxContainmentUnavailableError("Could not resolve the Linux access boundary.") from error
    finally:
        os.close(descriptor)
