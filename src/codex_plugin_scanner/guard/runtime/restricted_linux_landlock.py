"""Fail-closed Linux filesystem/exec restrictions layered inside namespaces.

This module is not an authorization mechanism. The execution owner must supply
an independently validated plan and create the mount/network namespace first.
Landlock grants reads and execution separately, so mounting a runtime library
tree never grants permission to execute arbitrary programs from that tree.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_REFER = 1 << 13
_TRUNCATE = 1 << 14
_HANDLED = (1 << 15) - 1
_MAKE_CHAR = 1 << 6
_MAKE_BLOCK = 1 << 11
_WRITE_DIRECTORY = _HANDLED & ~(_EXECUTE | _READ_FILE | _READ_DIR | _MAKE_CHAR | _MAKE_BLOCK)
_MAX_RULES = 250_000
_SAFE_DEVICES = {"/dev/null": (1, 3), "/dev/random": (1, 8), "/dev/urandom": (1, 9)}


class LinuxContainmentUnavailableError(RuntimeError):
    """No repository code may run when the required kernel boundary fails."""


class _Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _FilterProgram(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(_Filter))]


def _socket_filter(machine: str) -> list[tuple[int, int, int, int]]:
    """Supplement Landlock: pathname sockets are not filesystem read grants.

    Private AF_UNIX stream pairs support local worker IPC without a connectable
    host endpoint. Datagram pairs are excluded because sendto can redirect them.
    See https://docs.kernel.org/userspace-api/seccomp_filter.html.
    """
    architectures = {
        "x86_64": (0xC000003E, 53, (41, 42, 101, 311, 425, 426, 427)),
        "aarch64": (0xC00000B7, 199, (198, 203, 117, 271, 425, 426, 427)),
    }
    if machine not in architectures:
        raise LinuxContainmentUnavailableError("Unsupported Linux socket-filter architecture.")
    arch, pair, denied = architectures[machine]
    allow, kill, deny = 0x7FFF0000, 0x80000000, 0x00050000 | errno.EPERM
    instructions = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, arch),
        (0x06, 0, 0, kill),
        (0x20, 0, 0, 0),
        (0x35, 0, 1, 0x40000000),
        (0x06, 0, 0, kill),
    ]
    for number in denied:
        instructions.extend(((0x15, 0, 1, number), (0x06, 0, 0, deny)))
    instructions.extend(((0x15, 1, 0, pair), (0x06, 0, 0, allow)))
    instructions.extend(((0x20, 0, 0, 16), (0x15, 1, 0, 1), (0x06, 0, 0, deny)))
    # SOCK_CLOEXEC and SOCK_NONBLOCK are harmless flags, not socket types.
    instructions.extend(
        ((0x20, 0, 0, 24), (0x54, 0, 0, 0xFFFFFFFF ^ (0x80000 | 0x800)), (0x15, 1, 0, 1), (0x06, 0, 0, deny))
    )
    instructions.extend(((0x20, 0, 0, 32), (0x15, 1, 0, 0), (0x06, 0, 0, deny), (0x06, 0, 0, allow)))
    return instructions


def enforce_socket_boundary() -> None:
    """Install an inherited filter after namespaces and before repository code."""
    if platform.system() != "Linux":
        raise LinuxContainmentUnavailableError("Linux socket isolation is unavailable.")
    instructions = _socket_filter(platform.machine())
    filters = (_Filter * len(instructions))(*(_Filter(*item) for item in instructions))
    program = _FilterProgram(len(filters), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise LinuxContainmentUnavailableError("Could not enforce Linux socket isolation.")


def enforce_landlock(
    *,
    read_roots: Sequence[Path],
    read_files: Sequence[Path],
    list_roots: Sequence[Path],
    write_roots: Sequence[Path],
    executables: Sequence[Path],
    read_identities: Mapping[Path, tuple[int, int]] | None = None,
    device_files: Sequence[Path] = (),
) -> None:
    """Irreversibly restrict this single-threaded launcher and future children.

    Workspace reads must be individual, nonsensitive files, not a blanket
    read_roots grant. READ_DIR only permits listing, not reading child contents.
    No exec grant is inherited from a read/write directory. ABI 3 is mandatory
    because older kernels do not enforce truncation of already-existing files.
    """
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64"}:
        raise LinuxContainmentUnavailableError("Unsupported Linux syscall architecture; execution was not started.")
    if sum(map(len, (read_roots, read_files, list_roots, write_roots, executables, device_files))) > _MAX_RULES:
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

    def grant(
        path: Path,
        access: int,
        *,
        directory: bool | None = None,
        identity_required: bool = False,
        device_required: bool = False,
    ) -> None:
        if not path.is_absolute():
            raise LinuxContainmentUnavailableError("Linux access plans require absolute paths.")
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if device_required and (
                str(path) not in _SAFE_DEVICES
                or not stat.S_ISCHR(metadata.st_mode)
                or (os.major(metadata.st_rdev), os.minor(metadata.st_rdev)) != _SAFE_DEVICES[str(path)]
            ):
                raise LinuxContainmentUnavailableError("Unexpected namespace device.")
            if identity_required and (
                read_identities is None
                or read_identities.get(path) != (metadata.st_dev, metadata.st_ino)
                or metadata.st_nlink != 1
            ):
                raise LinuxContainmentUnavailableError("Linux read target changed after discovery.")
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
            grant(path, _READ_FILE, directory=False, identity_required=read_identities is not None)
        for path in list_roots:
            grant(path, _READ_DIR, directory=True)
        for path in write_roots:
            grant(path, _WRITE_DIRECTORY | _READ_FILE | _READ_DIR, directory=True)
        for path in executables:
            grant(path, _EXECUTE | _READ_FILE, directory=False)
        for path in device_files:
            grant(
                path,
                _READ_FILE | (_WRITE_FILE if str(path) == "/dev/null" else 0),
                directory=False,
                device_required=True,
            )
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise LinuxContainmentUnavailableError("Could not prohibit privilege escalation.")
        if libc.syscall(restrict, descriptor, 0) != 0:
            raise LinuxContainmentUnavailableError("Could not enforce the Linux access boundary.")
    except OSError as error:
        raise LinuxContainmentUnavailableError("Could not resolve the Linux access boundary.") from error
    finally:
        os.close(descriptor)
