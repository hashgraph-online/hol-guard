"""Child environment, capability guard, and operating-system limits."""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path


def _child_environment() -> dict[str, str]:
    environment = {
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
    }
    for key in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _darwin_virtual_size_bytes() -> int | None:
    """Return this task's current Darwin VM footprint without spawning a helper.

    Darwin maps the shared cache into every process, so an absolute RLIMIT_AS of
    a few hundred MiB is below the interpreter's starting VM size.  Querying the
    kernel lets the child apply an *incremental* hard VM budget instead of
    silently running without a memory boundary.
    """

    if sys.platform != "darwin":
        return None
    try:
        import ctypes

        class _TimeValue(ctypes.Structure):
            _fields_ = [("seconds", ctypes.c_int), ("microseconds", ctypes.c_int)]

        class _MachTaskBasicInfo(ctypes.Structure):
            _fields_ = [
                ("virtual_size", ctypes.c_uint64),
                ("resident_size", ctypes.c_uint64),
                ("resident_size_max", ctypes.c_uint64),
                ("user_time", _TimeValue),
                ("system_time", _TimeValue),
                ("policy", ctypes.c_int),
                ("suspend_count", ctypes.c_int),
            ]

        process = ctypes.CDLL(None)
        task_port = ctypes.c_uint.in_dll(process, "mach_task_self_").value
        task_info = process.task_info
        task_info.argtypes = [
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint),
        ]
        task_info.restype = ctypes.c_int
        information = _MachTaskBasicInfo()
        information_count = ctypes.c_uint(ctypes.sizeof(information) // ctypes.sizeof(ctypes.c_uint))
        # MACH_TASK_BASIC_INFO is stable Darwin ABI value 20.
        if task_info(task_port, 20, ctypes.byref(information), ctypes.byref(information_count)) != 0:
            return None
        if information_count.value * ctypes.sizeof(ctypes.c_uint) < ctypes.sizeof(information):
            return None
        virtual_size = int(information.virtual_size)
        return virtual_size if virtual_size > 0 else None
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _child_limits(timeout_seconds: float, max_memory_bytes: int) -> bool:
    if os.name != "posix":
        return False
    try:
        import resource
    except ImportError:
        return False
    required_limits_applied = True
    try:
        cpu_seconds = max(1, math.ceil(timeout_seconds))
        _soft_cpu, hard_cpu = resource.getrlimit(resource.RLIMIT_CPU)
        cpu_limit = cpu_seconds if hard_cpu == resource.RLIM_INFINITY else min(cpu_seconds, hard_cpu)
        if cpu_limit <= 0:
            required_limits_applied = False
        else:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, hard_cpu))
    except (OSError, ValueError):
        required_limits_applied = False
    try:
        _soft_files, hard_files = resource.getrlimit(resource.RLIMIT_NOFILE)
        descriptor_limit = 32 if hard_files == resource.RLIM_INFINITY else min(32, hard_files)
        if descriptor_limit < 8:
            required_limits_applied = False
        else:
            resource.setrlimit(resource.RLIMIT_NOFILE, (descriptor_limit, hard_files))
    except (OSError, ValueError):
        required_limits_applied = False
    memory_limit_applied = False
    try:
        address_space_limit = getattr(resource, "RLIMIT_AS", None)
        if address_space_limit is not None:
            _soft_memory, hard_memory = resource.getrlimit(address_space_limit)
            if sys.platform == "darwin":
                current_virtual_size = _darwin_virtual_size_bytes() or 0
                memory_limit = current_virtual_size + max_memory_bytes if current_virtual_size else 0
            else:
                current_virtual_size = 0
                memory_limit = max_memory_bytes
            if hard_memory != resource.RLIM_INFINITY:
                memory_limit = min(memory_limit, hard_memory)
            if memory_limit > current_virtual_size:
                resource.setrlimit(address_space_limit, (memory_limit, memory_limit))
                applied_soft_limit, applied_hard_limit = resource.getrlimit(address_space_limit)
                memory_limit_applied = (
                    current_virtual_size < applied_soft_limit <= memory_limit
                    and applied_hard_limit == applied_soft_limit
                )
    except (OSError, ValueError):
        memory_limit_applied = False
    return required_limits_applied and memory_limit_applied


def _install_child_capability_guard() -> None:
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def deny_capability(event: str, arguments: tuple[object, ...]) -> None:
        if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn")) or event in {
            "os.fork",
            "os.forkpty",
            "os.posix_spawn",
            "os.system",
            "pty.spawn",
        }:
            raise PermissionError("offline archive inspector capability denied")
        if event != "open" or not arguments:
            return
        mode = arguments[1] if len(arguments) > 1 else None
        flags = arguments[2] if len(arguments) > 2 else 0
        if (isinstance(mode, str) and any(character in mode for character in "wax+")) or (
            isinstance(flags, int) and flags & write_flags
        ):
            raise PermissionError("offline archive inspector write denied")

    sys.addaudithook(deny_capability)


def _platform_sandbox_command(command: list[str]) -> list[str] | None:
    if sys.platform != "darwin":
        return command
    sandbox_executable = Path("/usr/bin/sandbox-exec")
    if not sandbox_executable.is_file():
        return None
    return [
        str(sandbox_executable),
        "-p",
        "(version 1) (allow default) (deny network*)",
        *command,
    ]
