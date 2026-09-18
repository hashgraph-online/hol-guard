"""Observe owned probe exits without releasing their process-group identity."""

from __future__ import annotations

import ctypes
import os
import signal
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Any


@dataclass(frozen=True)
class ProbeExit:
    si_pid: int
    si_code: int
    si_status: int


class _DarwinSiginfo(ctypes.Structure):
    # Darwin's public LP64 siginfo_t from <sys/signal.h>. Python 3.12 omits
    # os.waitid on macOS, although the operating system implements WNOWAIT.
    # https://github.com/python/cpython/issues/113536
    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_uint),
        ("si_status", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
        ("si_value", ctypes.c_void_p),
        ("si_band", ctypes.c_long),
        ("reserved", ctypes.c_ulong * 7),
    ]


@lru_cache(maxsize=1)
def _darwin_waitid_function() -> Any:
    if sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(_DarwinSiginfo) != 104:
        raise RuntimeError("qualification_interpreter_waitid_platform_unsupported")
    function = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).waitid
    function.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.POINTER(_DarwinSiginfo), ctypes.c_int]
    function.restype = ctypes.c_int
    return function


def _darwin_waitid(pid: int) -> ProbeExit | None:
    status = _DarwinSiginfo()
    function = _darwin_waitid_function()
    if function(os.P_PID, pid, ctypes.byref(status), os.WEXITED | os.WNOHANG | os.WNOWAIT) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if status.si_pid == 0:
        return None
    if status.si_pid != pid or status.si_signo != signal.SIGCHLD:
        raise RuntimeError("qualification_interpreter_waitid_identity_mismatch")
    return ProbeExit(status.si_pid, status.si_code, status.si_status)


def observe_probe_exit(pid: int) -> ProbeExit | None:
    """Inspect one still-owned Popen child; never poll, reap, or signal it."""
    if type(pid) is not int or not 0 < pid < 2**31:
        raise RuntimeError("qualification_interpreter_waitid_pid_invalid")
    if sys.platform == "darwin" and not hasattr(os, "waitid"):
        return _darwin_waitid(pid)
    status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if status is None:
        return None
    if status.si_pid != pid:
        raise RuntimeError("qualification_interpreter_waitid_identity_mismatch")
    return ProbeExit(status.si_pid, status.si_code, status.si_status)
