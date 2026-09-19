"""Test-only identity-bound membership check against the owner's retained Job."""

from __future__ import annotations

import ctypes
import json
from pathlib import Path


def install(owner, witness_path: str):
    """Hold the real child alive until its exact outer-Job membership is queried."""
    path = Path(witness_path)
    release = path.with_suffix(".release")
    observation = {}
    retained = []
    original = owner._accounting
    kernel = owner._job_api()._kernel32()
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    kernel.IsProcessInJob.restype = ctypes.c_int
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p, *([ctypes.POINTER(owner._FileTime)] * 4)]
    kernel.GetProcessTimes.restype = ctypes.c_int
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int

    def accounting(api, job):
        result = original(api, job)
        if observation or not path.exists():
            return result
        try:
            identity = json.loads(path.read_text(encoding="utf-8"))
            handle = kernel.OpenProcess(0x100000 | 0x1000, False, identity["pid"])
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            retained.append(handle)
            values = [owner._FileTime() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
                raise ctypes.WinError(ctypes.get_last_error())
            birth = str((values[0].high << 32) | values[0].low)
            observation.update(pid=identity["pid"], birth=birth, birth_matches=birth == identity["birth"])
            observation["alive_during_query"] = kernel.WaitForSingleObject(handle, 0) == 258
            member = ctypes.c_int()
            if not kernel.IsProcessInJob(handle, job.handle, ctypes.byref(member)):
                raise ctypes.WinError(ctypes.get_last_error())
            observation.update(in_retained_job=bool(member.value), active_at_query=result["active"])
        except Exception as error:
            observation["query_failure"] = type(error).__name__
            raise
        finally:
            # Release only after the query; even a failing witness gets bounded cleanup.
            release.write_text("observed", encoding="utf-8")
        return result

    def finish():
        for handle in retained:
            try:
                observation["child_exit_observed"] = kernel.WaitForSingleObject(handle, 0) == 0
            finally:
                if not kernel.CloseHandle(handle):
                    raise ctypes.WinError(ctypes.get_last_error())
        return observation

    owner._accounting = accounting
    return finish


CHILD = """
import ctypes, json, os, sys, time
from pathlib import Path
class FileTime(ctypes.Structure):
    _fields_ = [('low', ctypes.c_uint32), ('high', ctypes.c_uint32)]
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.GetCurrentProcess.argtypes = []
kernel.GetCurrentProcess.restype = ctypes.c_void_p
kernel.GetProcessTimes.argtypes = [ctypes.c_void_p, *([ctypes.POINTER(FileTime)] * 4)]
kernel.GetProcessTimes.restype = ctypes.c_int
values = [FileTime() for _ in range(4)]
if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), *(ctypes.byref(value) for value in values)):
    raise ctypes.WinError(ctypes.get_last_error())
path = Path(sys.argv[1])
temporary = path.with_suffix('.pending')
temporary.write_text(json.dumps({'pid': os.getpid(),
    'birth': str((values[0].high << 32) | values[0].low)}), encoding='utf-8')
temporary.replace(path)
deadline = time.monotonic() + 5
while not path.with_suffix('.release').exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('membership witness was not observed before deadline')
    time.sleep(0.01)
print('retained child finished', flush=True)
"""
