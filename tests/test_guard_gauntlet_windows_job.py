"""Windows Job Object containment for the live Gauntlet host process."""

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Job Object containment is Windows-only")

_CHILD = "import os, time; from pathlib import Path; Path('child.pid').write_text(str(os.getpid())); time.sleep(60)"


def _parent(after_spawn: str) -> str:
    return (
        "import subprocess, sys, time; from pathlib import Path; "
        f"subprocess.Popen([sys.executable, '-c', {_CHILD!r}]); "
        f"\nwhile not Path('child.pid').exists(): time.sleep(0.01)\n{after_spawn}"
    )


def _exits_soon(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        return True
    try:
        return kernel32.WaitForSingleObject(handle, 5000) == 0
    finally:
        kernel32.CloseHandle(handle)


def _run(tmp_path, code: str, timeout: float):
    from ci.gauntlet.host_process import run_process

    return run_process(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=dict(os.environ),
        output=tmp_path / "stdout.log",
        error_output=tmp_path / "stderr.log",
        timeout=timeout,
    )


def test_timeout_kills_the_host_and_its_descendants(tmp_path):
    code, timed_out = _run(tmp_path, _parent("time.sleep(60)"), timeout=3)
    assert timed_out is True
    assert code != 0
    assert _exits_soon(int((tmp_path / "child.pid").read_text()))


def test_descendant_does_not_outlive_a_host_that_exited(tmp_path):
    code, timed_out = _run(tmp_path, _parent(""), timeout=10)
    assert (code, timed_out) == (0, False)
    assert _exits_soon(int((tmp_path / "child.pid").read_text()))


def test_failed_job_assignment_kills_the_suspended_host(tmp_path, monkeypatch):
    from ci.gauntlet import host_process, windows_job

    original_popen = subprocess.Popen
    children = []

    def capture(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        children.append(process)
        return process

    def refuse(self, process):
        raise OSError("assignment refused")

    monkeypatch.setattr(host_process.subprocess, "Popen", capture)
    monkeypatch.setattr(windows_job.KillOnCloseJob, "assign_and_resume", refuse)
    with pytest.raises(OSError, match="assignment refused"):
        _run(tmp_path, "import time; time.sleep(60)", timeout=10)
    assert len(children) == 1
    assert children[0].poll() is not None
    assert not (tmp_path / "child.pid").exists()


def test_missing_symlink_privilege_names_the_host_requirement(tmp_path, monkeypatch):
    from pathlib import Path

    from ci.gauntlet.fixtures import create_fixture

    def refuse(self, target):
        raise OSError(1314, "A required privilege is not held by the client")

    monkeypatch.setattr(Path, "symlink_to", refuse)
    with pytest.raises(RuntimeError, match="Developer Mode"):
        create_fixture(tmp_path / "fixture")
