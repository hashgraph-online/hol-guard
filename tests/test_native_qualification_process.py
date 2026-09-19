"""Probe completion preserves an unreaped child on Linux and macOS."""

from __future__ import annotations

import ctypes
import errno
import os
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from scripts import native_qualification_process as process_probe

pytestmark = pytest.mark.skipif(sys.platform not in {"linux", "darwin"}, reason="POSIX interpreter qualification")


@pytest.mark.skipif(sys.platform not in {"linux", "darwin"}, reason="POSIX interpreter qualification")
@pytest.mark.parametrize("return_code", [0, 7])
def test_real_owned_child_exit_remains_unreaped_until_wait(return_code: int) -> None:
    process = subprocess.Popen([sys.executable, "-I", "-c", f"raise SystemExit({return_code})"], start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        status = None
        while status is None and time.monotonic() < deadline:
            status = process_probe.observe_probe_exit(process.pid)
            if status is None:
                time.sleep(0.01)
        assert status == process_probe.ProbeExit(process.pid, os.CLD_EXITED, return_code)
        assert process.returncode is None
        assert process_probe.observe_probe_exit(process.pid) == status
        assert process.wait(timeout=1) == return_code
    finally:
        if process.returncode is None:
            process.kill()
            process.wait(timeout=1)


def _darwin_without_python_waitid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_probe, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(
        process_probe,
        "os",
        SimpleNamespace(P_PID=1, WEXITED=4, WNOHANG=1, WNOWAIT=32, strerror=os.strerror),
    )


@pytest.mark.parametrize("reported_pid", [0, 41])
def test_missing_python_waitid_uses_bounded_darwin_nonreaping_call(
    monkeypatch: pytest.MonkeyPatch, reported_pid: int
) -> None:
    _darwin_without_python_waitid(monkeypatch)
    calls = []

    def waitid(kind, pid, output, flags):
        calls.append((kind, pid, flags))
        status = ctypes.cast(output, ctypes.POINTER(process_probe._DarwinSiginfo)).contents
        status.si_pid = reported_pid
        status.si_signo = signal.SIGCHLD
        status.si_code = os.CLD_EXITED
        status.si_status = 7
        return 0

    monkeypatch.setattr(process_probe, "_darwin_waitid_function", lambda: waitid)
    expected = None if reported_pid == 0 else process_probe.ProbeExit(41, os.CLD_EXITED, 7)
    assert process_probe.observe_probe_exit(41) == expected
    assert calls == [(1, 41, 37)]


@pytest.mark.parametrize("failure", ["system_error", "wrong_pid", "wrong_signal"])
def test_darwin_observation_rejects_errors_and_unrelated_children(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    _darwin_without_python_waitid(monkeypatch)

    def waitid(kind, pid, output, flags):
        if failure == "system_error":
            ctypes.set_errno(errno.EPERM)
            return -1
        status = ctypes.cast(output, ctypes.POINTER(process_probe._DarwinSiginfo)).contents
        status.si_pid = 42 if failure == "wrong_pid" else pid
        status.si_signo = signal.SIGTERM if failure == "wrong_signal" else signal.SIGCHLD
        return 0

    monkeypatch.setattr(process_probe, "_darwin_waitid_function", lambda: waitid)
    with pytest.raises(PermissionError if failure == "system_error" else RuntimeError):
        process_probe.observe_probe_exit(41)


def test_darwin_64_bit_public_siginfo_layout() -> None:
    assert ctypes.sizeof(process_probe._DarwinSiginfo) == 104
    assert process_probe._DarwinSiginfo.si_pid.offset == 12
    assert process_probe._DarwinSiginfo.si_status.offset == 20
    assert process_probe._DarwinSiginfo.reserved.offset == 48


@pytest.mark.skipif(sys.platform not in {"linux", "darwin"}, reason="POSIX interpreter qualification")
def test_real_interpreter_probe_captures_success_without_requiring_python_waitid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pathlib import Path

    from scripts import native_qualification_interpreter as provision

    monkeypatch.setattr(provision, "_PROBE", "print('qualification-ready')")
    assert provision._probe_output(Path(sys.executable), dict(os.environ), managed=False) == b"qualification-ready\n"
