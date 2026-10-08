from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ci.native_runtime import native_process_test_support as support

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="Linux proc state regression")


def test_current_process_is_alive() -> None:
    assert support.process_is_alive(os.getpid())
    assert support.process_is_executing(os.getpid())


@linux_only
def test_live_and_unreaped_dead_children_have_distinct_liveness() -> None:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert support.process_is_executing(child.pid)
        child.kill()
        # Wait for termination without reaping. This makes the zombie case
        # deterministic and retains parent ownership until the finally block.
        result = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
        assert result is not None and result.si_pid == child.pid
        # Preserve the stronger presence/reaping check at other call sites.
        assert support.process_is_alive(child.pid)
        assert not support.process_is_executing(child.pid)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
    assert not support.process_is_executing(child.pid)
    assert not support.process_is_alive(child.pid)


@pytest.mark.parametrize("state", [b"R", b"S", b"D", b"T", b"t", b"I", b"?"])
@linux_only
def test_non_zombie_states_cannot_pass_containment(monkeypatch: pytest.MonkeyPatch, state: bytes) -> None:
    monkeypatch.setattr(support.sys, "platform", "linux")
    monkeypatch.setattr(support.os, "kill", lambda *_args: None)
    monkeypatch.setattr(Path, "read_bytes", lambda _path: b"123 (complex ) name) " + state + b" 1 2 3")
    assert support.process_is_executing(123)


@linux_only
def test_zombie_with_parentheses_in_name_is_not_executing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(support.sys, "platform", "linux")
    monkeypatch.setattr(support.os, "kill", lambda *_args: None)
    monkeypatch.setattr(Path, "read_bytes", lambda _path: b"123 (complex ) name) Z 1 2 3")
    assert not support.process_is_executing(123)


@pytest.mark.parametrize("error", [PermissionError, OSError])
@linux_only
def test_unreadable_proc_state_does_not_claim_termination(
    monkeypatch: pytest.MonkeyPatch, error: type[OSError]
) -> None:
    monkeypatch.setattr(support.sys, "platform", "linux")
    monkeypatch.setattr(support.os, "kill", lambda *_args: None)

    def unreadable(_path: Path) -> bytes:
        raise error("proc state unavailable")

    monkeypatch.setattr(Path, "read_bytes", unreadable)
    with pytest.raises(error, match="proc state unavailable"):
        support.process_is_executing(123)


@linux_only
@pytest.mark.parametrize(
    "stat",
    [b"", b") Z", b"999 (other pid) Z 1", b"123 (name) Z", b"123 (name) Z invalid"],
)
def test_malformed_proc_state_does_not_claim_termination(monkeypatch: pytest.MonkeyPatch, stat: bytes) -> None:
    monkeypatch.setattr(support.sys, "platform", "linux")
    monkeypatch.setattr(support.os, "kill", lambda *_args: None)
    monkeypatch.setattr(Path, "read_bytes", lambda _path: stat)
    with pytest.raises(RuntimeError, match="native_test_process_state_unavailable"):
        support.process_is_executing(123)
