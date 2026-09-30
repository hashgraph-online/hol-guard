from __future__ import annotations

import signal
from types import SimpleNamespace

import pytest

from ci.native_runtime import native_hook_client_support as support


def test_termination_never_uses_signal_zero_for_liveness(monkeypatch: pytest.MonkeyPatch) -> None:
    signals: list[tuple[int, int]] = []
    checks: list[int] = []
    monkeypatch.setattr(support, "os", SimpleNamespace(name="nt", kill=lambda pid, sig: signals.append((pid, sig))))
    monkeypatch.setattr(support, "process_is_alive", lambda pid: checks.append(pid) or False)
    support._terminate_process(12345)
    assert signals == [(12345, signal.SIGTERM)]
    assert checks == [12345]
