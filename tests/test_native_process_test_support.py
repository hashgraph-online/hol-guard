from __future__ import annotations

import json
import signal
import subprocess
from pathlib import Path
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


def test_policy_push_timeout_reports_bounded_startup_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeouts: list[object] = []

    def timed_out(*_args: object, **kwargs: object) -> object:
        timeouts.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(("runtime", "resident-client"), timeout=8)

    monkeypatch.setattr(support.subprocess, "run", timed_out)
    monkeypatch.setattr(support, "_policy_snapshot_push_bytes_v3", lambda _snapshot: b"push")
    monkeypatch.setattr(
        support,
        "_startup_diagnostic",
        lambda _runtime, _state_dir: "native_test_direct_start_timeout",
    )

    with pytest.raises(AssertionError) as raised:
        support._push_snapshot(
            Path("/private/runtime-secret"),
            Path("/private/state-secret"),
            json.dumps({"policy_snapshot": {"payload": "raw-secret"}}).encode(),
        )

    assert timeouts == [8]
    assert str(raised.value) == (
        "native policy push failed: native_policy_snapshot_push_timed_out; "
        "direct startup: native_test_direct_start_timeout"
    )


def test_policy_push_timeout_hides_subprocess_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timed_out(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired(
            ("runtime", "resident-client", "/private/state-secret"),
            timeout=8,
            output=b"raw stdout secret",
            stderr=b"raw stderr secret",
        )

    monkeypatch.setattr(support.subprocess, "run", timed_out)
    monkeypatch.setattr(support, "_policy_snapshot_push_bytes_v3", lambda _snapshot: b"push")
    monkeypatch.setattr(
        support,
        "_startup_diagnostic",
        lambda _runtime, _state_dir: "native_test_direct_start_failed",
    )

    with pytest.raises(AssertionError) as raised:
        support._push_snapshot(
            Path("/private/runtime-secret"),
            Path("/private/state-secret"),
            b'{"policy_snapshot":{"payload":"raw payload secret"}}',
        )

    message = str(raised.value)
    assert message == (
        "native policy push failed: native_policy_snapshot_push_timed_out; "
        "direct startup: native_test_direct_start_failed"
    )
    assert "raw" not in message
    assert "secret" not in message
    assert "/private" not in message
    assert "TimeoutExpired" not in message
