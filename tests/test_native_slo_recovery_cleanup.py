from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts import native_slo_recovery_cleanup as recovery
from scripts import native_slo_session as sessions
from scripts.native_slo_stop_diagnostics import NativeStopResult


def test_recovery_uses_one_native_owned_home_and_one_total_deadline(tmp_path, monkeypatch):
    ticks = iter((100.0, 101.0))
    monkeypatch.setattr(recovery.time, "monotonic", lambda: next(ticks))
    calls = []
    monkeypatch.setattr(recovery, "close_native_residents", lambda home, **kwargs: calls.append((home, kwargs)) or True)
    assert recovery.recover_failed_stop(tmp_path) == {"attempted": True, "contained": True, "seconds": 1.0}
    assert calls == [(tmp_path, {"deadline_monotonic": 110.0})]


def test_recovery_keeps_unknown_outcomes_and_withholds_private_error_text(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("private-fixture-diagnostic")

    monkeypatch.setattr(recovery, "close_native_residents", fail)
    result = recovery.recover_failed_stop(tmp_path)
    assert result["contained"] is False and result["error_type"] == "RuntimeError"
    assert "private-fixture" not in str(result)


@pytest.mark.parametrize("recovered", [False, True])
def test_failed_strict_stop_remains_failed_after_recovery_and_preserves_uncontained_state(
    tmp_path, monkeypatch, recovered
):
    events = []
    failure = {"status": "failed", "process_outcome": "timed_out"}
    session = object.__new__(sessions.AdapterSession)
    session.runtime, session.guard_home = tmp_path / "runtime", tmp_path
    session._connection = None
    session.last_stop_diagnostic = failure
    session._stop_diagnostic_written = True
    session.daemon = SimpleNamespace(
        stop=lambda: events.append("daemon-stop"), _server=SimpleNamespace(), _finish_service_completed=True
    )
    session.temporary = SimpleNamespace(
        cleanup=lambda: events.append("state-removed"),
        _finalizer=SimpleNamespace(detach=lambda: events.append("state-retained")),
    )
    monkeypatch.setattr(sessions, "stop_native_resident", lambda *args, **kwargs: NativeStopResult(False, failure))
    monkeypatch.setattr(sessions, "_write_stop_diagnostic", lambda *_: events.append("strict-failure-written"))
    monkeypatch.setattr(sessions, "preserve_session_diagnostics", lambda *_: None)

    def recover(home):
        assert home == tmp_path
        events.append("native-recovery")
        return {"attempted": True, "contained": recovered}

    monkeypatch.setattr(sessions, "recover_failed_stop", recover)
    session._close()
    assert session.final_stop_diagnostic == session.last_stop_diagnostic == failure
    assert session.recovery_cleanup == {"attempted": True, "contained": recovered}
    assert events == [
        "daemon-stop",
        "strict-failure-written",
        "native-recovery",
        "state-removed" if recovered else "state-retained",
    ]
