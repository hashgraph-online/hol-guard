"""Private fixtures drain their real evidence producer before native Stop."""

from __future__ import annotations

import threading
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_evidence_dispatch import HookEvidenceDispatch
from scripts import bench_guard_cigar_contention as contention
from scripts import cigar_slo_activity as activity_module
from scripts import native_slo_session as sessions
from scripts.native_slo_stop_diagnostics import NativeStopResult


def fixture(tmp_path, monkeypatch, *, daemon_stop):
    session = object.__new__(sessions.AdapterSession)
    events = []
    session.runtime, session.guard_home = tmp_path / "runtime", tmp_path
    session._connection = None
    session.daemon = SimpleNamespace(
        stop=daemon_stop,
        _finish_service_completed=False,
        _server=SimpleNamespace(active_hook_requests=0),
    )
    session.temporary = SimpleNamespace(
        cleanup=lambda: events.append("state-removed"),
        _finalizer=SimpleNamespace(detach=lambda: events.append("state-retained")),
    )
    monkeypatch.setattr(sessions, "_write_stop_diagnostic", lambda *_: None)
    monkeypatch.setattr(sessions, "preserve_session_diagnostics", lambda *_: None)
    return session, events


def test_actual_ordered_evidence_drains_against_the_live_resident_before_stop(tmp_path, monkeypatch):
    entered, release, native_alive = threading.Event(), threading.Event(), threading.Event()
    native_alive.set()
    dispatch = HookEvidenceDispatch()
    recorded, stop_observations = [], []

    def receipt():
        entered.set()
        assert release.wait(2)
        recorded.append(("receipt", native_alive.is_set()))

    dispatch.run(receipt)
    dispatch.run(lambda: recorded.append(("activity", native_alive.is_set())))
    dispatch.run(lambda: recorded.append(("discovery", native_alive.is_set())))
    assert entered.wait(1)

    def daemon_stop():
        release.set()
        session.daemon._finish_service_completed = dispatch.stop(1)

    session, state_events = fixture(tmp_path, monkeypatch, daemon_stop=daemon_stop)

    def stop(*_args, **_options):
        stop_observations.append(len(recorded))
        native_alive.clear()
        return NativeStopResult(True, {"status": "contained"})

    monkeypatch.setattr(sessions, "stop_native_resident", stop)
    try:
        session.close()
        assert recorded == [("receipt", True), ("activity", True), ("discovery", True)]
        assert stop_observations == [3, 3]
        assert state_events == ["state-removed"]
    finally:
        release.set()
        assert dispatch.stop(1)


@pytest.mark.parametrize("client_containment", [False, None])
def test_successful_resident_stop_cannot_hide_false_client_containment(tmp_path, monkeypatch, client_containment):
    monkeypatch.setattr(sessions, "_resident_state_may_exist", lambda _path: False)
    monkeypatch.setattr(sessions, "close_native_resident_clients", lambda _home: client_containment)
    result = sessions.stop_native_resident(Path("/owned/runtime"), tmp_path, write_diagnostic=False)
    assert not result
    assert result.diagnostic["status"] == "contained_client_cleanup_failed"
    assert "private" not in str(result.diagnostic)


def test_unconfirmed_daemon_stop_retains_private_state_and_original_native_result(tmp_path, monkeypatch):
    session, events = fixture(tmp_path, monkeypatch, daemon_stop=lambda: None)
    monkeypatch.setattr(
        sessions, "stop_native_resident", lambda *_args, **_options: NativeStopResult(True, {"status": "contained"})
    )
    session.close()
    assert session.daemon_stop_contained is False
    assert session.final_stop_diagnostic == {"status": "contained"}
    assert events == ["state-retained"]


def test_focused_gate_requires_daemon_containment_when_no_native_process_is_left():
    result = {"gates": {}}
    session = SimpleNamespace(
        final_stop_diagnostic={"status": "contained"},
        last_stop_diagnostic={"status": "contained"},
        recovery_cleanup=None,
        daemon_stop_contained=False,
    )
    sampler = SimpleNamespace(
        sample=lambda: {"rss_bytes": 1, "counts": {"benchmark_daemon_host": 1}},
        summary=lambda: {},
        errors=0,
    )
    contention.finish_cleanup(result, session, sampler)
    assert result["gates"]["strict_final_stop"]
    assert result["gates"]["all_observed_live_descendants_contained"]
    assert not result["gates"]["daemon_shutdown_contained"]


def test_complete_slo_activity_retains_unconfirmed_daemon_shutdown(monkeypatch):
    activity = object.__new__(activity_module.CigarSloActivity)
    activity.cleanups = []
    session = object.__new__(activity_module._ObservedSession)
    session._on_cleanup = partial(activity.contained, "session_1")
    session.final_stop_diagnostic = session.last_stop_diagnostic = {"status": "contained"}
    session.recovery_cleanup = None
    session.daemon_stop_contained = False
    monkeypatch.setattr(sessions.AdapterSession, "close", lambda _self: None)
    session.close()
    assert activity.cleanups[0]["daemon_stop_contained"] is False
    assert activity.cleanups[0]["final_contained"] is False
