"""Finite lifecycle failure controls using synthetic owned state, without native qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_workspace_poststart as lifecycle
from scripts import native_slo_workspace_poststart_session as sessions
from scripts.native_slo_session import NativeStopResult, _build_stop_diagnostic
from scripts.native_slo_workspace_poststart_evidence import RetainedLedger, encode_retained


class ObservedWorkerProcess:
    """A retained multiprocessing-shaped worker with no Popen.poll method."""

    def __init__(self, pid: int, exitcode: int | None) -> None:
        self.pid, self.current_exitcode = pid, exitcode
        self.observations: list[int | None] = []

    @property
    def exitcode(self) -> int | None:
        self.observations.append(self.current_exitcode)
        return self.current_exitcode


def retired_service(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "owned"
    root.mkdir(mode=0o700)
    guard_home = root / ".hol-guard"
    guard_home.mkdir(mode=0o700)
    calls = []
    thread = SimpleNamespace(is_alive=lambda: False)
    runner = SimpleNamespace(
        _state_lock=threading.RLock(),
        _closed=True,
        _started=False,
        _all_slots={},
        _spawn_threads=set(),
        _retirement_threads=set(),
        _active_reviews={},
        _supervisor_thread=None,
    )
    writer = SimpleNamespace(_thread=thread)
    server = SimpleNamespace(
        hook_process_runner=runner,
        runtime_hook_evidence_writer=writer,
        request_executors_stopped=True,
        active_hook_requests=0,
    )
    daemon = SimpleNamespace(
        _server=server,
        _finish_service_completed=True,
        _is_quarantined=lambda: False,
        _owned_service_ready=False,
        _thread=None,
        _owner_lock=None,
        stop=lambda: calls.append("service_stop"),
    )
    service = sessions.PostStartService.__new__(sessions.PostStartService)
    service.root, service.guard_home = root, guard_home
    service.runtime = root / "controlled-runtime"
    service.owner = SimpleNamespace(
        root_identity=sessions.private_identity(root),
        guard_identity=sessions.private_identity(guard_home),
    )
    service.daemon = daemon
    service.publisher = SimpleNamespace(closed=True, _thread=thread)
    service.threads, service.owned_processes = {}, {}
    service.stop_called = False
    service.retirement = {"passed": False, "status": "not_stopped"}
    monkeypatch.setattr(service, "retain_owned_work", lambda: None)
    return service, calls


@pytest.mark.parametrize(
    "first_contained,last_contained",
    [
        (False, False),
        (False, True),
        (True, False),
        (True, True),
    ],
)
def test_both_native_stop_outcomes_survive_one_service_stop(tmp_path, monkeypatch, first_contained, last_contained):
    service, calls = retired_service(tmp_path, monkeypatch)
    process = ObservedWorkerProcess(4321, 0)
    service.owned_processes[id(process)] = process
    originals = [
        _build_stop_diagnostic(
            "contained" if contained else "failed",
            error=None if contained else code,
            fields={"endpoint": "verified" if contained else "unverified"},
        )
        for contained, code in (
            (first_contained, "native_resident_stop_unavailable"),
            (last_contained, "native_resident_stop_containment_failed"),
        )
    ]
    expected = copy.deepcopy(originals)
    results = iter(
        [
            NativeStopResult(first_contained, originals[0]),
            NativeStopResult(last_contained, originals[1]),
        ]
    )

    def stop(runtime, guard_home, *, write_diagnostic):
        assert runtime == service.runtime and guard_home == service.guard_home
        assert write_diagnostic is False
        calls.append("native_stop")
        return next(results)

    monkeypatch.setattr(sessions, "stop_native_resident", stop)
    observed = service.stop()
    assert calls == ["native_stop", "service_stop", "native_stop"]
    assert observed["passed"] is (first_contained and last_contained)
    assert observed["explicit_service_stop_calls"] == 1
    assert observed["last_native_stop_contained"] is last_contained
    assert [row["diagnostic"] for row in observed["native_stop_observations"]] == expected
    assert [row["contained"] for row in observed["native_stop_observations"]] == [
        first_contained,
        last_contained,
    ]
    originals[0]["endpoint"] = "unknown"
    assert observed["native_stop_observations"][0]["diagnostic"] == expected[0]
    assert json.loads(encode_retained(observed)) == observed
    assert observed["retained_direct_workers"] == [{"pid": 4321, "returncode": 0, "reaped": True}]
    assert observed["checks"]["retained_direct_workers_reaped"] is True
    assert process.observations == [0]
    assert service.stop() == observed
    assert calls == ["native_stop", "service_stop", "native_stop"]
    assert process.observations == [0]


@pytest.mark.parametrize("fault", ["quarantine", "writer_alive", "runner_slot"])
def test_current_unretired_service_state_blocks_retirement(tmp_path, monkeypatch, fault):
    service, calls = retired_service(tmp_path, monkeypatch)
    if fault == "quarantine":
        service.daemon._is_quarantined = lambda: True
        field = "service_not_quarantined"
    elif fault == "writer_alive":
        service.daemon._server.runtime_hook_evidence_writer._thread = SimpleNamespace(is_alive=lambda: True)
        field = "writer_thread_retired"
    else:
        service.daemon._server.hook_process_runner._all_slots["controlled"] = object()
        field = "runner_closed_and_empty"
    monkeypatch.setattr(
        sessions,
        "stop_native_resident",
        lambda *_args, **_kwargs: NativeStopResult(True, _build_stop_diagnostic("contained")),
    )
    result = service.stop()
    assert result["passed"] is False and result["checks"][field] is False
    assert calls == ["service_stop"]

    process = ObservedWorkerProcess(4322, None)
    service.owned_processes[id(process)] = process
    for exitcode in (None, -9):
        process.current_exitcode = exitcode
        snapshot = service.retirement_snapshot([], result["native_stop_observations"], [])
        assert snapshot["passed"] is False and snapshot["checks"][field] is False
        expected_worker = {"pid": 4322, "returncode": exitcode, "reaped": exitcode is not None}
        assert snapshot["retained_direct_workers"] == [expected_worker]
        assert snapshot["checks"]["retained_direct_workers_reaped"] is (exitcode is not None)
    assert process.observations == [None, -9]
    assert service.stop() == result
    assert process.observations == [None, -9]
    assert calls == ["service_stop"]


def test_service_stop_error_cannot_erase_either_original_native_failure(tmp_path, monkeypatch):
    service, calls = retired_service(tmp_path, monkeypatch)
    original = [
        _build_stop_diagnostic("failed", error="native_resident_stop_unavailable"),
        _build_stop_diagnostic("failed", error="native_resident_stop_containment_failed"),
    ]
    outcomes = iter(NativeStopResult(False, value) for value in original)

    def fail_service():
        calls.append("service_stop")
        raise RuntimeError("controlled service stop failure")

    service.daemon.stop = fail_service
    monkeypatch.setattr(sessions, "stop_native_resident", lambda *_args, **_kwargs: next(outcomes))
    result = service.stop()
    assert result["passed"] is False
    assert [row["diagnostic"] for row in result["native_stop_observations"]] == original
    assert result["errors"] == [
        "before_service_stop:native_containment_failed",
        "service_stop:RuntimeError",
        "after_service_stop:native_containment_failed",
    ]
    assert (
        result["failures"][0]["failure"]["diagnostic_digest"]
        == hashlib.sha256(b"controlled service stop failure").hexdigest()
    )
    assert calls == ["service_stop"]


def test_failed_retirement_refuses_replacement_before_constructor(monkeypatch):
    home = sessions.PersistentWorkspaceHome.__new__(sessions.PersistentWorkspaceHome)
    home.removed = home.construction_failed = False
    home.instances = [SimpleNamespace(retirement={"passed": False})]
    calls = []

    def forbidden(_home):
        calls.append("construct")
        raise AssertionError("replacement must not construct")

    monkeypatch.setattr(sessions, "PostStartService", forbidden)
    with pytest.raises(RuntimeError, match="retirement is not verified"):
        home.start_instance()
    assert calls == []


def test_ready_and_unexpected_stop_failures_both_reach_terminal_evidence(tmp_path):
    def not_ready():
        raise RuntimeError("controlled original readiness failure")

    def bad_stop():
        raise RuntimeError("controlled unexpected stop failure")

    session = SimpleNamespace(
        ready=not_ready,
        stop=bad_stop,
        retirement={"passed": False, "status": "not_stopped"},
    )
    home = SimpleNamespace(workspaces=(Path("controlled"),), start_instance=lambda: session)
    ledger = RetainedLedger(tmp_path / "failures.jsonl")
    result = lifecycle.service(home, 0, ledger)
    assert result["passed"] is False and result["status"] == "finished"
    assert (
        result["failure"]["diagnostic_digest"] == hashlib.sha256(b"controlled original readiness failure").hexdigest()
    )
    assert (
        result["retirement"]["failure"]["diagnostic_digest"]
        == hashlib.sha256(b"controlled unexpected stop failure").hexdigest()
    )
    assert ledger.finish()["complete"] is True


def test_failed_ledger_refuses_new_cell_before_home_construction(tmp_path, monkeypatch):
    ledger = RetainedLedger(tmp_path / "refuse.jsonl")
    with pytest.raises(ValueError):
        ledger.write({"kind": "poststart_cell_offer", "payload": "controlled"})
    calls = []

    def forbidden(*_args):
        calls.append("construct")
        raise AssertionError("home must not construct after retention failure")

    monkeypatch.setattr(lifecycle, "PersistentWorkspaceHome", forbidden)
    result = lifecycle.cell(Path("controlled"), 1, ledger)
    assert result["passed"] is False
    assert result["unoffered_service_instances"] == result["unconstructed_service_instances"] == 2
    assert calls == []
    assert ledger.finish()["complete"] is False
