"""Private-control wiring with real SQLite/writer and synthetic native returns."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_mixed import run_mixed_scenario
from scripts.native_slo_mixed_request import fixture_request
from scripts.native_slo_mixed_server import MixedScenarioFixture
from scripts.native_slo_persistence_observation import PersistenceObservationSpec, persistence_observation_checks
from tests.native_workspace_request_fixtures import receipt, snapshot
from tests.test_native_slo_sqlite_vfs import sqlite_vfs_build as sqlite_vfs_build


@pytest.mark.parametrize(
    "change",
    [
        {"extension": "relative.so"},
        {"extension": "/" + "a" * 1024},
        {"extension": None},
        {"extension_sha256": "x" * 64},
        {"extension_sha256": "a" * 63},
        {"queue_max_pending": 0},
        {"queue_max_pending": 65_537},
        {"queue_max_pending": True},
        {"schema": "unknown"},
        {"extra": True},
    ],
)
def test_private_observation_control_rejects_invalid_or_extra_scope(change: dict[str, object]) -> None:
    request = PersistenceObservationSpec(Path("/owned/observer.so"), "a" * 64).to_request()
    with pytest.raises(ValueError):
        PersistenceObservationSpec.from_request({**request, **change})


@pytest.mark.parametrize("observed", [False, True])
def test_only_explicit_control_request_crosses_the_existing_fixture_pipe(tmp_path: Path, observed: bool) -> None:
    seen = []

    class FailedFixture:
        def control(self, operation: str, **kwargs: object) -> dict[str, object]:
            seen.append((operation, kwargs))
            return {"status": "failed"}

        def request(self, *_args: object) -> tuple[dict[str, object], float]:
            pytest.fail("failed fixture must not offer hook work")

    spec = PersistenceObservationSpec(tmp_path / "observer.so", "a" * 64) if observed else None
    result = run_mixed_scenario(FailedFixture(), raw_file=tmp_path / "control.jsonl", receipt_observation=spec)
    assert result["passed"] is False
    assert len(seen) == 1 and seen[0][0] == "mixed_start"
    if spec is None:
        assert "receipt_observation" not in seen[0][1]
    else:
        wire = json.loads(json.dumps(seen[0][1]["receipt_observation"]))
        assert PersistenceObservationSpec.from_request(wire) == spec


def test_legacy_receipt_profile_cannot_enable_current_observer_contract(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="current candidate"):
        run_mixed_scenario(
            object(),
            raw_file=tmp_path / "never-created.jsonl",
            receipt_profile="baseline_2e672d2",
            receipt_observation=PersistenceObservationSpec(tmp_path / "observer.so", "a" * 64),
        )
    assert not (tmp_path / "never-created.jsonl").exists()


@pytest.mark.skipif(sys.platform != "linux" or sys.version_info < (3, 12), reason="Linux Python 3.12 VFS admission")
def test_wire_spec_installs_real_sqlite_and_queue_observation_in_mixed_dispatch(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard")
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0.01)
    native = receipt(snapshot())
    edge = {"receipt": native}
    worker = SimpleNamespace(test_oracle=None, _review_raw_hook_native=lambda **_kwargs: edge)
    scheduler = SimpleNamespace(stats=lambda: {"active": 0, "queued": 0, "retained_bytes": 0, "oldest_queued_ms": 0})
    session = SimpleNamespace(
        store=store,
        daemon=SimpleNamespace(
            _server=SimpleNamespace(
                hook_worker=worker, runtime_hook_evidence_writer=writer, runtime_hook_scheduler=scheduler
            )
        ),
    )
    fixture = MixedScenarioFixture(session)
    monkeypatch.setattr(fixture, "_ack", lambda *_args, **_kwargs: {})
    spec = PersistenceObservationSpec(sqlite_vfs_build["extension"], sqlite_vfs_build["extension_sha256"])
    try:
        wrong = {**spec.to_request(), "extension_sha256": "0" * 64}
        refused = fixture.dispatch("mixed_start", {"maximum": 1, "receipt_observation": wrong})
        assert refused["status"] == "failed"
        assert fixture.witness is None and writer._queue_observation is None
        started = fixture.dispatch("mixed_start", {"maximum": 1, "receipt_observation": spec.to_request()})
        assert started["status"] == "completed"
        request = fixture_request("claude-code", "PostToolUse", attempt="mixed-load-0")
        assert worker._review_raw_hook_native(payload=request) is edge
        assert writer.submit_native_decision_receipt(native) is True
        final = fixture.dispatch("mixed_finish", {})
        assert final["status"] == "completed"
        report = {
            "queues_and_persistence": final,
            "checks": {"native_receipts_committed": True, "every_completed_hook_bound": True},
        }
        checks = persistence_observation_checks(report)
        assert all(checks.values()), checks
        assert final["receipts"]["native_receipts"] == final["receipts"]["committed"] == 1
        assert store.get_native_decision_receipt(native["decision_id"]) == native
        for mutation in (
            lambda value: value["queues_and_persistence"]["receipts"]["sqlite_vfs_observation"].update(closed=False),
            lambda value: value["queues_and_persistence"]["receipts"]["writer_queue_observation"].update(attached=True),
            lambda value: value["queues_and_persistence"]["receipts"].update(sqlite_fsync_calls=1),
        ):
            altered = copy.deepcopy(report)
            mutation(altered)
            assert not all(persistence_observation_checks(altered).values())
    finally:
        assert writer.stop(timeout_seconds=3)
        fixture.close()


def test_observer_cleanup_runs_even_if_receipt_wrapper_cleanup_raises() -> None:
    closed = []

    def failure() -> None:
        raise RuntimeError("wrapper cleanup sentinel")

    fixture = MixedScenarioFixture(object(), sqlite_observer=SimpleNamespace(close=lambda: closed.append("sqlite")))
    fixture.witness = SimpleNamespace(close=failure)
    with pytest.raises(RuntimeError, match="wrapper cleanup sentinel"):
        fixture.close()
    assert closed == ["sqlite"]


@pytest.mark.skipif(sys.platform != "linux" or sys.version_info < (3, 12), reason="Linux Python 3.12 VFS admission")
@pytest.mark.parametrize("failure", ["constructor", "entry", "cleanup"])
def test_failed_witness_start_releases_actual_vfs_before_a_valid_retry(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any], monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal
    from scripts import native_slo_mixed_server
    from scripts.native_slo_sqlite_vfs import SQLiteVFSObservation

    store = GuardStore(tmp_path / "guard")
    writer = RuntimeHookEvidenceWriter(store=store)
    worker = SimpleNamespace(test_oracle=None, _review_raw_hook_native=lambda **_kwargs: None)
    session = SimpleNamespace(
        store=store,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer)),
    )
    fixture = MixedScenarioFixture(session)
    monkeypatch.setattr(fixture, "_ack", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(fixture, "_stats", lambda: {})
    monkeypatch.setattr(fixture, "sample", lambda: {})
    spec = PersistenceObservationSpec(sqlite_vfs_build["extension"], sqlite_vfs_build["extension_sha256"])
    request = {"maximum": 1, "receipt_observation": spec.to_request()}
    primary = ValueError("constructor sentinel")

    def fail_constructor(*_args: object, **_kwargs: object) -> None:
        raise primary

    close = SQLiteVFSObservation.close

    def close_then_fail(observer: SQLiteVFSObservation) -> bool:
        assert close(observer)
        raise RuntimeError("cleanup sentinel")

    try:
        with monkeypatch.context() as faults:
            if failure == "entry":
                faults.delattr(journal, "fsync_directory")
            else:
                faults.setattr(native_slo_mixed_server, "ReceiptWitness", fail_constructor)
                if failure == "cleanup":
                    faults.setattr(SQLiteVFSObservation, "close", close_then_fail)
            with pytest.raises((ValueError, RuntimeError)) as caught:
                fixture._dispatch("mixed_start", request)
            if failure != "entry":
                assert caught.value is primary
            if failure == "cleanup":
                assert fixture.progress["observation_cleanup_failed"] is True
        assert fixture.witness is fixture.sqlite_observer is fixture.queue_observation is None
        assert writer._queue_observation is None
        assert fixture.dispatch("mixed_start", request)["status"] == "completed"
        assert fixture.sqlite_observer.report()["identity"]["extension_loaded_by_actual_python_connection"] is True
    finally:
        assert writer.stop(timeout_seconds=3)
        fixture.close()
