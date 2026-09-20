"""Actual daemon mixed-control dispatch with finite authority providers.

The dispatcher, mixed fixture, receipt witness, writer and SQLite store are real.
The worker edge and policy ACK are finite controls, not installed native traffic.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_acked
from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_slo_daemon_fixture
from tests.test_native_decision_receipt import _receipt


class _Controls:
    def __init__(self, ending: str, submit: Callable[[], None]) -> None:
        self.ending = ending
        self.submit = submit
        self.index = 0
        self.bounds: list[int] = []
        self.thread_ids: list[int] = []

    def readline(self, limit: int) -> bytes:
        self.bounds.append(limit)
        self.thread_ids.append(threading.get_ident())
        operations = (
            {"op": "mixed_start", "maximum": 1},
            {"op": self.ending},
            {"op": "mixed_page", "offset": 0, "limit": 1},
            {"op": "close"},
        )
        if self.index == 1:
            self.submit()
        if self.index >= len(operations):
            raise AssertionError("dispatcher read beyond the finite control sequence")
        raw = json.dumps(operations[self.index], separators=(",", ":")).encode() + b"\n"
        self.index += 1
        assert len(raw) <= 4096
        return raw


@pytest.mark.parametrize("ending", ["mixed_finish", "unsupported"])
def test_actual_serve_session_keeps_default_observers_and_retires_wrappers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str
) -> None:
    store = GuardStore(tmp_path / "guard")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0.025)
    receipt = _receipt(request_id="daemon-mixed-dispatch")
    edge = {"receipt": receipt}
    calls: list[tuple[str, object]] = []
    binding = {"generation": 2, "policy_digest": "b" * 64, "runtime_identity": "c" * 64}

    def native(**kwargs: Any) -> dict[str, object]:
        calls.append(("native", kwargs))
        return edge

    def prepare(path: Path, *, deadline: float) -> dict[str, object]:
        calls.append(("prepare", path))
        assert isinstance(deadline, float)
        return binding

    def acknowledged(owner: GuardStore) -> dict[str, object]:
        assert owner is store
        calls.append(("ack", owner))
        return binding

    worker = SimpleNamespace(
        _review_raw_hook_native=native,
        test_oracle=None,
        prepare_workspace_policy=prepare,
        policy_snapshot_publisher=SimpleNamespace(
            current_snapshot=lambda: {
                **binding,
                "mode": "enforce",
                "effective_policy": {"default_action": "allow", "subprocess_action": "allow"},
            }
        ),
    )
    server = SimpleNamespace(
        hook_worker=worker,
        runtime_hook_evidence_writer=writer,
        runtime_hook_scheduler=SimpleNamespace(
            stats=lambda: {"active": 0, "queued": 0, "retained_bytes": 0, "oldest_queued_ms": 0}
        ),
        auth_token="finite-control-token",
    )
    session = SimpleNamespace(
        store=store,
        root=tmp_path,
        workspace=workspace,
        guard_home=store.guard_home,
        daemon=SimpleNamespace(_server=server, port=1),
        readiness_ms=0.0,
    )
    emitted: list[dict[str, Any]] = []
    original_submit = writer.submit_native_decision_receipt
    original_connect = sqlite3.connect

    def submit() -> None:
        assert emitted[-1]["status"] == "completed"
        assert writer._queue_observation is None
        assert sqlite3.connect is original_connect
        assert worker._review_raw_hook_native is not native
        assert writer.submit_native_decision_receipt != original_submit
        assert worker._review_raw_hook_native(payload={"native_slo_attempt": "mixed-load-0"}) is edge
        assert writer.submit_native_decision_receipt(receipt) is True
        assert writer.stop(timeout_seconds=3)
        stats = writer.stats()
        assert stats["accepted"] == stats["receipt_accepted"] == 1
        assert stats["processed"] == stats["receipt_processed"] == 1
        assert not writer._thread.is_alive()
        assert store.get_native_decision_receipt(receipt["decision_id"]) == receipt

    controls = _Controls(ending, submit)
    monkeypatch.setattr(native_slo_daemon_fixture, "sys", SimpleNamespace(stdin=SimpleNamespace(buffer=controls)))
    monkeypatch.setattr(native_slo_daemon_fixture, "_emit", emitted.append)
    monkeypatch.setattr(native_policy_snapshot_acked, "acked_snapshot_binding_for_store", acknowledged)
    try:
        if ending == "unsupported":
            with pytest.raises(RuntimeError, match="unsupported daemon fixture operation"):
                native_slo_daemon_fixture._serve_session(session, None)
        else:
            native_slo_daemon_fixture._serve_session(session, None)
    finally:
        assert writer.stop(timeout_seconds=3)
    assert not writer._thread.is_alive()
    assert controls.bounds == [4097] * (4 if ending == "mixed_finish" else 2)
    assert controls.thread_ids == [threading.get_ident()] * len(controls.bounds)
    assert [name for name, _value in calls] == ["prepare", "ack", "native"]
    assert calls[0][1] == workspace
    assert worker._review_raw_hook_native is native
    assert writer.submit_native_decision_receipt == original_submit
    assert writer._queue_observation is None
    assert journal.os is os
    assert sqlite3.connect is original_connect
    assert emitted[0]["state"] == "ready"
    assert emitted[-1] == {"state": "progress", "stage": "cleanup"}
    assert store.get_native_decision_receipt(receipt["decision_id"]) == receipt
    if ending == "mixed_finish":
        final = emitted[2]
        assert final["status"] == "completed"
        assert final["writer"]["accepted"] == final["writer"]["processed"] == 1
        assert final["writer"]["in_flight"] is False
        report = final["receipts"]
        assert report["native_receipts"] == report["writer_admitted"] == report["committed"] == 1
        assert report["binding_mismatches"] == report["missing"] == 0
        assert report["journal_io"]["journal_written_bytes"] > 0
        assert report["journal_io"]["journal_file_fsync_calls"] > 0
        assert report["writer_queue_observation"] is None
        assert report["sqlite_vfs_observation"] is None
        assert report["full_persistence_metric_coverage"] is False
        page = emitted[3]
        assert page["status"] == "completed"
        assert len(page["rows"]) == 1
        assert page["rows"][0]["decision_id"] == receipt["decision_id"]
        assert page["rows"][0]["writer_admitted"] is page["rows"][0]["committed"] is True
    else:
        assert len(emitted) == 3
