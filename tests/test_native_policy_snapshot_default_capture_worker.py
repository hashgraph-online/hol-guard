"""Observe default worker recovery after real startup status commits."""

from __future__ import annotations

import json
import threading
import time
from typing import TypedDict

import pytest

from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _PUBLISH_RETRY_SECONDS
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_context import CapturedV3PublicationInputs
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_policy_snapshot_reservation_capture import _make_publisher


class _CaptureCount(TypedDict):
    captures: int


class _Attempt(_CaptureCount):
    elapsed_ms: float
    transports: int
    error: str | None
    ready: bool
    closed: bool
    retry_remaining_ms: float | None


def _write_status_commit(store: GuardStore, write_number: int) -> tuple[int, int]:
    stamp = f"2026-09-19T00:00:{write_number:02d}Z"
    payload = {"status": "not_configured", "refreshed_at": stamp}
    with store._connect() as observer:
        before = observer.execute("pragma data_version").fetchone()[0]
        store.set_sync_payload("supply_chain_bundle_daemon", payload, stamp)
        after = observer.execute("pragma data_version").fetchone()[0]
    assert before != after
    assert store.get_sync_payload("supply_chain_bundle_daemon") == payload
    return before, after


@pytest.mark.parametrize("writes_mode", ["none", "twice", "continuous"])
def test_default_worker_admits_workspace_after_startup_status_writes(tmp_path, monkeypatch, writes_mode):
    store = GuardStore(tmp_path / "guard-home")
    transports = []
    publisher = _make_publisher(store, transports, scoped=False)
    assert publisher._poll_interval_seconds == _PUBLISH_RETRY_SECONDS == 0.25
    original_run = publisher._run
    original_publish = publisher._publish_once
    original_context = publisher._publication_context
    bootstrap_complete = threading.Event()
    worker_errors = []
    attempts: list[_Attempt] = []
    captures = []
    writes = []
    measuring = False
    active_attempt: _CaptureCount | None = None

    def checked_run():
        try:
            original_run()
        except BaseException as error:
            worker_errors.append(error)
            publisher.close()

    def observed_publish(*, renew_after_generation=None):
        nonlocal active_attempt
        observed = measuring
        attempt: _CaptureCount = {"captures": 0}
        active_attempt = attempt
        started = time.monotonic()
        transport_count = len(transports)
        try:
            return original_publish(renew_after_generation=renew_after_generation)
        finally:
            if observed:
                completed = _Attempt(
                    captures=attempt["captures"],
                    elapsed_ms=round((time.monotonic() - started) * 1_000, 3),
                    transports=len(transports) - transport_count,
                    error=publisher.last_error,
                    ready=publisher.is_ready(),
                    closed=publisher.closed,
                    retry_remaining_ms=(
                        None
                        if publisher._retry_not_before_monotonic is None
                        else round(
                            max(0.0, publisher._retry_not_before_monotonic - time.monotonic()) * 1_000,
                            3,
                        )
                    ),
                )
                attempts.append(completed)
            else:
                bootstrap_complete.set()
            active_attempt = None

    def capture(*, publish_epoch=None, prepared_command_extensions=None):
        context = original_context(publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions)
        if not measuring or publisher.closed or context is None:
            return context
        assert active_attempt is not None
        active_attempt["captures"] += 1
        inputs = context[5]
        assert isinstance(inputs, CapturedV3PublicationInputs)
        assert inputs.source_identity is None and inputs.defaults is None
        captures.append(inputs)
        reservation_read = active_attempt["captures"] >= 2
        inject = writes_mode == "continuous" or (writes_mode == "twice" and len(writes) < 2)
        if reservation_read and inject:
            epoch = publisher._epoch
            writes.append(_write_status_commit(store, len(writes) + 1))
            assert publisher._epoch == epoch
        return context

    monkeypatch.setattr(publisher, "_run", checked_run)
    monkeypatch.setattr(publisher, "_publish_once", observed_publish)
    monkeypatch.setattr(publisher, "_publication_context", capture)
    try:
        # Schema, verifier, real signing, and the initial authenticated barrier
        # complete before the existing 400ms workspace-admission window.
        publisher.start()
        assert publisher.wait_until_ready(time.monotonic() + 2.0), publisher.last_error
        assert bootstrap_complete.wait(2.0)
        assert not worker_errors
        bootstrap_snapshot = publisher.current_snapshot()
        assert bootstrap_snapshot is not None and transports
        bootstrap_transports = len(transports)
        initial_epoch = publisher._epoch
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        # The timed work includes real status commits and all production
        # authority captures. Full fixture-only source comparisons bracket
        # that window instead of adding two extra captures to every commit.
        verified_before = read_native_policy_authority_inputs(store, now=publisher._wall_clock())
        measuring = True
        started = time.monotonic()
        deadline = started + 0.4
        assert publisher.register_workspace(workspace)
        ready = publisher.wait_until_ready(deadline)
        elapsed_ms = (time.monotonic() - started) * 1_000
        observed_epoch = publisher._epoch
        last_error = publisher.last_error
        snapshot = publisher.current_snapshot()
        binding = publisher.current_snapshot_binding()
        retained_snapshot = publisher._snapshot
        observed_transport_count = len(transports) - bootstrap_transports
    finally:
        publisher.close()
    assert publisher._thread is not None and not publisher._thread.is_alive()
    assert not worker_errors, [type(error).__name__ for error in worker_errors]
    verified_after = read_native_policy_authority_inputs(store, now=publisher._wall_clock())
    assert verified_after.input_digest == verified_before.input_digest
    assert observed_epoch == initial_epoch + 1
    assert captures and all(capture.input_digest == captures[0].input_digest for capture in captures)
    assert captures[0].input_digest == verified_after.input_digest
    if writes_mode == "none":
        assert writes == []
    else:
        assert len(writes) >= 2
    assert all(before != after for before, after in writes)
    diagnostic = json.dumps(
        {
            "attempts": attempts,
            "elapsed_ms": round(elapsed_ms, 3),
            "error": last_error,
            "ready": ready,
            "retained_snapshot": retained_snapshot is not None,
            "transports": observed_transport_count,
            "writes": len(writes),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    if writes_mode == "continuous":
        assert not ready and snapshot is None and binding is None, diagnostic
        assert retained_snapshot == bootstrap_snapshot and observed_transport_count == 0, diagnostic
        assert last_error == "native_policy_authority_capture_changed", diagnostic
        assert any(attempt["error"] == last_error for attempt in attempts), diagnostic
    else:
        if writes_mode == "twice":
            assert len(writes) == 2
            rejected = [
                attempt for attempt in attempts if attempt["error"] == "native_policy_authority_capture_changed"
            ]
            assert rejected and rejected[0]["captures"] == 3, diagnostic
            assert rejected[0]["transports"] == 0 and not rejected[0]["ready"], diagnostic
        assert ready, "stable workspace authority did not recover within the default 400ms window: " + diagnostic
        assert elapsed_ms <= 400.0, "workspace readiness exceeded its unchanged deadline: " + diagnostic
        assert observed_transport_count == 1 and snapshot == transports[-1], diagnostic
        assert binding is not None and last_error is None, diagnostic
