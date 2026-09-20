from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from queue import Queue
from types import FunctionType

import pytest

from codex_plugin_scanner.guard import native_resident_client as client_module
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_publication_worker_diagnostic as diagnostic
from scripts.native_publication_diagnostic import observe_publication
from scripts.native_slo_contract import MAX_READINESS_P95_MS
from tests.native_policy_snapshot_test_fixtures import _ack, _status


def _publisher() -> NativePolicySnapshotPublisher:
    publisher = object.__new__(NativePolicySnapshotPublisher)
    publisher._started, publisher._closed, publisher._acked = True, False, False
    publisher._snapshot = None
    publisher._thread = None
    publisher._publish_event = threading.Event()
    return publisher


def test_existing_captured_transport_is_visible_when_late_observer_counts_are_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, release = threading.Event(), threading.Event()
    calls = []

    def transport(**kwargs):
        # This call and its private request exist before the observer attaches.
        private_canary = "synthetic-private-captured-request-canary"
        calls.append(private_canary)
        entered.set()
        assert release.wait(5)
        return _ack(kwargs["payload"])

    monkeypatch.setattr(client_module, "native_resident_client_request", transport)
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path), status_provider=_status)
    try:
        publisher.start()
        assert entered.wait(3)
        with observe_publication(publisher) as observation:
            assert observation.attached
            assert publisher.register_workspace(tmp_path / "workspace")
            deadline = time.monotonic() + MAX_READINESS_P95_MS / 1_000
            assert not publisher.wait_until_ready(deadline)
            assert publisher.current_snapshot_binding() is None
            observed = observation.describe(publisher.last_error) + observation.readiness.describe(publisher)
            assert "started=0; completed=0" in observed
            assert "publication_calls=0/0" in observed
            assert "preparation_context_calls=0/0" in observed
            facts = diagnostic.describe_publication_worker(publisher)
            assert "worker_started=yes; worker_closed=no; worker_acked=no; worker_snapshot=missing" in facts
            assert "worker_thread=alive; worker_event=yes" in facts
            assert "worker_phase=snapshot_transport; worker_stack=matched" in facts
            assert "private" not in facts and "canary" not in facts and str(tmp_path) not in facts
            assert len(calls) == 1 and publisher._epoch == 2
    finally:
        release.set()
        publisher.close(timeout_seconds=2)
    assert publisher._thread is not None and not publisher._thread.is_alive()


def test_unknown_objects_are_not_interpreted_or_rendered() -> None:
    class Hostile:
        def __getattribute__(self, name: str):
            pytest.fail("Untrusted diagnostic property was accessed")

        def __repr__(self) -> str:
            pytest.fail("Untrusted diagnostic value was rendered")

    facts = diagnostic.describe_publication_worker(Hostile())
    assert facts == (
        "worker_started=unknown; worker_closed=unknown; worker_acked=unknown; worker_snapshot=unknown; "
        "worker_thread=unknown; worker_event=unknown; worker_phase=unknown; worker_stack=unavailable"
    )


def test_state_fields_reject_private_values_and_fake_thread_event_objects() -> None:
    class Hostile:
        def is_alive(self) -> bool:
            pytest.fail("Fake thread was called")

        def is_set(self) -> bool:
            pytest.fail("Fake event was called")

        def __bool__(self) -> bool:
            pytest.fail("Private state was coerced")

        def __repr__(self) -> str:
            pytest.fail("Private state was rendered")

    publisher = _publisher()
    vars(publisher).update(
        dict.fromkeys(("_started", "_closed", "_acked", "_snapshot", "_thread", "_publish_event"), Hostile())
    )
    assert "private" not in diagnostic.describe_publication_worker(publisher)
    assert "=yes" not in diagnostic.describe_publication_worker(publisher)
    assert "=no" not in diagnostic.describe_publication_worker(publisher)


def test_missing_and_stopped_threads_are_distinct_and_no_thread_is_started() -> None:
    publisher = _publisher()
    assert "worker_thread=missing; worker_event=no" in diagnostic.describe_publication_worker(publisher)
    publisher._thread = threading.Thread(target=lambda: pytest.fail("Diagnostic started a thread"))
    publisher._snapshot = {"synthetic-private-canary": object()}
    publisher._publish_event.set()
    facts = diagnostic.describe_publication_worker(publisher)
    assert "worker_snapshot=present; worker_thread=stopped; worker_event=yes" in facts
    assert "private" not in facts and "canary" not in facts


@pytest.mark.parametrize("frame_failure", [False, True])
def test_exact_thread_and_event_methods_ignore_instance_overrides_and_frame_failure_is_finite(
    monkeypatch: pytest.MonkeyPatch, frame_failure: bool
) -> None:
    publisher = _publisher()
    entered, release = threading.Event(), threading.Event()

    def worker() -> None:
        entered.set()
        assert release.wait(2)

    def forbidden() -> bool:
        pytest.fail("Arbitrary instance method was called")

    def unavailable():
        raise RuntimeError("synthetic-private-frame-canary")

    thread = threading.Thread(target=worker)
    publisher._thread = thread
    thread.start()
    try:
        assert entered.wait(1)
        monkeypatch.setattr(thread, "is_alive", forbidden)
        monkeypatch.setattr(publisher._publish_event, "is_set", forbidden)
        if frame_failure:
            monkeypatch.setattr(diagnostic.sys, "_current_frames", unavailable)
        facts = diagnostic.describe_publication_worker(publisher)
        assert "worker_thread=alive; worker_event=no; worker_phase=unknown" in facts
        assert f"worker_stack={'unavailable' if frame_failure else 'complete'}" in facts
        assert "private" not in facts and "canary" not in facts
    finally:
        release.set()
        thread.join(2)
    assert not threading.Thread.is_alive(thread)


def test_frame_walk_is_bounded_and_unknown_frame_objects_are_rejected() -> None:
    def nested(depth: int) -> tuple[str, str]:
        if depth:
            return nested(depth - 1)
        return diagnostic._stack_phase(sys._getframe())

    assert nested(diagnostic._MAX_STACK_FRAMES + 1) == ("unknown", "truncated")
    assert diagnostic._stack_phase(None) == ("unknown", "complete")
    assert diagnostic._stack_phase(object()) == ("unknown", "unavailable")


def test_spoofed_function_name_and_source_path_do_not_match_trusted_code_identity() -> None:
    def sample() -> tuple[str, str]:
        return diagnostic._stack_phase(sys._getframe())

    trusted = NativePolicySnapshotPublisher._publish_once.__code__
    spoofed = FunctionType(sample.__code__.replace(co_name=trusted.co_name, co_filename=trusted.co_filename), globals())
    phase, _scan = spoofed()
    assert phase == "unknown"


@pytest.mark.parametrize("native_request", [False, True])
def test_actual_response_queue_wait_requires_trusted_native_request_context(
    monkeypatch: pytest.MonkeyPatch, native_request: bool
) -> None:
    entered = threading.Event()

    class NotifyingQueue(Queue[bytes]):
        def get(self, block: bool = True, timeout: float | None = None) -> bytes:
            entered.set()
            return super().get(block=block, timeout=timeout)

    responses = NotifyingQueue(maxsize=1)
    client = _PersistentNativeClient(
        executable=Path("synthetic-private-executable"),
        state_dir=Path("synthetic-private-state"),
        environment={},
    )
    monkeypatch.setattr(client, "_request_snapshot", lambda: (object(), object(), responses))
    monkeypatch.setattr(client, "_request_is_current", lambda *_args: True)
    monkeypatch.setattr(client, "_write_frame", lambda *_args, **_kwargs: True)
    returned: list[bytes | None] = []

    def worker() -> None:
        returned.append(
            client.request(b"synthetic-private-payload", deadline_monotonic=time.monotonic() + 3)
            if native_request
            else responses.get(timeout=3)
        )

    publisher = _publisher()
    thread = threading.Thread(target=worker)
    publisher._thread = thread
    thread.start()
    try:
        assert entered.wait(1)
        expected = "client_response_wait" if native_request else "unknown"
        deadline = time.monotonic() + 1
        while True:
            phase, scan = diagnostic._worker_phase(thread)
            if phase == expected or time.monotonic() >= deadline:
                break
            time.sleep(0.001)
        assert phase == expected
        assert scan == ("matched" if native_request else "complete")
        facts = diagnostic.describe_publication_worker(publisher)
        assert f"worker_phase={expected}" in facts
        assert "private" not in facts and "payload" not in facts
        assert returned == []
    finally:
        responses.put_nowait(b"synthetic-private-response")
        thread.join(2)
    assert not thread.is_alive()
    assert returned == [b"synthetic-private-response"]
