"""Late publication failures cannot overwrite a newer barrier or a closed one."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_publisher_context as publisher_context
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _DeterministicClock, _status


@pytest.mark.parametrize(
    "failure",
    ["publication", "transport", "context-runtime", "context-key", "context-capture"],
)
@pytest.mark.parametrize("handoff", ["accepted", "closed"])
def test_late_failure_preserves_newer_or_closed_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, handoff: str
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    master = b"e" * 32
    clock = _DeterministicClock()
    original_capture = publisher_context.compiled_scoped_policy
    armed = False
    handoffs: list[int] = []
    snapshots: list[dict[str, object]] = []
    accepted: dict[str, object] | None = None
    retry_before: float | None = None
    failures_before = 0

    def complete_handoff() -> None:
        nonlocal armed, accepted, retry_before, failures_before
        assert armed
        armed = False
        handoffs.append(publisher._epoch)
        if handoff == "accepted":
            publisher.request_publish()
            publisher._publish_once()
            assert publisher.is_ready()
            accepted = publisher.current_snapshot_binding()
            assert accepted is not None
        else:
            publisher.close()
            assert publisher.closed
            assert not publisher.is_ready()
        assert publisher.last_error is None
        retry_before = publisher._retry_not_before_monotonic
        failures_before = publisher._failure_count

    def status_provider() -> SimpleNamespace:
        status = _status()
        if armed and failure == "context-runtime":
            complete_handoff()
            status.available = False
        return status

    def material_getter(
        *, create: bool, connection: sqlite3.Connection | None = None
    ) -> tuple[bytes | None, str | None]:
        del connection
        if create and armed and failure == "context-key":
            complete_handoff()
            return None, None
        return master, "master-id"

    def capture_then_fail(capture_publisher: NativePolicySnapshotPublisher, *, command_extensions=None):
        captured = original_capture(capture_publisher, command_extensions=command_extensions)
        if armed and failure == "context-capture":
            complete_handoff()
            raise NativePolicySnapshotError("native_policy_authority_capture_changed")
        return captured

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        snapshot = json.loads(payload)["request"]["snapshot"]
        assert isinstance(snapshot["generation"], int) and snapshot["generation"] > 0
        assert isinstance(snapshot["policy_digest"], str) and len(snapshot["policy_digest"]) == 64
        snapshots.append(snapshot)
        if armed and failure in {"publication", "transport"}:
            complete_handoff()
            if failure == "publication":
                raise NativePolicySnapshotError("native_policy_snapshot_ack_invalid")
            raise OSError()
        return _ack(payload)

    monkeypatch.setattr(store, "_policy_integrity_secret_material", material_getter)
    monkeypatch.setattr(publisher_context, "compiled_scoped_policy", capture_then_fail)
    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=status_provider,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        # Catalog authority is a publication prerequisite. Inject the late
        # failure only after it is prepared, at the named context/IPC boundary.
        publisher._compiled_command_extensions()
        armed = True
        publisher.request_publish()
        attempt_epoch = publisher._epoch
        publisher._publish_event.clear()
        publisher._publish_once()
        assert handoffs == [attempt_epoch]
        assert publisher._epoch == attempt_epoch + int(handoff == "accepted")
        assert len(snapshots) == int(failure in {"publication", "transport"}) + int(handoff == "accepted")
        assert publisher._publish_event.is_set()
        assert publisher.closed is (handoff == "closed")
        if handoff == "accepted":
            assert publisher.is_ready()
            assert publisher.current_snapshot_binding() == accepted
        else:
            assert not publisher.is_ready()
            assert publisher.current_snapshot_binding() is None
        assert publisher.last_error is None
        assert publisher._failure_count == failures_before
        assert publisher._retry_not_before_monotonic == retry_before
    finally:
        publisher.close()
