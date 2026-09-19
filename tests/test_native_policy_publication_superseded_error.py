"""A superseded publication must not delay a newer pending policy epoch."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _DeterministicClock, _status


@pytest.mark.parametrize("failure", ["publication", "transport"])
@pytest.mark.parametrize("supersede", [False, True], ids=["current-epoch", "new-workspace"])
def test_publication_error_belongs_to_its_attempt_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, supersede: bool
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    master = b"e" * 32
    monkeypatch.setattr(
        store, "_policy_integrity_secret_material", lambda *, create, connection=None: (master, "master-id")
    )
    clock = _DeterministicClock()
    error = NativePolicySnapshotError("native_policy_snapshot_ack_invalid") if failure == "publication" else OSError()
    attempts: list[tuple[int, bool]] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        snapshot = json.loads(payload)["request"]["snapshot"]
        assert isinstance(snapshot["generation"], int) and snapshot["generation"] > 0
        assert isinstance(snapshot["policy_digest"], str) and len(snapshot["policy_digest"]) == 64
        before = publisher._epoch
        if supersede:
            assert publisher.register_workspace(workspace) is True
        attempts.append((before, publisher._publish_event.is_set()))
        raise error

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        publisher.request_publish()
        attempt_epoch = publisher._epoch
        publisher._publish_event.clear()
        publisher._publish_once()
        assert len(attempts) == 1
        assert attempts[0] == (attempt_epoch, supersede)
        assert publisher._epoch == attempt_epoch + int(supersede)
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert publisher._publish_event.is_set() is supersede

        if supersede:
            assert publisher.last_error is None
            assert publisher._failure_count == 0
            assert publisher._retry_not_before_monotonic is None
        else:
            expected = "native_policy_snapshot_ack_invalid" if failure == "publication" else "oserror"
            assert publisher.last_error == expected
            assert publisher._failure_count == 1
            retry_at = publisher._retry_not_before_monotonic
            assert retry_at is not None
            assert clock.monotonic < retry_at <= clock.monotonic + 0.2
    finally:
        publisher.close()
