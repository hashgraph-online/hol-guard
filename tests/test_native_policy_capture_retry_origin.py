"""Keep the one initial capture retry local, bounded, and outside renewals."""

from __future__ import annotations

import json
from contextlib import closing

from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_policy_snapshot_capture_retry import _interrupt_reservation
from tests.test_native_policy_snapshot_reservation_capture import _make_publisher


def test_resident_capture_error_cannot_consume_local_retry_allowance(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        original_client = publisher._client_request
        assert original_client is not None

        def failed_reply(**kwargs):
            original_client(**kwargs)
            return json.dumps({"error": "native_policy_authority_capture_changed"}).encode()

        monkeypatch.setattr(publisher, "_client_request", failed_reply)
        publisher._publish_once()
        assert len(calls) == 1
        assert publisher.last_error == "native_policy_authority_capture_changed"
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert publisher._snapshot is None
        assert not publisher._initial_database_capture_retry_used
        assert publisher._failure_count == 1
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > publisher._monotonic_clock()


def test_capture_retry_allowance_remains_spent_after_new_request(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        captures, writes = _interrupt_reservation(publisher, monkeypatch, repeated=True)
        publisher._publish_once()
        assert len(captures) == 3 and len(writes) == 2 and calls == []
        assert publisher.last_error == "native_policy_authority_capture_changed"
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert publisher._initial_database_capture_retry_used
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic <= publisher._monotonic_clock()
        publisher._publish_once()
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert calls == [] and publisher._snapshot is None
        assert publisher.last_error == "native_policy_authority_capture_changed"
        assert publisher._failure_count == 2
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > publisher._monotonic_clock()
        assert publisher.register_workspace(tmp_path / "workspace")
        publisher._publish_once()
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert calls == [] and publisher._snapshot is None
        assert publisher.last_error == "native_policy_authority_capture_changed"
        assert publisher._initial_database_capture_retry_used
        assert publisher._failure_count == 1
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > publisher._monotonic_clock()
        assert all(before != after for before, after in writes)


def test_acknowledged_renewal_capture_refusal_keeps_normal_backoff(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        publisher._publish_once()
        assert publisher.is_ready() and len(calls) == 1
        initial_snapshot = publisher._snapshot
        assert initial_snapshot is not None
        captures, writes = _interrupt_reservation(publisher, monkeypatch, repeated=True)
        generation = initial_snapshot["generation"]
        assert isinstance(generation, int) and generation > 0
        publisher._publish_once(renew_after_generation=generation)
        assert len(captures) == 2 and len(writes) == 1
        assert all(before != after for before, after in writes)
        assert len(calls) == 1 and publisher._snapshot is initial_snapshot
        assert publisher.last_error == "native_policy_authority_capture_changed"
        assert not publisher._initial_database_capture_retry_used
        assert publisher._failure_count == 1
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > publisher._monotonic_clock()
