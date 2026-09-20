"""A refused V3 ACK may schedule one fresh attempt; it never becomes readiness."""

from __future__ import annotations

import socket
import sqlite3
import time
from contextlib import closing

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_publisher as publisher_module
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_policy_snapshot_capture_retry import _write_startup_status
from tests.test_native_policy_snapshot_reservation_capture import _make_publisher
from tests.test_native_policy_source_selection import _insert_untrusted_row


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("network is prohibited in this local publication control")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket.socket, "sendto", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)


def _interrupt_postack(publisher, monkeypatch, *, mutation=None, repeated=False):
    original = publisher_module.compiled_v3_compatible_policy
    captures = []

    def compile_current(*args, **kwargs):
        result = original(*args, **kwargs)
        captures.append(result[1])
        if len(captures) == 1 or repeated:
            if mutation is None:
                _write_startup_status(publisher.store, len(captures), now=publisher._wall_clock())
            else:
                mutation()
        return result

    monkeypatch.setattr(publisher_module, "compiled_v3_compatible_policy", compile_current)
    return captures


def test_refused_ack_requires_complete_new_capture_and_client_ack(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        captures = _interrupt_postack(publisher, monkeypatch)
        context = publisher._publication_context
        contexts = []

        def fresh_context(**kwargs):
            result = context(**kwargs)
            contexts.append(result[5] if result is not None else None)
            return result

        monkeypatch.setattr(publisher, "_publication_context", fresh_context)
        publisher._publish_once()
        assert len(calls) == 1 and len(contexts) == 2 and len(captures) == 1
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert publisher.last_error == "native_policy_authority_changed_during_publish"
        assert publisher._failure_count == 1
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic <= publisher._monotonic_clock()
        assert publisher._snapshot is None
        publisher._publish_once()
        assert len(calls) == 2 and len(contexts) == 4 and len(captures) == 2
        assert publisher.is_ready() and publisher.current_snapshot_binding() is not None
        assert publisher._snapshot == calls[-1]
        assert publisher.last_error is None and publisher._failure_count == 0


def test_existing_worker_performs_fresh_retry_after_one_status_race(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        captures = _interrupt_postack(publisher, monkeypatch)
        publisher.start()
        assert publisher.wait_until_ready(time.monotonic() + _PUBLISH_TIMEOUT_SECONDS), publisher.last_error
        assert len(calls) == 2 and len(captures) == 2
        assert publisher.current_snapshot_binding() is not None
        assert publisher._initial_database_capture_retry_used


def test_allowance_is_not_reset_by_workspace_or_resident_style_requests(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        captures = _interrupt_postack(publisher, monkeypatch, repeated=True)
        monkeypatch.setattr(publisher, "_monotonic_clock", lambda: 100.0)
        publisher._publish_once()
        assert publisher._retry_not_before_monotonic == 100.0
        publisher._publish_once()
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > 100.0 and publisher._failure_count == 2
        assert publisher.register_workspace(tmp_path / "workspace")
        publisher._publish_once()
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > 100.0 and publisher._failure_count == 1
        publisher.request_publish()
        publisher._publish_once()
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > 100.0 and publisher._failure_count == 1
        assert len(calls) == len(captures) == 4
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None


def test_new_workspace_admission_can_retry_after_prior_home_snapshot(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        publisher._publish_once()
        assert publisher.is_ready()
        previous = publisher._snapshot
        assert publisher.register_workspace(tmp_path / "workspace")
        _interrupt_postack(publisher, monkeypatch)
        publisher._publish_once()
        assert publisher._snapshot is previous
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic <= publisher._monotonic_clock()
        publisher._publish_once()
        assert publisher.is_ready() and len(calls) == 3


def test_ready_renewal_failure_preserves_normal_backoff(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        publisher._publish_once()
        assert publisher.is_ready()
        _interrupt_postack(publisher, monkeypatch)
        monkeypatch.setattr(publisher, "_monotonic_clock", lambda: 100.0)
        publisher._publish_once(renew_after_generation=calls[-1]["generation"])
        assert not publisher.is_ready()
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > 100.0
        assert not publisher._initial_database_capture_retry_used


@pytest.mark.parametrize("mutation", ["configuration", "policy-before-capture"])
def test_observed_policy_change_does_not_consume_initial_allowance(tmp_path, monkeypatch, mutation):
    store = GuardStore(tmp_path / "guard-home")
    calls = []

    def change_during_push(snapshot):
        if mutation == "configuration":
            (store.guard_home / "config.toml").write_text('mode="enforce"\ndefault_action="block"\n')
        else:
            _insert_untrusted_row(store)
        return "accepted"

    with closing(_make_publisher(store, calls, during=change_during_push, scoped=False)) as publisher:
        monkeypatch.setattr(publisher, "_monotonic_clock", lambda: 100.0)
        publisher._publish_once()
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert publisher._retry_not_before_monotonic is not None
        assert publisher._retry_not_before_monotonic > 100.0
        assert not publisher._initial_database_capture_retry_used
        assert len(calls) == 1


def test_policy_change_after_capture_cannot_reuse_old_ack(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        _interrupt_postack(publisher, monkeypatch, mutation=lambda: _insert_untrusted_row(store))
        publisher._publish_once()
        assert publisher.last_error == "native_policy_authority_changed_during_publish"
        assert not publisher.is_ready() and len(calls) == 1
        publisher._publish_once()
        assert publisher.last_error == "native_policy_authority_local_unavailable"
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert len(calls) == 1


def test_direct_external_sql_aba_discards_old_ack_before_fresh_attempt(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []

    def aba():
        with sqlite3.connect(store.path) as connection:
            connection.execute(
                "insert into sync_state (state_key,payload_json,updated_at) values (?,?,?)",
                ("policy_bundle", "{}", "2026-09-19T00:00:00Z"),
            )
        with sqlite3.connect(store.path) as connection:
            connection.execute("delete from sync_state where state_key = ?", ("policy_bundle",))

    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        _interrupt_postack(publisher, monkeypatch, mutation=aba)
        publisher._publish_once()
        assert publisher.last_error == "native_policy_authority_changed_during_publish"
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert len(calls) == 1
        publisher._publish_once()
        assert publisher.is_ready() and len(calls) == 2


@pytest.mark.parametrize("mutation", ["request", "close"])
def test_late_retry_scheduling_cannot_escape_failed_epoch(tmp_path, monkeypatch, mutation):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        _interrupt_postack(publisher, monkeypatch)
        record = publisher_module.record_publication_error
        retained = []

        def after_record(*args, **kwargs):
            record(*args, **kwargs)
            if mutation == "request":
                publisher.request_publish()
            else:
                publisher.close()
            retained.append((publisher._last_error, publisher._failure_count, publisher._retry_not_before_monotonic))

        monkeypatch.setattr(publisher_module, "record_publication_error", after_record)
        publisher._publish_once()
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert not publisher._initial_database_capture_retry_used
        assert (publisher._last_error, publisher._failure_count, publisher._retry_not_before_monotonic) == retained[0]


def test_expired_waiter_does_not_gain_time_from_retry_opportunity(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        _interrupt_postack(publisher, monkeypatch)
        monkeypatch.setattr(publisher, "_monotonic_clock", lambda: 100.0)
        publisher._publish_once()
        assert not publisher.wait_until_ready(99.0)
        assert len(calls) == 1 and not publisher.is_ready()
