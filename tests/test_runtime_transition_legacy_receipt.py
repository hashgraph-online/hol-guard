"""Actual legacy-shaped writer/SQLite correlation; receipts are unit fixtures."""

import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from codex_plugin_scanner.guard import runtime_transition_legacy_receipt as lookup
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_existing_installation_correlation_key,
)
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_decision_receipt import _receipt


def persist(store, writer, payload, action, *, variant="a"):
    receipt = _receipt(
        harness="codex",
        event_name="PreToolUse",
        policy_action=action,
        decision="allow" if action == "allow" else "deny",
        request_digest=variant * 64,
    )
    assert writer.submit_native_decision_receipt(receipt=receipt)
    assert writer.submit_command_activity(
        harness="codex",
        event="PreToolUse",
        payload=payload,
        succeeded=True,
        policy_action=action,
        receipt_id=receipt["decision_id"],
    )
    return receipt


@pytest.fixture
def legacy(tmp_path):
    store = GuardStore(tmp_path / "guard")
    writer = RuntimeHookEvidenceWriter(store=store)
    since = datetime.now(timezone.utc)
    payload = {"tool_call_id": uuid.uuid4().hex, "tool_name": "exec_command", "tool_input": {"cmd": "pwd"}}
    key = load_existing_installation_correlation_key(store.guard_home)
    assert key is not None
    handle = derive_proven_request_correlation(harness="codex", event="PreToolUse", payload=payload, key=key)
    assert handle is not None
    try:
        yield store, writer, payload, handle, since
    finally:
        assert writer.stop(timeout_seconds=2)


def read(store, handle, since):
    return lookup.read_legacy_codex_probe_receipt(
        store, correlation=handle, since=since, deadline_monotonic=time.monotonic() + 2
    )


@pytest.mark.parametrize("expired", [False, True])
def test_connection_timeout_preserves_parent_deadline_and_first_cause(legacy, monkeypatch, expired):
    _, _, _, handle, since = legacy
    now = [10.0]
    failure = TimeoutError("connection setup storage deadline")

    class FailedConnectionStore:
        @contextmanager
        def _connect(self):
            now[0] = 21.0 if expired else 15.0
            raise failure
            yield  # pragma: no cover - retain context-manager entry semantics

    with monkeypatch.context() as patch:
        patch.setattr(lookup.time, "monotonic", lambda: now[0])
        with pytest.raises(TransitionError if expired else TimeoutError) as caught:
            lookup.read_legacy_codex_probe_receipt(
                FailedConnectionStore(),
                correlation=handle,
                since=since,
                deadline_monotonic=20.0,
            )
    if expired:
        assert "admission_deadline_expired" in str(caught.value)
        assert caught.value.__cause__ is failure
    else:
        assert caught.value is failure


@pytest.mark.parametrize("action", ["allow", "block"])
def test_fresh_exact_receipt_is_found_in_actual_writer_rows(legacy, action):
    store, writer, payload, handle, since = legacy
    receipt = persist(store, writer, payload, action)
    assert writer.stop(timeout_seconds=2)
    assert read(store, handle, since) == receipt


def test_unrelated_request_and_stale_boundary_do_not_match(legacy):
    store, writer, payload, handle, since = legacy
    persist(store, writer, {**payload, "tool_call_id": uuid.uuid4().hex}, "allow")
    assert writer.stop(timeout_seconds=2)
    assert read(store, handle, since) is None
    assert read(store, handle, datetime.now(timezone.utc) + timedelta(seconds=1)) is None


@pytest.mark.parametrize("fault", ["receipt_stale", "receipt_changed", "prompted", "activity_policy"])
def test_matching_but_invalid_evidence_is_refused(legacy, fault):
    store, writer, payload, handle, since = legacy
    persist(store, writer, payload, "allow")
    assert writer.stop(timeout_seconds=2)
    with store._connect() as connection:
        if fault == "receipt_stale":
            connection.execute(
                "update native_hook_decision_receipts set recorded_at = ?",
                ((since - timedelta(seconds=1)).isoformat(),),
            )
        elif fault == "receipt_changed":
            connection.execute("update native_hook_decision_receipts set runtime_identity = ?", ("0" * 64,))
        elif fault == "prompted":
            connection.execute("update command_activity set prompted = 1")
        else:
            connection.execute("update command_activity set policy_action = 'warn'")
    with pytest.raises(TransitionError, match="legacy_probe_receipt_invalid"):
        read(store, handle, since)


def test_multiple_denied_receipts_for_same_nonce_are_ambiguous(legacy):
    store, writer, payload, handle, since = legacy
    persist(store, writer, payload, "block", variant="a")
    persist(store, writer, payload, "block", variant="b")
    assert writer.stop(timeout_seconds=2)
    with pytest.raises(TransitionError, match="legacy_probe_receipt_ambiguous"):
        read(store, handle, since)


def test_busy_recent_window_is_capped_instead_of_selecting_newest_row(legacy):
    store, writer, payload, handle, since = legacy
    for index in range(lookup.MAX_LEGACY_PROBE_ROWS + 1):
        persist(store, writer, payload if index == 0 else {**payload, "tool_call_id": uuid.uuid4().hex}, "allow")
    assert writer.stop(timeout_seconds=10)
    assert writer.stats()["durable_pending"] == 0, writer.stats()
    with pytest.raises(TransitionError, match="legacy_probe_receipt_capacity"):
        read(store, handle, since)


def test_expired_deadline_never_opens_store(legacy, monkeypatch):
    store, _, _, handle, since = legacy

    def forbidden():
        raise AssertionError("expired probe opened SQLite")

    monkeypatch.setattr(store, "_connect", forbidden)
    with pytest.raises(TransitionError, match="admission_deadline_expired"):
        lookup.read_legacy_codex_probe_receipt(
            store, correlation=handle, since=since, deadline_monotonic=time.monotonic() - 1
        )


def test_short_lock_wait_does_not_replace_the_admission_operation_deadline(legacy, monkeypatch):
    from codex_plugin_scanner.guard.sqlite_tuning import (
        sqlite_connect_timeout_seconds,
        sqlite_operation_deadline_monotonic,
    )

    _, _, _, handle, since = legacy
    now = [10.0]
    observed = []
    stop = RuntimeError("stop after checking connection budget")

    class BudgetStore:
        @contextmanager
        def _connect(self):
            observed.append((sqlite_connect_timeout_seconds(), sqlite_operation_deadline_monotonic()))
            now[0] = 10.2  # Slow setup remains inside the original 20-second deadline.
            observed.append((sqlite_connect_timeout_seconds(), sqlite_operation_deadline_monotonic()))
            raise stop
            yield  # pragma: no cover - context manager shape

    monkeypatch.setattr(lookup.time, "monotonic", lambda: now[0])
    with pytest.raises(RuntimeError, match="stop after checking"):
        lookup.read_legacy_codex_probe_receipt(BudgetStore(), correlation=handle, since=since, deadline_monotonic=20.0)
    assert observed == [(0.1, 20.0), (0.1, 20.0)]
