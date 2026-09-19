"""HGP-153: activation failures leave recoverable durable state."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_activation_failure import (
    STORAGE_FAILURE,
    classify_policy_activation_failure,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_activation_atomicity import (
    _activate_bundle,
    _signed_bundle,
    _sorted_policy_rows,
)


def test_json_encoding_failure_rejects_before_commit(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    prior = _signed_bundle(rollout_state="enforcing")
    assert _activate_bundle(store, prior, "2026-07-18T00:00:00Z") is not None
    rows_before = _sorted_policy_rows(store)
    last_good = store.get_sync_payload("policy_bundle_last_good")

    class _Unencodable:
        def __str__(self) -> str:
            raise TypeError("unencodable")

    result = store.apply_policy_bundle_authority(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:unencodable",
                reason="must not apply",
                source="policy-bundle",
            )
        ],
        "2026-07-18T01:00:00Z",
        policy_bundle={"bundleVersion": "bad", "unencodable": _Unencodable()},
        policy_bundle_keyring={"keys": []},
        cloud_exceptions=[],
        policy_bundle_ack={"status": "synced", "bundleVersion": "bad"},
        policy_bundle_checkpoint={},
        update_last_good=True,
        remote_write_authorized=True,
    )
    assert result is None
    assert _sorted_policy_rows(store) == rows_before
    assert store.get_sync_payload("policy_bundle_last_good") == last_good


def test_sqlite_locked_and_disk_full_do_not_claim_application(tmp_path: Path) -> None:
    locked = classify_policy_activation_failure(sqlite3.OperationalError("database is locked"))
    disk = classify_policy_activation_failure(sqlite3.OperationalError("database or disk is full"))
    transport = classify_policy_activation_failure(TimeoutError("connect timed out"))
    encode = classify_policy_activation_failure(json.JSONDecodeError("bad", "x", 0))
    assert locked["applied"] is False
    assert locked["failure_kind"] == STORAGE_FAILURE
    assert locked["reason"] == "policy_activation_sqlite_locked"
    assert disk["reason"] == "policy_activation_disk_full"
    assert transport["failure_kind"] == "transport"
    assert encode["applied"] is False
    assert encode["retryable"] is False


def test_mid_transaction_failure_is_idempotent_on_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = _signed_bundle(rollout_state="enforcing", bundle_version="policy-2026-07-18.1")
    assert _activate_bundle(store, first, "2026-07-18T00:00:00Z") is not None
    rows_before = _sorted_policy_rows(store)
    original_replace = store._replace_remote_policy_rows_locked  # pyright: ignore[reportPrivateUsage]

    def fail_after_rows(connection: sqlite3.Connection, rows: object, **kwargs: object) -> None:
        original_replace(connection, rows, **kwargs)
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", fail_after_rows)
    second = _signed_bundle(rollout_state="enforcing", bundle_version="policy-2026-07-18.2")
    with pytest.raises(sqlite3.OperationalError, match="disk is full"):
        _activate_bundle(store, second, "2026-07-18T01:00:00Z")
    assert _sorted_policy_rows(store) == rows_before
    monkeypatch.undo()
    assert _activate_bundle(store, second, "2026-07-18T01:00:00Z") is not None
    assert store.get_sync_payload("policy_bundle")["bundleVersion"] == "policy-2026-07-18.2"


def test_activation_boundary_classifies_transaction_failure_after_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.policy_activation_failure import activation_status_from_store
    from codex_plugin_scanner.guard.policy_bundle_activation import activate_with_reason, persist_activation_rejection

    store = GuardStore(tmp_path / "guard-home")
    prior = _signed_bundle(rollout_state="enforcing", bundle_version="revision-1")
    assert _activate_bundle(store, prior, "2026-07-18T00:00:00Z") is not None
    rows_before = _sorted_policy_rows(store)
    prior_ack = store.get_sync_payload("policy_bundle_ack")
    original_replace = store._replace_remote_policy_rows_locked

    def disk_full(connection: sqlite3.Connection, rows: object, **kwargs: object) -> None:
        original_replace(connection, rows, **kwargs)
        raise sqlite3.OperationalError("database or disk is full: private-canary")

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", disk_full)
    candidate = _signed_bundle(rollout_state="enforcing", bundle_version="revision-2")

    def activate(*args: object, **kwargs: object) -> dict[str, object] | None:
        return _activate_bundle(store, candidate, "2026-07-18T01:00:00Z")

    result, reason = activate_with_reason(activate)
    assert result is None
    assert reason == "policy_activation_disk_full"
    assert _sorted_policy_rows(store) == rows_before
    assert store.get_sync_payload("policy_bundle") == prior
    assert store.get_sync_payload("policy_bundle_ack") == prior_ack
    persist_activation_rejection(store, {"reason": reason}, "2026-07-18T01:00:00Z")
    status = activation_status_from_store(store)
    assert status["storage_failure"] is True
    assert status["transport_failure"] is False
    assert status["applied"] is False
    assert "private-canary" not in json.dumps(status)
    monkeypatch.undo()
    assert _activate_bundle(store, candidate, "2026-07-18T01:00:00Z") is not None
    assert activation_status_from_store(store)["reason"] is None


def test_unwritable_failure_record_raises_a_safe_storage_error() -> None:
    from codex_plugin_scanner.guard.policy_activation_failure import PolicyActivationPersistenceError
    from codex_plugin_scanner.guard.policy_bundle_activation import persist_activation_rejection

    class LockedStore:
        def set_sync_payload(self, *args: object) -> None:
            raise sqlite3.OperationalError("database is locked: private-canary")

        def add_event(self, *args: object) -> None:
            raise AssertionError("must not report a persisted rejection")

    with pytest.raises(PolicyActivationPersistenceError, match=r"^policy_activation_sqlite_locked$") as caught:
        persist_activation_rejection(LockedStore(), {"reason": "policy_activation_disk_full"}, "2026-07-18T00:00:00Z")
    assert caught.value.status["applied"] is False
    assert caught.value.status["failure_kind"] == "storage"


def test_publication_rejection_remains_available_to_the_callers_existing_handler() -> None:
    from codex_plugin_scanner.guard.policy_bundle_activation import activate_with_reason

    def rejected_publication(**kwargs: object) -> None:
        raise ValueError("publication rejected")

    with pytest.raises(ValueError, match="publication rejected"):
        activate_with_reason(rejected_publication)


def test_approval_gate_rejection_is_not_reclassified_as_a_retryable_storage_error() -> None:
    from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
    from codex_plugin_scanner.guard.policy_bundle_activation import activate_with_reason

    denied = ApprovalGateError("approval_gate_required", "Approval is required.")

    def activate(**kwargs: object) -> None:
        raise denied

    with pytest.raises(ApprovalGateError) as caught:
        activate_with_reason(activate)
    assert caught.value is denied
    assert caught.value.code == "approval_gate_required"


def test_unreadable_status_and_stale_acknowledgement_never_claim_application(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.policy_activation_failure import activation_status_from_store

    class UnreadableStore:
        def get_sync_payload(self, key: str) -> None:
            raise sqlite3.OperationalError("database is locked: private-canary")

    status = activation_status_from_store(UnreadableStore())
    assert status["reason"] == "policy_activation_sqlite_locked"
    assert status["applied"] is False
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("policy_bundle_ack", {"status": "applied"}, "2026-07-18T00:00:00Z")
    assert activation_status_from_store(store)["applied"] is False


def test_sqlite_codes_and_os_disk_failure_keep_the_storage_classification() -> None:
    import errno

    locked = sqlite3.OperationalError("private-canary")
    locked.sqlite_errorcode = getattr(sqlite3, "SQLITE_LOCKED", 6)
    assert classify_policy_activation_failure(locked)["reason"] == "policy_activation_sqlite_locked"
    full = OSError(errno.ENOSPC, "private-canary")
    assert classify_policy_activation_failure(full)["reason"] == "policy_activation_disk_full"
    assert classify_policy_activation_failure(RuntimeError("private-canary"))["failure_kind"] == "activation"
