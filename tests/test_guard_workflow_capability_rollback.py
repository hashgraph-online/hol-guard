"""Rollback and crash-boundary tests for workflow-capability authority."""

# pyright: reportAny=false, reportMissingParameterType=false, reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false
# pyright: reportUnknownParameterType=false, reportUnusedCallResult=false, reportUnusedFunction=false
# pyright: reportUnusedParameter=false

from __future__ import annotations

import json
import sqlite3

import pytest

from codex_plugin_scanner.guard import store_workflow_capabilities as workflow_capability_store_mixin
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    WorkflowCapabilityError,
    sign_workflow_capability,
)
from codex_plugin_scanner.guard.workflow_capability_transitions import (
    authority_transition_sha256,
    decode_signed_authority_transition,
)
from tests.test_guard_workflow_capabilities import (
    _KEY,
    _KEY_ID,
    _claim,
    _claim_capability,
    _issue,
    _now,
    _store,
)


@pytest.fixture(autouse=True)
def _fixed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda self, *, create: (_KEY, _KEY_ID),
    )
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", _now)


def _state_row(connection: sqlite3.Connection, capability_id: str) -> tuple[object, ...]:
    row = connection.execute(
        """
        select signed_state_json, key_id, revision, use_high_water, observed_at, revocation_id
        from guard_workflow_capability_authority_state where capability_id = ?
        """,
        (capability_id,),
    ).fetchone()
    assert row is not None
    return tuple(row)


def _restore_state(connection: sqlite3.Connection, capability_id: str, state: tuple[object, ...]) -> None:
    connection.execute(
        """
        update guard_workflow_capability_authority_state
        set signed_state_json = ?, key_id = ?, revision = ?, use_high_water = ?,
            observed_at = ?, revocation_id = ? where capability_id = ?
        """,
        (*state, capability_id),
    )


def test_receipt_counter_and_signed_state_rollback_fails_after_reopen(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-combined-rollback")
    _issue(store, claim)
    with sqlite3.connect(store.path) as connection:
        prior_state = _state_row(connection, claim.capability_id)
    _claim_capability(store, claim, invocation_id="invocation-first")
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger trg_guard_workflow_receipt_immutable_delete")
        connection.execute("delete from guard_workflow_capability_receipts")
        connection.execute("update guard_workflow_capabilities set used_count = 0")
        _restore_state(connection, claim.capability_id, prior_state)

    reopened = _store(tmp_path)
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_transition_projection_invalid"):
        _claim_capability(reopened, claim, invocation_id="invocation-second")
    assert len(reopened.list_events(event_name="workflow_capability.claimed")) == 1


def test_revocation_evidence_and_signed_state_rollback_fails_after_reopen(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-revocation-rollback")
    _issue(store, claim)
    with sqlite3.connect(store.path) as connection:
        prior_state = _state_row(connection, claim.capability_id)
    assert store.revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger trg_guard_workflow_revocation_immutable_delete")
        connection.execute("delete from guard_workflow_capability_revocations")
        connection.execute("update guard_workflow_capabilities set revoked_at = null, revocation_code = null")
        _restore_state(connection, claim.capability_id, prior_state)

    reopened = _store(tmp_path)
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_transition_projection_invalid"):
        _claim_capability(reopened, claim, invocation_id="invocation-after-revoke")


def test_whole_authority_history_rollback_fails_external_head_after_reopen(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-whole-history-rollback")
    _issue(store, claim)
    with sqlite3.connect(store.path) as connection:
        prior_state = _state_row(connection, claim.capability_id)
    _claim_capability(store, claim, invocation_id="invocation-first")
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger trg_guard_workflow_transition_immutable_delete")
        connection.execute("drop trigger trg_guard_workflow_receipt_immutable_delete")
        connection.execute("drop trigger trg_guard_workflow_event_preserve_link")
        connection.execute("delete from guard_workflow_capability_authority_transitions where sequence = 2")
        connection.execute("delete from guard_workflow_capability_receipts")
        connection.execute("delete from guard_events where event_name = 'workflow_capability.claimed'")
        connection.execute("update guard_workflow_capabilities set used_count = 0")
        _restore_state(connection, claim.capability_id, prior_state)

    reopened = _store(tmp_path)
    with pytest.raises(WorkflowCapabilityError, match="capability_control_rollback_detected"):
        _claim_capability(reopened, claim, invocation_id="invocation-second")


@pytest.mark.parametrize("event_name", ["workflow_capability.issued", "workflow_capability.revoked"])
def test_issued_and_revoked_event_rewrite_fails_lookup(tmp_path, event_name: str) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id=f"wc-event-rewrite-{event_name.rsplit('.', 1)[-1]}")
    _issue(store, claim)
    if event_name.endswith("revoked"):
        assert store.revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update guard_events set payload_json = '{}' where event_name = ?",
            (event_name,),
        )
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_transition_event_invalid"):
        store.lookup_workflow_capability(claim.capability_id)


@pytest.mark.parametrize("event_name", ["workflow_capability.issued", "workflow_capability.revoked"])
def test_issued_and_revoked_event_deletion_fails_lookup_after_reopen(tmp_path, event_name: str) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id=f"wc-event-delete-{event_name.rsplit('.', 1)[-1]}")
    _issue(store, claim)
    if event_name.endswith("revoked"):
        assert store.revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger trg_guard_workflow_event_preserve_link")
        connection.execute("delete from guard_events where event_name = ?", (event_name,))
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_transition_event_invalid"):
        _store(tmp_path).lookup_workflow_capability(claim.capability_id)


def test_pending_control_only_recovers_forward_to_matching_database_head(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-pending-forward")
    _issue(store, claim)
    _claim_capability(store, claim, invocation_id="invocation-first")
    encoded = store._load_workflow_capability_control()
    assert encoded is not None
    control = json.loads(encoded)
    with sqlite3.connect(store.path) as connection:
        first_encoded = connection.execute(
            "select signed_transition_json from guard_workflow_capability_authority_transitions where sequence = 1"
        ).fetchone()[0]
    control["committed_sequence"] = 1
    control["committed_head_sha256"] = authority_transition_sha256(decode_signed_authority_transition(first_encoded))
    control["pending_sequence"] = 2
    control["pending_head_sha256"] = json.loads(encoded)["committed_head_sha256"]
    assert store._store_workflow_capability_control(json.dumps(control, sort_keys=True, separators=(",", ":")))

    assert store.lookup_workflow_capability(claim.capability_id) is not None
    recovered_encoded = store._load_workflow_capability_control()
    assert recovered_encoded is not None
    recovered = json.loads(recovered_encoded)
    assert recovered["committed_sequence"] == 2
    assert recovered["pending_sequence"] is None


def test_pending_control_never_clears_backward_to_old_database(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-pending-old-db")
    _issue(store, claim)
    encoded = store._load_workflow_capability_control()
    assert encoded is not None
    control = json.loads(encoded)
    control["pending_sequence"] = 2
    control["pending_head_sha256"] = "f" * 64
    assert store._store_workflow_capability_control(json.dumps(control, sort_keys=True, separators=(",", ":")))
    with pytest.raises(WorkflowCapabilityError, match="capability_control_pending_unresolved"):
        store.lookup_workflow_capability(claim.capability_id)


def test_post_commit_finalize_failure_recovers_only_from_matching_database(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-finalize-recovery")
    original_store = store._store_workflow_capability_control
    calls = 0

    def fail_finalize(encoded: str) -> bool:
        nonlocal calls
        calls += 1
        if calls == 3:
            return False
        return original_store(encoded)

    monkeypatch.setattr(store, "_store_workflow_capability_control", fail_finalize)
    with pytest.raises(WorkflowCapabilityError, match="capability_control_unavailable"):
        _issue(store, claim)
    assert calls == 3
    assert _store(tmp_path).lookup_workflow_capability(claim.capability_id) is not None


def test_pre_commit_failure_leaves_forward_only_pending_control_blocked(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-precommit-pending")

    def fail_transition(*args: object, **kwargs: object) -> None:
        raise RuntimeError("forced_transition_failure")

    monkeypatch.setattr(workflow_capability_store_mixin, "append_authority_transition", fail_transition)
    with pytest.raises(RuntimeError, match="forced_transition_failure"):
        _issue(store, claim)
    with pytest.raises(WorkflowCapabilityError, match="capability_control_pending_unresolved"):
        store.lookup_workflow_capability(claim.capability_id)


def test_missing_external_control_never_blesses_nonempty_sqlite(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-control-missing")
    _issue(store, claim)
    monkeypatch.setattr(GuardStore, "_load_workflow_capability_control", lambda self: None)
    with pytest.raises(WorkflowCapabilityError, match="capability_control_bootstrap_refused"):
        store.lookup_workflow_capability(claim.capability_id)


def test_missing_control_refuses_nonempty_legacy_sqlite_without_transition_history(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-legacy-bootstrap")
    signed = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            insert into guard_workflow_capabilities
              (capability_id, approval_provenance_id, nonce, signed_claim_json, key_id,
               issued_at, not_before, expires_at, max_uses, used_count, revoked_at, revocation_code)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, null, null)
            """,
            (
                claim.capability_id,
                claim.approval_provenance_id,
                claim.nonce,
                json.dumps(signed.to_dict(), sort_keys=True, separators=(",", ":")),
                _KEY_ID,
                claim.issued_at,
                claim.not_before,
                claim.expires_at,
                claim.max_uses,
            ),
        )
    with pytest.raises(WorkflowCapabilityError, match="capability_control_bootstrap_refused"):
        store.lookup_workflow_capability(claim.capability_id)


def test_unavailable_external_control_blocks_first_issue(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-control-unavailable")
    monkeypatch.setattr(GuardStore, "_load_workflow_capability_control", lambda self: None)
    monkeypatch.setattr(GuardStore, "_store_workflow_capability_control", lambda self, encoded: False)
    with pytest.raises(WorkflowCapabilityError, match="capability_control_unavailable"):
        _issue(store, claim)
