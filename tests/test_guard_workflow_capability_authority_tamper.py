"""Adversarial persistence tests for workflow-capability authority state."""

# pyright: reportAny=false, reportMissingParameterType=false, reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false
# pyright: reportUnknownParameterType=false, reportUnusedCallResult=false, reportUnusedFunction=false

from __future__ import annotations

import json
import sqlite3
from typing import cast

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityBinding,
    WorkflowCapabilityError,
    sign_workflow_capability,
    verify_workflow_capability,
    verify_workflow_capability_receipt,
    verify_workflow_capability_signature,
)
from codex_plugin_scanner.guard.workflow_capability_authority_state import (
    SignedAuthorityState,
    SignedRevocation,
    decode_signed_authority_state,
    decode_signed_revocation,
    verify_authority_state,
    verify_revocation,
)
from codex_plugin_scanner.guard.workflow_capability_transitions import (
    SignedAuthorityTransition,
    decode_signed_authority_transition,
    verify_authority_transition,
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


def test_expected_binding_requires_exact_contract_type() -> None:
    claim = _claim(capability_id="wc-exact-binding")
    signed = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)
    with pytest.raises(WorkflowCapabilityError, match="invalid_expected_capability_binding"):
        verify_workflow_capability(
            signed,
            key=_KEY,
            key_id=_KEY_ID,
            now=_now(),
            expected_binding=cast(WorkflowCapabilityBinding, object()),
        )


def test_uninitialized_signed_claim_fails_closed() -> None:
    signed = object.__new__(SignedWorkflowCapability)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_capability"):
        verify_workflow_capability_signature(signed, key=_KEY, key_id=_KEY_ID)


def test_uninitialized_signed_receipt_fails_closed() -> None:
    signed = object.__new__(SignedWorkflowCapabilityReceipt)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_receipt"):
        verify_workflow_capability_receipt(signed, key=_KEY, key_id=_KEY_ID)


def test_uninitialized_signed_authority_state_fails_closed() -> None:
    signed = object.__new__(SignedAuthorityState)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_authority_state"):
        verify_authority_state(signed, key=_KEY, key_id=_KEY_ID)


def test_uninitialized_signed_revocation_fails_closed() -> None:
    signed = object.__new__(SignedRevocation)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_revocation"):
        verify_revocation(signed, key=_KEY, key_id=_KEY_ID)


def test_uninitialized_signed_authority_transition_fails_closed() -> None:
    signed = object.__new__(SignedAuthorityTransition)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_authority_transition"):
        verify_authority_transition(signed, key=_KEY, key_id=_KEY_ID)


def _cyclic_value() -> list[object]:
    value: list[object] = []
    value.append(value)
    return value


@pytest.mark.parametrize("invalid_value", [object(), _cyclic_value()])
def test_malformed_present_claim_value_fails_closed(invalid_value: object) -> None:
    signed = sign_workflow_capability(_claim(capability_id="wc-malformed-claim-value"), key=_KEY, key_id=_KEY_ID)
    object.__setattr__(signed.claim, "capability_id", invalid_value)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_capability"):
        verify_workflow_capability_signature(signed, key=_KEY, key_id=_KEY_ID)


@pytest.mark.parametrize("invalid_value", [object(), _cyclic_value()])
def test_malformed_present_receipt_value_fails_closed(tmp_path, invalid_value: object) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-malformed-receipt-value")
    _issue(store, claim)
    signed = _claim_capability(store, claim, invocation_id="invocation-malformed-receipt-value")
    object.__setattr__(signed.receipt, "capability_id", invalid_value)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_receipt"):
        verify_workflow_capability_receipt(signed, key=_KEY, key_id=_KEY_ID)


@pytest.mark.parametrize("invalid_value", [object(), _cyclic_value()])
def test_malformed_present_authority_state_value_fails_closed(tmp_path, invalid_value: object) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-malformed-state-value")
    _issue(store, claim)
    with sqlite3.connect(store.path) as connection:
        encoded = connection.execute(
            "select signed_state_json from guard_workflow_capability_authority_state where capability_id = ?",
            (claim.capability_id,),
        ).fetchone()[0]
    signed = decode_signed_authority_state(encoded)
    object.__setattr__(signed.state, "capability_id", invalid_value)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_authority_state"):
        verify_authority_state(signed, key=_KEY, key_id=_KEY_ID)


@pytest.mark.parametrize("invalid_value", [object(), _cyclic_value()])
def test_malformed_present_revocation_value_fails_closed(tmp_path, invalid_value: object) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-malformed-revocation-value")
    _issue(store, claim)
    assert store.revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")
    with sqlite3.connect(store.path) as connection:
        encoded = connection.execute(
            "select signed_revocation_json from guard_workflow_capability_revocations where capability_id = ?",
            (claim.capability_id,),
        ).fetchone()[0]
    signed = decode_signed_revocation(encoded)
    object.__setattr__(signed.revocation, "capability_id", invalid_value)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_revocation"):
        verify_revocation(signed, key=_KEY, key_id=_KEY_ID)


@pytest.mark.parametrize("invalid_value", [object(), _cyclic_value()])
def test_malformed_present_transition_value_fails_closed(tmp_path, invalid_value: object) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-malformed-transition-value")
    _issue(store, claim)
    with sqlite3.connect(store.path) as connection:
        encoded = connection.execute(
            "select signed_transition_json from guard_workflow_capability_authority_transitions where sequence = 1"
        ).fetchone()[0]
    signed = decode_signed_authority_transition(encoded)
    object.__setattr__(signed.transition, "capability_id", invalid_value)
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_authority_transition"):
        verify_authority_transition(signed, key=_KEY, key_id=_KEY_ID)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_subject_id", "subject.other"),
        ("expected_task_id", "task.other"),
        ("expected_issuer_id", "issuer.other"),
        ("expected_approval_provenance_id", "provenance-other"),
    ],
)
def test_claim_rejects_every_expected_authority_identity(tmp_path, field: str, value: str) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id=f"wc-identity-{field}")
    _issue(store, claim)
    expected = {
        "expected_subject_id": claim.subject_id,
        "expected_task_id": claim.task_id,
        "expected_issuer_id": claim.issuer_id,
        "expected_approval_provenance_id": claim.approval_provenance_id,
    }
    expected[field] = value
    with pytest.raises(WorkflowCapabilityError, match="capability_claimant_context_mismatch"):
        store.claim_workflow_capability(
            claim.capability_id,
            invocation_id="invocation-identity",
            expected_binding=claim.binding,
            **expected,
        )
    _claim_capability(store, claim, invocation_id="invocation-identity")


def test_legacy_use_counter_reset_cannot_revive_exhausted_capability(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-use-reset")
    _issue(store, claim)
    _claim_capability(store, claim, invocation_id="invocation-first")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update guard_workflow_capabilities set used_count = 0 where capability_id = ?",
            (claim.capability_id,),
        )
    with pytest.raises(WorkflowCapabilityError, match="capability_use_high_water_invalid"):
        _claim_capability(store, claim, invocation_id="invocation-revived")


def test_legacy_revocation_reset_cannot_revive_revoked_capability(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-revocation-reset")
    _issue(store, claim)
    assert store.revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update guard_workflow_capabilities set revoked_at = null, revocation_code = null where capability_id = ?",
            (claim.capability_id,),
        )
    with pytest.raises(WorkflowCapabilityError, match="capability_revocation_state_invalid"):
        _claim_capability(store, claim, invocation_id="invocation-revived")


def test_authenticated_state_tamper_is_detected(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-state-tamper")
    _issue(store, claim)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update guard_workflow_capability_authority_state set revision = revision + 1 where capability_id = ?",
            (claim.capability_id,),
        )
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_state_binding_invalid"):
        _claim_capability(store, claim, invocation_id="invocation-state-tamper")


def test_prior_valid_state_cannot_roll_back_signed_receipt_history(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-state-rollback", max_uses=2)
    _issue(store, claim)
    with sqlite3.connect(store.path) as connection:
        prior = connection.execute(
            "select * from guard_workflow_capability_authority_state where capability_id = ?",
            (claim.capability_id,),
        ).fetchone()
    assert prior is not None
    _claim_capability(store, claim, invocation_id="invocation-first")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            update guard_workflow_capability_authority_state
            set signed_state_json = ?, key_id = ?, revision = ?, use_high_water = ?,
                observed_at = ?, revocation_id = ? where capability_id = ?
            """,
            (prior[1], prior[2], prior[3], prior[4], prior[5], prior[6], claim.capability_id),
        )
    with pytest.raises(WorkflowCapabilityError, match="capability_use_high_water_invalid"):
        _claim_capability(store, claim, invocation_id="invocation-second")


def test_forged_receipt_history_is_fully_revalidated(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-forged-history", max_uses=3)
    _issue(store, claim)
    receipt = _claim_capability(store, claim, invocation_id="invocation-legitimate")
    with sqlite3.connect(store.path) as connection:
        event_id = connection.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            ("workflow_capability.claimed", "{}", _now()),
        ).lastrowid
        connection.execute(
            """
            insert into guard_workflow_capability_receipts
              (receipt_id, capability_id, task_id, invocation_id, approval_provenance_id,
               signed_receipt_json, claimed_at, use_number, event_id)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "wcr-forged",
                claim.capability_id,
                claim.task_id,
                "invocation-forged",
                claim.approval_provenance_id,
                "{}",
                _now(),
                2,
                event_id,
            ),
        )
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_event_cardinality_invalid"):
        store.lookup_workflow_capability(claim.capability_id)
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_event_cardinality_invalid"):
        store.lookup_workflow_capability_receipt(receipt_id=receipt.receipt.receipt_id)
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_event_cardinality_invalid"):
        _claim_capability(store, claim, invocation_id="invocation-real")


def test_each_authority_operation_revalidates_owned_schema(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-schema-revalidation", max_uses=2)
    _issue(store, claim)
    receipt = _claim_capability(store, claim, invocation_id="invocation-before-schema-tamper")
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger trg_guard_workflow_revocation_immutable_delete")
        connection.execute(
            """create trigger trg_guard_workflow_revocation_immutable_delete
            before delete on guard_workflow_capability_revocations begin select 1; end"""
        )
    with pytest.raises(RuntimeError, match="invalid_workflow_capability_schema:trigger"):
        store.lookup_workflow_capability(claim.capability_id)
    with pytest.raises(RuntimeError, match="invalid_workflow_capability_schema:trigger"):
        store.lookup_workflow_capability_receipt(receipt_id=receipt.receipt.receipt_id)
    with pytest.raises(RuntimeError, match="invalid_workflow_capability_schema:trigger"):
        _claim_capability(store, claim, invocation_id="invocation-schema")
    with pytest.raises(RuntimeError, match="invalid_workflow_capability_schema:trigger"):
        store.revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")


def test_expired_denial_commits_monotonic_time_high_water(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-clock-high-water")
    _issue(store, claim)
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: _now(61))
    with pytest.raises(WorkflowCapabilityError, match="capability_expired"):
        _claim_capability(store, claim, invocation_id="invocation-expired")
    encoded = store._load_workflow_capability_control()
    assert encoded is not None
    assert json.loads(encoded)["observed_at"] == _now(61)

    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: _now(1))
    with pytest.raises(WorkflowCapabilityError, match="capability_clock_rollback"):
        _claim_capability(store, claim, invocation_id="invocation-backdated")
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("select count(*) from guard_workflow_capability_receipts").fetchone() == (0,)
