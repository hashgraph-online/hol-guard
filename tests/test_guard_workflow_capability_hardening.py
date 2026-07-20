"""Adversarial hardening tests for dormant workflow capabilities."""

# pyright: reportAny=false, reportMissingParameterType=false, reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false
# pyright: reportUnknownParameterType=false, reportUnusedCallResult=false, reportUnusedFunction=false
# pyright: reportUntypedFunctionDecorator=false

from __future__ import annotations

import inspect
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import cast

import pytest

from codex_plugin_scanner.guard import store_workflow_capabilities as workflow_store_module
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workflow_capabilities import (
    WORKFLOW_CAPABILITY_ALGORITHM,
    WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA,
    WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA,
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityError,
    sign_workflow_capability,
    verify_workflow_capability,
    verify_workflow_capability_receipt,
)
from tests.test_guard_workflow_capabilities import (
    _KEY,
    _KEY_ID,
    _binding,
    _claim,
    _claim_capability,
    _issue,
    _now,
    _store,
)


@pytest.fixture(autouse=True)
def _fixed_policy_integrity_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda self, *, create: (_KEY, _KEY_ID),
    )
    monkeypatch.setattr(workflow_store_module, "_workflow_capability_store_now", _now)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capability_id", "wc-tampered"),
        ("approval_provenance_id", "provenance-tampered"),
        ("task_id", "task-tampered"),
        ("nonce", "b" * 64),
        ("issuer_id", "issuer.tampered"),
        ("subject_id", "subject.tampered"),
        ("issued_at", "2026-07-19T11:59:00.000000Z"),
        ("not_before", "2026-07-19T12:01:00.000000Z"),
        ("expires_at", "2026-07-19T13:01:00.000000Z"),
        ("max_uses", 2),
    ],
)
def test_every_claim_authority_field_is_signature_bound(field: str, value: object) -> None:
    claim = _claim()
    signed = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)
    tampered = replace(signed, claim=replace(claim, **{field: value}))
    with pytest.raises(WorkflowCapabilityError, match="signature_invalid"):
        verify_workflow_capability(
            tampered,
            key=_KEY,
            key_id=_KEY_ID,
            now=_now(),
            expected_binding=claim.binding,
        )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("envelope_schema", "wrong.envelope.v1", "unsupported_capability_envelope"),
        ("algorithm", "hmac-sha512", "unsupported_capability_algorithm"),
        ("key_id", "guard-policy-integrity-key:other", "capability_key_mismatch"),
        ("signature", "0" * 64, "capability_signature_invalid"),
    ],
)
def test_claim_envelope_tamper_fails_closed(field: str, value: str, error: str) -> None:
    claim = _claim()
    signed = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)
    object.__setattr__(signed, field, value)
    with pytest.raises(WorkflowCapabilityError, match=error):
        verify_workflow_capability(
            signed,
            key=_KEY,
            key_id=_KEY_ID,
            now=_now(),
            expected_binding=claim.binding,
        )


def test_claim_schema_tamper_fails_closed() -> None:
    claim = _claim()
    signed = sign_workflow_capability(claim, key=_KEY, key_id=_KEY_ID)
    object.__setattr__(signed.claim, "schema_version", "wrong.claim.v1")
    with pytest.raises(WorkflowCapabilityError, match="unsupported_capability_schema"):
        verify_workflow_capability(
            signed,
            key=_KEY,
            key_id=_KEY_ID,
            now=_now(),
            expected_binding=claim.binding,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("receipt_id", "wcr-tampered"),
        ("capability_id", "wc-tampered"),
        ("task_id", "task-tampered"),
        ("invocation_id", "invocation-tampered"),
        ("approval_provenance_id", "provenance-tampered"),
        ("claim_sha256", "0" * 64),
        ("binding", _binding(policy_version="policy.v99")),
        ("use_number", 2),
        ("event_id", 999),
        ("claimed_at", "2026-07-19T12:02:00.000000Z"),
    ],
)
def test_every_receipt_field_is_signature_bound(tmp_path, field: str, value: object) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id=f"wc-receipt-tamper-{field}")
    _issue(store, claim)
    signed = _claim_capability(
        store,
        claim,
        invocation_id=f"invocation-{field}",
    )
    tampered = replace(signed, receipt=replace(signed.receipt, **{field: value}))
    with pytest.raises(WorkflowCapabilityError, match="receipt_signature_invalid"):
        verify_workflow_capability_receipt(tampered, key=_KEY, key_id=_KEY_ID)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("envelope_schema", "wrong.receipt.v1", "unsupported_receipt_envelope"),
        ("algorithm", "hmac-sha512", "unsupported_receipt_algorithm"),
        ("key_id", "guard-policy-integrity-key:other", "receipt_key_mismatch"),
        ("signature", "0" * 64, "receipt_signature_invalid"),
    ],
)
def test_receipt_envelope_tamper_fails_closed(tmp_path, field: str, value: str, error: str) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id=f"wc-receipt-envelope-{field}")
    _issue(store, claim)
    signed = _claim_capability(
        store,
        claim,
        invocation_id=f"invocation-{field}",
    )
    object.__setattr__(signed, field, value)
    with pytest.raises(WorkflowCapabilityError, match=error):
        verify_workflow_capability_receipt(signed, key=_KEY, key_id=_KEY_ID)


def test_receipt_schema_tamper_fails_closed(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-receipt-schema")
    _issue(store, claim)
    signed = _claim_capability(
        store,
        claim,
        invocation_id="invocation-receipt-schema",
    )
    object.__setattr__(signed.receipt, "schema_version", "wrong.receipt.v1")
    with pytest.raises(WorkflowCapabilityError, match="unsupported_receipt_schema"):
        verify_workflow_capability_receipt(signed, key=_KEY, key_id=_KEY_ID)


def test_claim_and_revoke_race_is_serializable(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-claim-revoke-race")
    _issue(store, claim)
    barrier = threading.Barrier(2)

    def claim_once() -> str:
        barrier.wait()
        try:
            _claim_capability(
                _store(tmp_path),
                claim,
                invocation_id="invocation-race",
            )
        except WorkflowCapabilityError as error:
            return str(error)
        return "claimed"

    def revoke_once() -> str:
        barrier.wait()
        return (
            "revoked"
            if _store(tmp_path).revoke_workflow_capability(claim.capability_id, reason_code="operator.revoked")
            else "not-revoked"
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        claim_future = executor.submit(claim_once)
        revoke_future = executor.submit(revoke_once)
    claim_result = claim_future.result()
    assert revoke_future.result() == "revoked"
    assert claim_result in {"claimed", "capability_revoked"}
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            """
            select used_count, revoked_at is not null,
                   (select count(*) from guard_workflow_capability_receipts)
            from guard_workflow_capabilities where capability_id = ?
            """,
            (claim.capability_id,),
        ).fetchone()
    expected_uses = 1 if claim_result == "claimed" else 0
    assert row == (expected_uses, 1, expected_uses)


def test_store_rejects_every_unauthorized_issue_without_persistence(tmp_path) -> None:
    store = _store(tmp_path)
    base = _claim(capability_id="wc-issue-base")
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_capability"):
        store.issue_workflow_capability(
            cast(SignedWorkflowCapability, cast(object, base)),
            approval_provenance_id=base.approval_provenance_id,
        )
    with pytest.raises(WorkflowCapabilityError, match="invalid_signed_capability"):
        store.issue_workflow_capability(
            cast(SignedWorkflowCapability, object()),
            approval_provenance_id=base.approval_provenance_id,
        )

    wrong_key = sign_workflow_capability(base, key=b"x" * 32, key_id=_KEY_ID)
    with pytest.raises(WorkflowCapabilityError, match="signature_invalid"):
        store.issue_workflow_capability(wrong_key, approval_provenance_id=base.approval_provenance_id)
    future = _claim(capability_id="wc-issue-future", not_before=_now(10))
    with pytest.raises(WorkflowCapabilityError, match="not_yet_valid"):
        _issue(store, future)
    expired = _claim(
        capability_id="wc-issue-expired",
        issued_at="2026-07-19T10:00:00.000000Z",
        not_before="2026-07-19T10:00:00.000000Z",
        expires_at="2026-07-19T11:00:00.000000Z",
    )
    with pytest.raises(WorkflowCapabilityError, match="expired"):
        _issue(store, expired)
    with pytest.raises(WorkflowCapabilityError, match="approval_binding_mismatch"):
        _issue(store, base, approval_provenance_id="provenance-drift")
    tampered = replace(
        sign_workflow_capability(base, key=_KEY, key_id=_KEY_ID),
        signature="0" * 64,
    )
    with pytest.raises(WorkflowCapabilityError, match="signature_invalid"):
        store.issue_workflow_capability(tampered, approval_provenance_id=base.approval_provenance_id)

    with sqlite3.connect(store.path) as connection:
        capability_count = connection.execute("select count(*) from guard_workflow_capabilities").fetchone()
        issue_event_count = connection.execute(
            "select count(*) from guard_events where event_name = 'workflow_capability.issued'"
        ).fetchone()
    assert capability_count == (0,)
    assert issue_event_count == (0,)


def test_store_clock_cannot_be_backdated_after_expiry(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-clock-expiry")
    _issue(store, claim)
    monkeypatch.setattr(workflow_store_module, "_workflow_capability_store_now", lambda: _now(61))
    with pytest.raises(WorkflowCapabilityError, match="expired"):
        _claim_capability(
            store,
            claim,
            invocation_id="invocation-expired",
        )
    for method_name in (
        "issue_workflow_capability",
        "claim_workflow_capability",
        "revoke_workflow_capability",
    ):
        assert "now" not in inspect.signature(getattr(store, method_name)).parameters
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("select count(*) from guard_workflow_capability_receipts").fetchone() == (0,)


def test_key_rotation_and_context_failure_do_not_create_replay_state(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-key-context", max_uses=2)
    _issue(store, claim)
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda self, *, create: (b"r" * 32, "guard-policy-integrity-key:rotated"),
    )
    with pytest.raises(WorkflowCapabilityError, match="key_mismatch"):
        _claim_capability(
            store,
            claim,
            invocation_id="invocation-retry",
        )
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda self, *, create: (_KEY, _KEY_ID),
    )
    with pytest.raises(WorkflowCapabilityError, match="context_mismatch"):
        _claim_capability(
            store,
            claim,
            invocation_id="invocation-retry",
            expected_binding=replace(claim.binding, policy_version="policy.v99"),
        )
    _claim_capability(
        store,
        claim,
        invocation_id="invocation-retry",
    )
    with pytest.raises(WorkflowCapabilityError, match="replayed"):
        _claim_capability(
            store,
            claim,
            invocation_id="invocation-retry",
        )


def test_receipt_lookup_reverifies_reopen_rows_events_and_current_key(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-receipt-lookup")
    _issue(store, claim)
    receipt = _claim_capability(
        store,
        claim,
        invocation_id="invocation-lookup",
    )
    reopened = _store(tmp_path)
    assert reopened.lookup_workflow_capability_receipt(receipt_id=receipt.receipt.receipt_id) == receipt
    assert reopened.lookup_workflow_capability_receipt(invocation_id=receipt.receipt.invocation_id) == receipt
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger trg_guard_workflow_receipt_immutable_update")
        connection.execute("update guard_workflow_capability_receipts set invocation_id = 'invocation-row-tampered'")
    with pytest.raises(WorkflowCapabilityError, match="capability_receipt_history_invalid"):
        reopened.lookup_workflow_capability_receipt(receipt_id=receipt.receipt.receipt_id)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update guard_workflow_capability_receipts set invocation_id = ?",
            (receipt.receipt.invocation_id,),
        )
        connection.execute(
            "update guard_events set payload_json = ? where event_name = 'workflow_capability.claimed'",
            (json.dumps({"tampered": True}),),
        )
    with pytest.raises(WorkflowCapabilityError, match="capability_authority_transition_event_invalid"):
        reopened.lookup_workflow_capability_receipt(receipt_id=receipt.receipt.receipt_id)
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda self, *, create: (b"r" * 32, "guard-policy-integrity-key:rotated"),
    )
    with pytest.raises(WorkflowCapabilityError, match="key_mismatch"):
        reopened.lookup_workflow_capability_receipt(receipt_id=receipt.receipt.receipt_id)


def test_receipt_lookup_rejects_noncanonical_persisted_json(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-receipt-noncanonical")
    _issue(store, claim)
    receipt = _claim_capability(
        store,
        claim,
        invocation_id="invocation-noncanonical",
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger trg_guard_workflow_receipt_immutable_update")
        connection.execute(
            """
            update guard_workflow_capability_receipts
            set signed_receipt_json = signed_receipt_json || ' '
            where receipt_id = ?
            """,
            (receipt.receipt.receipt_id,),
        )
    with pytest.raises(WorkflowCapabilityError, match="not_canonical"):
        store.lookup_workflow_capability_receipt(receipt_id=receipt.receipt.receipt_id)


def test_receipt_parent_and_event_links_are_trigger_enforced(tmp_path) -> None:
    store = _store(tmp_path)
    claim = _claim(capability_id="wc-link-parent")
    _issue(store, claim)
    receipt = _claim_capability(
        store,
        claim,
        invocation_id="invocation-link",
    )
    with sqlite3.connect(store.path) as connection:
        event_id = connection.execute(
            "select event_id from guard_workflow_capability_receipts where receipt_id = ?",
            (receipt.receipt.receipt_id,),
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError, match="parent_missing"):
            connection.execute(
                """
                insert into guard_workflow_capability_receipts
                  (receipt_id, capability_id, task_id, invocation_id, approval_provenance_id,
                   signed_receipt_json, claimed_at, use_number, event_id)
                values ('orphan-parent', 'missing', 'task', 'invocation-orphan-parent',
                        'approval', '{}', ?, 1, ?)
                """,
                (_now(), event_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="event_missing"):
            connection.execute(
                """
                insert into guard_workflow_capability_receipts
                  (receipt_id, capability_id, task_id, invocation_id, approval_provenance_id,
                   signed_receipt_json, claimed_at, use_number, event_id)
                values ('orphan-event', ?, 'task', 'invocation-orphan-event',
                        'approval', '{}', ?, 2, 99999999)
                """,
                (claim.capability_id, _now()),
            )
        with pytest.raises(sqlite3.IntegrityError, match="event_referenced"):
            connection.execute("delete from guard_events where event_id = ?", (event_id,))


def test_envelope_constants_remain_explicit() -> None:
    assert WORKFLOW_CAPABILITY_ALGORITHM == "hmac-sha256"
    assert WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA.endswith("envelope.v1")
    assert WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA.endswith("receipt-envelope.v1")
    assert SignedWorkflowCapability.__dataclass_fields__["algorithm"] is not None
    assert SignedWorkflowCapabilityReceipt.__dataclass_fields__["algorithm"] is not None
