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

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    WORKFLOW_CAPABILITY_ALGORITHM,
    WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA,
    WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA,
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityClaim,
    WorkflowCapabilityError,
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
from tests.workflow_capability_frame_support import sign_workflow_capability


@pytest.fixture(autouse=True)
def _fixed_policy_integrity_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda self, *, create: (_KEY, _KEY_ID),
    )
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", _now)


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
    with pytest.raises(WorkflowCapabilityError, match="invalid_capability_claim"):
        store.issue_workflow_capability(
            cast(WorkflowCapabilityClaim, object()),
            approval_provenance_id=base.approval_provenance_id,
        )
    # The resident holds the capability key, so a caller never hands a signed
    # envelope back to be issued: it is not a claim and never reaches the key.
    with pytest.raises(WorkflowCapabilityError, match="invalid_capability_claim"):
        store.issue_workflow_capability(
            cast(WorkflowCapabilityClaim, cast(object, sign_workflow_capability(base, key=_KEY, key_id=_KEY_ID))),
            approval_provenance_id=base.approval_provenance_id,
        )
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
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: _now(61))
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
