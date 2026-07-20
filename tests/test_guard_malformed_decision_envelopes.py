"""Regression coverage for malformed persisted decision envelopes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.decision_boundaries import (
    canonical_approval_surfaces,
    canonical_receipt_decision,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.runtime.decisions import (
    AUTHORITATIVE_DECISION_INCONSISTENT,
    decision_from_legacy_policy_action,
)
from codex_plugin_scanner.guard.store import GuardStore

_MALFORMED_BLOCK_ENVELOPE = '{"pre_execution_result":"block"'


def test_approval_boundary_rejects_contradictory_exact_decision_action() -> None:
    payload = decision_from_legacy_policy_action("block", reason="exact-block").to_dict()
    payload["action"] = "ask"

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        canonical_approval_surfaces(
            "review",
            payload,
            None,
            reject_contradiction=True,
        )

    recovered = canonical_approval_surfaces(
        "review",
        payload,
        None,
        reject_contradiction=False,
    )
    assert recovered.policy_action == "block"
    assert recovered.decision_v2_json["guard_action"] == "block"
    assert recovered.contract_error == AUTHORITATIVE_DECISION_INCONSISTENT


def test_decision_v2_hidden_action_alias_is_rejected_or_recovered_fail_closed() -> None:
    payload = decision_from_legacy_policy_action("allow", reason="exact-allow").to_dict()
    payload["final_action"] = "block"

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        canonical_approval_surfaces("allow", payload, None, reject_contradiction=True)

    recovered = canonical_approval_surfaces("allow", payload, None, reject_contradiction=False)
    assert recovered.policy_action == "block"
    assert recovered.decision_v2_json["guard_action"] == "block"
    assert recovered.contract_error == AUTHORITATIVE_DECISION_INCONSISTENT


def test_action_envelope_hidden_action_alias_is_rejected_or_recovered_fail_closed() -> None:
    envelope = {
        "pre_execution_result": "allow",
        "final_action": "block",
    }

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        canonical_receipt_decision("allow", envelope, reject_contradiction=True)

    recovered = canonical_receipt_decision("allow", envelope, reject_contradiction=False)
    assert recovered.policy_decision == "block"
    assert recovered.action_envelope_json == {"pre_execution_result": "block"}
    assert recovered.contract_error == AUTHORITATIVE_DECISION_INCONSISTENT


def test_action_envelope_documented_camel_alias_must_match_the_canonical_action() -> None:
    envelope = {
        "pre_execution_result": "allow",
        "preExecutionResult": "block",
    }

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        canonical_receipt_decision("allow", envelope, reject_contradiction=True)

    recovered = canonical_receipt_decision("allow", envelope, reject_contradiction=False)
    assert recovered.policy_decision == "block"
    assert recovered.action_envelope_json == {
        "pre_execution_result": "block",
        "preExecutionResult": "block",
    }
    assert recovered.contract_error == AUTHORITATIVE_DECISION_INCONSISTENT


def test_legacy_ask_has_one_exact_review_projection_across_persistence_boundaries() -> None:
    approval = canonical_approval_surfaces("ask", None, None, reject_contradiction=False)
    receipt = canonical_receipt_decision("ask", None, reject_contradiction=False)

    assert approval.policy_action == "review"
    assert approval.decision_v2_json["guard_action"] == "review"
    assert approval.contract_error is None
    assert receipt.policy_decision == "review"
    assert receipt.contract_error is None


def _allow_approval_request(tmp_path: Path, *, request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Shell command",
        artifact_hash=f"hash-{request_id}",
        policy_action="allow",
        recommended_scope="artifact",
        changed_fields=("command",),
        source_scope="project",
        config_path=str(tmp_path / ".codex" / "config.toml"),
        workspace=str(tmp_path),
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        decision_v2_json={
            "action": "allow",
            "reason": "malformed-envelope fixture",
            "signals": [],
        },
    )


def _allow_receipt():
    return build_receipt(
        harness="codex",
        artifact_id="codex:project:malformed-envelope",
        artifact_hash="hash-malformed-envelope",
        policy_decision="allow",
        capabilities_summary="No capability changes",
        changed_capabilities=[],
        provenance_summary="Malformed-envelope fixture",
        artifact_name="malformed-envelope",
        source_scope="project",
    )


@pytest.mark.parametrize(
    "persisted_envelope",
    [_MALFORMED_BLOCK_ENVELOPE, json.dumps([{"pre_execution_result": "block"}])],
)
def test_pending_approval_with_non_object_envelope_fails_closed(
    tmp_path: Path,
    persisted_envelope: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _allow_approval_request(tmp_path, request_id="req-malformed-envelope")
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set action_envelope_json = ? where request_id = ?",
            (persisted_envelope, request.request_id),
        )

    detail = store.get_approval_request(request.request_id)
    assert detail is not None
    assert detail["policy_action"] == "require-reapproval"
    decision_v2 = detail["decision_v2_json"]
    assert isinstance(decision_v2, dict)
    assert decision_v2["action"] == "ask"
    assert detail["action_envelope_json"] is None
    assert detail["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT

    page = store.list_pending_approval_summaries(limit=10)
    items = page["items"]
    assert isinstance(items, list)
    summary = items[0]
    assert isinstance(summary, dict)
    assert summary["policy_action"] == "require-reapproval"
    assert summary["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT


def test_receipt_read_marks_malformed_envelope_without_rewriting_history(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    with store._connect() as connection:
        connection.execute(
            """
            insert into runtime_receipt_envelopes (
              receipt_id, envelope_full_json, envelope_redacted_json
            ) values (?, ?, ?)
            """,
            (receipt.receipt_id, _MALFORMED_BLOCK_ENVELOPE, json.dumps({})),
        )

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "require-reapproval"
    assert stored["action_envelope_json"] is None
    assert stored["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 0
    assert analytics["reviewed"] == 1
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"require-reapproval": 1}


@pytest.mark.parametrize("corrupted_column", ["envelope_full_json", "envelope_redacted_json"])
def test_receipt_action_mutation_rejects_malformed_existing_envelope(
    tmp_path: Path,
    corrupted_column: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    store.set_receipt_action_envelope(
        receipt.receipt_id,
        {"source": "fixture", "policy_action": "allow"},
    )
    with store._connect() as connection:
        connection.execute(
            f"update runtime_receipt_envelopes set {corrupted_column} = ? where receipt_id = ?",
            (_MALFORMED_BLOCK_ENVELOPE, receipt.receipt_id),
        )

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        store.update_receipt_policy_decision(receipt.receipt_id, "block")

    with store._connect() as connection:
        receipt_row = connection.execute(
            "select policy_decision from runtime_receipts where receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone()
        envelope_row = connection.execute(
            f"select {corrupted_column} from runtime_receipt_envelopes where receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone()
    assert receipt_row is not None
    assert receipt_row["policy_decision"] == "allow"
    assert envelope_row is not None
    assert envelope_row[corrupted_column] == _MALFORMED_BLOCK_ENVELOPE
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 0
    assert analytics["reviewed"] == 1
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"require-reapproval": 1}
