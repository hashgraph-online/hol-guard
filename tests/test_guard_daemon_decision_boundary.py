"""Decision-authority checks at daemon approval and receipt persistence boundaries."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution, queue_blocked_approvals
from codex_plugin_scanner.guard.memory_decision_outbox import enqueue_memory_decision_event
from codex_plugin_scanner.guard.models import (
    GuardApprovalRequest,
    GuardArtifact,
    HarnessDetection,
)
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.runtime.decisions import AUTHORITATIVE_DECISION_INCONSISTENT
from codex_plugin_scanner.guard.schemas.guard_event_v1 import GuardEventV1
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_receipt_rollups import backfill_receipt_rollups


def _request(
    tmp_path: Path,
    *,
    request_id: str,
    policy_action: str,
    decision_action: str,
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Shell command",
        artifact_hash=f"hash-{request_id}",
        policy_action=policy_action,  # type: ignore[arg-type]
        recommended_scope="artifact",
        changed_fields=("command",),
        source_scope="project",
        config_path=str(tmp_path / ".codex" / "config.toml"),
        workspace=str(tmp_path),
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        decision_v2_json={
            "action": decision_action,
            "reason": "boundary fixture",
            "user_title": "Allowed by untrusted caller",
            "harness_message": "Caller says this action can continue.",
            "signals": [],
        },
    )


def test_queue_rejects_contradictory_policy_and_product_decision(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact = GuardArtifact(
        artifact_id="codex:project:blocked-command",
        name="blocked-command",
        harness="codex",
        artifact_type="command",
        source_scope="project",
        config_path=str(tmp_path / ".codex" / "config.toml"),
        command="cat ~/.npmrc",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    evaluation = {
        "artifacts": [
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "artifact_hash": "hash-blocked-command",
                "artifact_type": artifact.artifact_type,
                "policy_action": "require-reapproval",
                "decision_v2_json": {
                    "action": "allow",
                    "reason": "contradictory untrusted display field",
                    "signals": [],
                },
                "changed_fields": ["command"],
                "source_scope": artifact.source_scope,
                "config_path": artifact.config_path,
            }
        ]
    }

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:5474",
        )

    assert store.list_approval_requests(limit=None) == []


def test_store_rejects_direct_contradictory_approval_request(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-direct-contradiction",
        policy_action="require-reapproval",
        decision_action="allow",
    )

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        store.add_approval_request(request, "2026-07-18T00:00:00+00:00")

    assert store.list_approval_requests(limit=None) == []


def test_store_rejects_approval_envelope_with_a_different_action(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = replace(
        _request(
            tmp_path,
            request_id="req-envelope-contradiction",
            policy_action="require-reapproval",
            decision_action="ask",
        ),
        action_envelope_json={"pre_execution_result": "block"},
    )

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        store.add_approval_request(request, "2026-07-18T00:00:00+00:00")

    assert store.list_approval_requests(limit=None) == []


def test_legacy_contradictory_row_is_flagged_and_projected_fail_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-legacy-contradiction",
        policy_action="allow",
        decision_action="allow",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set decision_v2_json = ? where request_id = ?",
            (json.dumps({"action": "block", "reason": "legacy contradiction", "signals": []}), request.request_id),
        )

    detail = store.get_approval_request(request.request_id)
    assert detail is not None
    assert detail["policy_action"] == "block"
    assert detail["decision_v2_json"]["action"] == "block"  # type: ignore[index]
    assert detail["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT

    page = store.list_pending_approval_summaries(limit=10)
    summary = page["items"][0]  # type: ignore[index]
    assert summary["policy_action"] == "block"  # type: ignore[index]
    assert summary["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT  # type: ignore[index]

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        apply_approval_resolution(
            store=store,
            request_id=request.request_id,
            action="allow",
            scope="artifact",
            workspace=None,
            reason="must not resolve corrupted authority",
        )
    assert store.list_policy_decisions() == []


@pytest.mark.parametrize("terminal_action", ["sandbox-required", "block"])
def test_terminal_legacy_queue_rows_cannot_mint_an_approval_policy(
    tmp_path: Path,
    terminal_action: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id=f"req-terminal-{terminal_action}",
        policy_action=terminal_action,
        decision_action="block" if terminal_action == "block" else "ask",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")

    with pytest.raises(ValueError, match="terminal_policy_action_not_resolvable"):
        apply_approval_resolution(
            store=store,
            request_id=request.request_id,
            action="allow",
            scope="artifact",
            workspace=None,
            reason="must not override terminal policy",
        )

    assert store.get_approval_request(request.request_id)["status"] == "pending"  # type: ignore[index]
    assert store.list_policy_decisions() == []


def test_terminal_request_cannot_be_resolved_through_single_request_store_facade(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-terminal-direct-facade",
        policy_action="block",
        decision_action="block",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")

    with pytest.raises(ValueError, match="terminal_policy_action_not_resolvable"):
        store.resolve_approval_request(
            request.request_id,
            resolution_action="allow",
            resolution_scope="artifact",
            reason="must not override terminal policy",
            resolved_at="2026-07-18T00:01:00+00:00",
        )

    stored = store.get_approval_request(request.request_id)
    assert stored is not None
    assert stored["status"] == "pending"
    assert stored["resolution_action"] is None


def test_compatible_ask_decision_preserves_exact_review_action(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-compatible-review",
        policy_action="review",
        decision_action="ask",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")

    detail = store.get_approval_request(request.request_id)
    assert detail is not None
    assert detail["policy_action"] == "review"
    assert detail["decision_v2_json"]["action"] == "ask"  # type: ignore[index]
    assert detail["decision_v2_json"]["user_title"] == "Approval required"  # type: ignore[index]
    assert detail["decision_v2_json"]["harness_message"] != "Caller says this action can continue."  # type: ignore[index]
    assert "decision_contract_error" not in detail


def test_legacy_approval_envelope_contradiction_aligns_detail_and_summary(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-legacy-envelope",
        policy_action="allow",
        decision_action="allow",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set action_envelope_json = ? where request_id = ?",
            (json.dumps({"pre_execution_result": "block"}), request.request_id),
        )

    detail = store.get_approval_request(request.request_id)
    assert detail is not None
    assert detail["policy_action"] == "block"
    assert detail["decision_v2_json"]["action"] == "block"  # type: ignore[index]
    assert detail["action_envelope_json"]["pre_execution_result"] == "block"  # type: ignore[index]
    assert detail["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    page = store.list_pending_approval_summaries(limit=10)
    summary = page["items"][0]  # type: ignore[index]
    assert summary["policy_action"] == "block"  # type: ignore[index]
    assert summary["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT  # type: ignore[index]


def _allow_receipt(*, approval_request_id: str | None = None):
    return build_receipt(
        harness="codex",
        artifact_id="codex:project:receipt-boundary",
        artifact_hash="hash-receipt-boundary",
        policy_decision="allow",
        capabilities_summary="No capability changes",
        changed_capabilities=[],
        provenance_summary="Receipt boundary fixture",
        artifact_name="receipt-boundary",
        source_scope="project",
        approval_request_id=approval_request_id,
    )


def test_receipt_envelope_write_rejects_a_different_final_action(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        store.set_receipt_action_envelope(
            receipt.receipt_id,
            {"source": "fixture", "policy_action": "block"},
        )

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "allow"
    assert stored["action_envelope_json"] is None


def test_legacy_receipt_envelope_contradiction_is_flagged_without_rewriting_history(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    with store._connect() as connection:
        connection.execute(
            """
            insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
            values (?, ?, ?)
            """,
            (
                receipt.receipt_id,
                json.dumps({"source": "legacy", "policy_action": "block"}),
                json.dumps({"source": "legacy", "policy_action": "block"}),
            ),
        )

    listed = store.list_receipts()
    assert listed[0]["policy_decision"] == "block"
    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "block"
    assert stored["action_envelope_json"]["policy_action"] == "block"  # type: ignore[index]
    assert stored["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 1
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"block": 1}
    command_detail_candidates = store.list_receipts_for_command_detail_backfill(days=1)
    assert [item["receipt_id"] for item in command_detail_candidates] == [receipt.receipt_id]
    with store._connect() as connection:
        backfill_receipt_rollups(connection)
    backfilled = store.receipt_analytics(top_limit=5)
    assert backfilled["allowed"] == 0
    assert backfilled["blocked"] == 1
    assert store.list_receipts()[0]["policy_decision"] == "block"
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"block": 1}
    events = store.list_guard_events_v1(uploaded=False, limit=10)
    receipt_event = next(item for item in events if item["event_type"] == "receipt.created")
    event = GuardEventV1.from_dict(receipt_event["payload"])  # type: ignore[arg-type]
    assert event.payload["policyDecision"] == "block"


def test_approval_context_link_rejects_a_stronger_action_than_the_receipt_event(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-receipt-context-link",
        policy_action="require-reapproval",
        decision_action="ask",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set action_envelope_json = ? where request_id = ?",
            (json.dumps({"source": "approval", "policy_action": "block"}), request.request_id),
        )
    receipt = _allow_receipt()
    store.add_receipt(receipt)

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        store.update_receipt_approval_context(
            receipt.receipt_id,
            approval_source="local",
            approval_request_id=request.request_id,
        )

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "allow"
    assert stored["approval_request_id"] is None
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 1
    assert analytics["blocked"] == 0


def test_approval_envelope_fallback_is_canonicalized_before_receipt_output(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-receipt-fallback",
        policy_action="require-reapproval",
        decision_action="ask",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set action_envelope_json = ? where request_id = ?",
            (json.dumps({"source": "approval", "policy_action": "block"}), request.request_id),
        )
    receipt = _allow_receipt(approval_request_id=request.request_id)
    store.add_receipt(receipt)

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "block"
    assert stored["action_envelope_json"]["policy_action"] == "block"  # type: ignore[index]
    assert stored["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 1
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"block": 1}
    events = store.list_guard_events_v1(uploaded=False, limit=10)
    receipt_event = next(item for item in events if item["event_type"] == "receipt.created")
    event = GuardEventV1.from_dict(receipt_event["payload"])  # type: ignore[arg-type]
    assert event.payload["policyDecision"] == "block"


def test_approval_envelope_mutation_reconciles_an_existing_receipt_rollup(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-receipt-fallback-mutation",
        policy_action="require-reapproval",
        decision_action="ask",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    receipt = replace(
        _allow_receipt(approval_request_id=request.request_id),
        policy_decision="require-reapproval",
    )
    store.add_receipt(receipt)
    store.set_receipt_action_envelope(
        receipt.receipt_id,
        {"source": "receipt", "policy_action": "require-reapproval"},
    )
    initial = store.receipt_analytics(top_limit=5)
    assert initial["allowed"] == 0
    assert initial["blocked"] == 0
    assert initial["reviewed"] == 1

    with store._connect() as connection:
        connection.execute(
            "update approval_requests set action_envelope_json = ? where request_id = ?",
            (json.dumps({"source": "approval", "policy_action": "block"}), request.request_id),
        )

    assert store.list_receipts()[0]["policy_decision"] == "block"
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"block": 1}
    reconciled = store.receipt_analytics(top_limit=5)
    assert reconciled["allowed"] == 0
    assert reconciled["blocked"] == 1

    store.update_receipt_policy_decision(receipt.receipt_id, "allow")

    updated = store.get_receipt(receipt.receipt_id)
    assert updated is not None
    assert updated["policy_decision"] == "block"
    assert updated["action_envelope_json"]["policy_action"] == "block"  # type: ignore[index]
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"block": 1}
    updated_analytics = store.receipt_analytics(top_limit=5)
    assert updated_analytics["total"] == 1
    assert updated_analytics["allowed"] == 0
    assert updated_analytics["blocked"] == 1


@pytest.mark.parametrize(
    ("resolution_action", "expected_policy_decision"),
    [("allow", "allow"), ("block", "block")],
)
def test_resolved_approval_uses_final_resolution_for_memory_receipt_and_event(
    tmp_path: Path,
    resolution_action: str,
    expected_policy_decision: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = replace(
        _request(
            tmp_path,
            request_id=f"req-resolved-memory-{resolution_action}",
            policy_action="review",
            decision_action="ask",
        ),
        action_envelope_json={
            "source": "pre-execution-review",
            "command": "printf resolved-memory-receipt",
            "policy_action": "review",
            "pre_execution_result": "review",
        },
        raw_command_text="printf resolved-memory-receipt",
    )
    created_at = "2026-07-18T00:00:00+00:00"
    resolved_at = "2026-07-18T00:01:00+00:00"
    store.add_approval_request(request, created_at)
    store.resolve_approval_request(
        request.request_id,
        resolution_action=resolution_action,
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at=resolved_at,
    )
    resolved = store.get_approval_request(request.request_id)
    assert resolved is not None

    assert enqueue_memory_decision_event(
        store,
        request=resolved,
        action=resolution_action,
        scope="artifact",
        resolved_at=resolved_at,
    )

    receipt = store.get_receipt_for_approval_request(
        request.request_id,
        policy_decision=expected_policy_decision,
    )
    assert receipt is not None
    assert receipt["policy_decision"] == expected_policy_decision
    assert "decision_contract_error" not in receipt
    receipt_envelope = receipt["action_envelope_json"]
    assert isinstance(receipt_envelope, dict)
    assert receipt_envelope["source"] == "pre-execution-review"
    assert receipt_envelope["command"] == "printf resolved-memory-receipt"
    assert receipt_envelope["policy_action"] == expected_policy_decision
    assert receipt_envelope["pre_execution_result"] == expected_policy_decision
    assert store.receipt_decision_counts(request.harness, request.artifact_id) == {expected_policy_decision: 1}
    analytics = store.receipt_analytics(top_limit=5)
    expected_bucket = "allowed" if expected_policy_decision == "allow" else "blocked"
    assert analytics[expected_bucket] == 1
    events = store.list_guard_events_v1(uploaded=False, limit=20)
    receipt_event = next(item for item in events if item["event_type"] == "receipt.created")
    parsed_event = GuardEventV1.from_dict(receipt_event["payload"])  # type: ignore[arg-type]
    assert parsed_event.payload["policyDecision"] == expected_policy_decision


@pytest.mark.parametrize(
    ("status", "resolution_action", "resolved_at", "expected_action"),
    [
        ("pending", "allow", None, "require-reapproval"),
        ("pending", "block", None, "block"),
        ("pending", "sandbox-required", None, "sandbox-required"),
        ("resolved", None, "2026-07-18T00:01:00+00:00", "require-reapproval"),
        ("resolved", "allow", None, "require-reapproval"),
        ("resolved", "block", None, "block"),
        ("future-status", None, None, "require-reapproval"),
        ("future-status", "block", None, "block"),
    ],
)
def test_malformed_linked_approval_lifecycle_fails_receipt_closed(
    tmp_path: Path,
    status: str,
    resolution_action: str | None,
    resolved_at: str | None,
    expected_action: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = replace(
        _request(
            tmp_path,
            request_id=f"req-malformed-lifecycle-{status}-{resolution_action}",
            policy_action="review",
            decision_action="ask",
        ),
        action_envelope_json={
            "source": "pre-execution-review",
            "policy_action": "review",
        },
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    with store._connect() as connection:
        connection.execute(
            """
            update approval_requests
            set status = ?, resolution_action = ?, resolved_at = ?
            where request_id = ?
            """,
            (status, resolution_action, resolved_at, request.request_id),
        )

    receipt = _allow_receipt(approval_request_id=request.request_id)
    store.add_receipt(receipt)

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == expected_action
    assert stored["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {expected_action: 1}
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == (1 if expected_action == "block" else 0)
    assert analytics["reviewed"] == (0 if expected_action == "block" else 1)


def test_corrupted_terminal_to_allow_resolution_preserves_terminal_receipt_authority(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = replace(
        _request(
            tmp_path,
            request_id="req-corrupted-terminal-resolution",
            policy_action="block",
            decision_action="block",
        ),
        action_envelope_json={
            "source": "terminal-policy",
            "policy_action": "block",
            "pre_execution_result": "block",
        },
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    with store._connect() as connection:
        connection.execute(
            """
            update approval_requests
            set status = 'resolved', resolution_action = 'allow',
                resolution_scope = 'artifact', resolved_at = ?
            where request_id = ?
            """,
            ("2026-07-18T00:01:00+00:00", request.request_id),
        )

    receipt = _allow_receipt(approval_request_id=request.request_id)
    store.add_receipt(receipt)

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "block"
    assert stored["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"block": 1}
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 1
    events = store.list_guard_events_v1(uploaded=False, limit=10)
    receipt_event = next(item for item in events if item["event_type"] == "receipt.created")
    parsed_event = GuardEventV1.from_dict(receipt_event["payload"])  # type: ignore[arg-type]
    assert parsed_event.payload["policyDecision"] == "block"


def test_corrupted_pre_resolution_surface_cannot_mask_a_resolved_block(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = replace(
        _request(
            tmp_path,
            request_id="req-corrupted-pre-surface-block-resolution",
            policy_action="allow",
            decision_action="allow",
        ),
        action_envelope_json={
            "source": "pre-execution-allow",
            "policy_action": "allow",
        },
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    with store._connect() as connection:
        connection.execute(
            """
            update approval_requests
            set decision_v2_json = ?, status = 'resolved',
                resolution_action = 'block', resolution_scope = 'artifact',
                resolved_at = ?
            where request_id = ?
            """,
            (
                json.dumps({"action": "future-action", "reason": "corrupted", "signals": []}),
                "2026-07-18T00:01:00+00:00",
                request.request_id,
            ),
        )

    receipt = _allow_receipt(approval_request_id=request.request_id)
    store.add_receipt(receipt)

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "block"
    assert stored["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"block": 1}
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 1
    events = store.list_guard_events_v1(uploaded=False, limit=10)
    receipt_event = next(item for item in events if item["event_type"] == "receipt.created")
    parsed_event = GuardEventV1.from_dict(receipt_event["payload"])  # type: ignore[arg-type]
    assert parsed_event.payload["policyDecision"] == "block"


def test_receipt_link_without_local_approval_row_preserves_receipt_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt(approval_request_id="req-does-not-exist")

    store.add_receipt(receipt)

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "allow"
    assert stored["approval_request_id"] == "req-does-not-exist"
    assert "decision_contract_error" not in stored


def test_receipt_context_without_local_approval_row_preserves_receipt_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)

    store.update_receipt_approval_context(
        receipt.receipt_id,
        approval_source="memory_decision",
        approval_request_id="req-does-not-exist",
    )

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "allow"
    assert stored["approval_source"] == "memory_decision"
    assert stored["approval_request_id"] == "req-does-not-exist"


def test_malformed_receipt_envelope_fails_closed_in_reads_counts_and_rollups(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    with store._connect() as connection:
        connection.execute(
            """
            insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
            values (?, ?, ?)
            """,
            (receipt.receipt_id, "not-json", json.dumps({"source": "legacy"})),
        )

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "require-reapproval"
    assert stored["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"require-reapproval": 1}
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 0
    assert analytics["reviewed"] == 1


def test_malformed_receipt_envelope_cannot_mask_a_linked_approval_block(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _request(
        tmp_path,
        request_id="req-malformed-receipt-envelope",
        policy_action="require-reapproval",
        decision_action="ask",
    )
    store.add_approval_request(request, "2026-07-18T00:00:00+00:00")
    receipt = _allow_receipt(approval_request_id=request.request_id)
    store.add_receipt(receipt)
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set action_envelope_json = ? where request_id = ?",
            (json.dumps({"source": "approval", "policy_action": "block"}), request.request_id),
        )
        connection.execute(
            """
            insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
            values (?, ?, ?)
            """,
            (receipt.receipt_id, "not-json", json.dumps({"source": "legacy"})),
        )

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "block"
    assert stored["action_envelope_json"]["policy_action"] == "block"  # type: ignore[index]
    assert stored["decision_contract_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    assert store.receipt_decision_counts(receipt.harness, receipt.artifact_id) == {"block": 1}
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 1
    assert analytics["reviewed"] == 0


def test_receipt_action_update_preserves_a_reconciled_fail_closed_rollup(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    with store._connect() as connection:
        envelope_json = json.dumps({"source": "legacy", "policy_action": "block"})
        connection.execute(
            """
            insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
            values (?, ?, ?)
            """,
            (receipt.receipt_id, envelope_json, envelope_json),
        )

    reconciled = store.receipt_analytics(top_limit=5)
    assert reconciled["allowed"] == 0
    assert reconciled["blocked"] == 1

    store.update_receipt_policy_decision(receipt.receipt_id, "block")

    updated = store.receipt_analytics(top_limit=5)
    assert updated["total"] == 1
    assert updated["allowed"] == 0
    assert updated["blocked"] == 1
    assert updated["reviewed"] == 0


def test_receipt_action_update_synchronizes_full_redacted_and_rollup(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    store.set_receipt_action_envelope(
        receipt.receipt_id,
        {"source": "fixture", "policy_action": "allow"},
    )

    store.update_receipt_policy_decision(receipt.receipt_id, "block")

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "block"
    assert stored["action_envelope_json"]["policy_action"] == "block"  # type: ignore[index]
    assert stored["envelope_redacted_json"]["policy_action"] == "block"  # type: ignore[index]
    assert "decision_contract_error" not in stored
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 1
    events = store.list_guard_events_v1(uploaded=False, limit=10)
    receipt_event = next(item for item in events if item["event_type"] == "receipt.created")
    event = GuardEventV1.from_dict(receipt_event["payload"])  # type: ignore[arg-type]
    assert event.payload["policyDecision"] == "block"


def test_receipt_action_update_rejects_an_already_uploaded_creation_event(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    store.set_receipt_action_envelope(
        receipt.receipt_id,
        {"source": "fixture", "policy_action": "allow"},
    )
    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    receipt_event = next(item for item in pending if item["event_type"] == "receipt.created")
    store.mark_guard_events_v1_uploaded(
        [str(receipt_event["event_id"])],
        "2026-07-18T00:01:00+00:00",
    )

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        store.update_receipt_policy_decision(receipt.receipt_id, "block")

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "allow"
    assert stored["action_envelope_json"]["policy_action"] == "allow"  # type: ignore[index]
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 1
    assert analytics["blocked"] == 0
    uploaded = store.list_guard_events_v1(uploaded=True, limit=10)
    event = GuardEventV1.from_dict(uploaded[0]["payload"])  # type: ignore[arg-type]
    assert event.payload["policyDecision"] == "allow"


def test_malformed_pending_receipt_event_is_rejected_before_upload_listing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    with store._connect() as connection:
        connection.execute(
            "update guard_cloud_events set payload_json = ? where idempotency_key = ?",
            ("not-json", f"receipt.created:{receipt.receipt_id}"),
        )

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        store.list_guard_events_v1(uploaded=False, limit=10)


@pytest.mark.parametrize("hidden_key", ["guardAction", "policy_decision"])
def test_hidden_pending_receipt_event_authority_is_rejected_before_upload(
    tmp_path: Path,
    hidden_key: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _allow_receipt()
    store.add_receipt(receipt)
    with store._connect() as connection:
        row = connection.execute(
            "select payload_json from guard_cloud_events where idempotency_key = ?",
            (f"receipt.created:{receipt.receipt_id}",),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row["payload_json"]))
        payload["payload"][hidden_key] = "block"
        connection.execute(
            "update guard_cloud_events set payload_json = ? where idempotency_key = ?",
            (json.dumps(payload), f"receipt.created:{receipt.receipt_id}"),
        )

    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        store.list_guard_events_v1(uploaded=False, limit=10)


def test_unknown_receipt_action_is_canonical_in_db_api_event_and_rollup(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = replace(_allow_receipt(), policy_decision="future-action")  # type: ignore[arg-type]

    store.add_receipt(receipt)

    stored = store.get_receipt(receipt.receipt_id)
    assert stored is not None
    assert stored["policy_decision"] == "require-reapproval"
    events = store.list_guard_events_v1(uploaded=False, limit=10)
    receipt_event = next(item for item in events if item["event_type"] == "receipt.created")
    assert receipt_event["payload"]["payload"]["policyDecision"] == "require-reapproval"  # type: ignore[index]
    analytics = store.receipt_analytics(top_limit=5)
    assert analytics["allowed"] == 0
    assert analytics["blocked"] == 0
    assert analytics["reviewed"] == 1
