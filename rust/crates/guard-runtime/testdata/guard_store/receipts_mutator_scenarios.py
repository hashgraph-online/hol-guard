"""Receipt mutator scenarios: envelope, policy decision and approval context updates."""

# ruff: noqa: E501

from __future__ import annotations

import json

from receipts_scenario_support import approval_sql, envelope, receipt, sql, step


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True)


SET_ENVELOPE = {
    "name": "set_receipt_action_envelope",
    "steps": [
        step("add_receipt", receipt(1, policy_decision="review"), label="plain review"),
        step("add_receipt", receipt(2, policy_decision="block"), label="plain block"),
        step(
            "set_receipt_action_envelope",
            "receipt-001",
            envelope(pre_execution_result="review").to_dict(),
            label="typed",
        ),
        step("set_receipt_action_envelope", "receipt-001", envelope(command="echo é").to_dict(), label="typed replace"),
        step("set_receipt_action_envelope", "receipt-404", envelope().to_dict(), label="missing receipt"),
        step(
            "set_receipt_action_envelope",
            "receipt-002",
            {"harness": "codex", "command": "ls", "target_paths": ["a"], "network_hosts": [], "policy_action": "block"},
            label="legacy shape",
        ),
        step(
            "set_receipt_action_envelope",
            "receipt-002",
            {**envelope().to_dict(), "policy_action": "block", "pre_execution_result": "block"},
            label="typed with policy fields",
        ),
        step(
            "set_receipt_action_envelope",
            "receipt-002",
            {**envelope().to_dict(), "policy_action": "allow"},
            label="policy contradiction",
        ),
        step(
            "set_receipt_action_envelope",
            "receipt-002",
            {**envelope().to_dict(), "final_action": "allow"},
            label="hidden action key",
        ),
        step(
            "set_receipt_action_envelope",
            "receipt-002",
            {**envelope().to_dict(), "action_id": "a", "actionId": "b"},
            label="alias conflict",
        ),
        step(
            "set_receipt_action_envelope",
            "receipt-002",
            {
                "actionId": "x",
                "policyAction": "block",
                "preExecutionResult": "block",
                "command": 12,
                "target_paths": "no",
            },
            label="camel legacy",
        ),
        step(
            "set_receipt_action_envelope",
            "receipt-002",
            {**envelope().to_dict(), "schema_version": 2, "observed_policy_action": "allow", "policy_action": "block"},
            label="unsupported version with observed action",
        ),
        step(
            "set_receipt_action_envelope",
            "receipt-002",
            {"observed_policy_action": "nonsense", "policy_action": "block"},
            label="observed unknown",
        ),
        step(
            "set_receipt_action_envelope",
            "receipt-001",
            {**envelope().to_dict(), "harness": "  ", "package_name": "x"},
            label="blank harness goes legacy",
        ),
    ],
}

UPDATE_DECISION = {
    "name": "update_receipt_policy_decision",
    "steps": [
        sql(
            "approvals",
            approval_sql("ap-pending", policy_action="review"),
            approval_sql(
                "ap-resolved-allow",
                status="resolved",
                policy_action="review",
                resolution_action="allow",
                resolved_at="2026-04-01T01:00:00+00:00",
            ),
        ),
        step("add_receipt", receipt(1, policy_decision="review"), label="review"),
        step(
            "add_receipt", receipt(2, policy_decision="allow"), action_envelope=envelope(pre_execution_result="allow")
        ),
        step("add_receipt", receipt(3, policy_decision="allow", approval_request_id="ap-pending"), label="linked"),
        step(
            "add_receipt",
            receipt(4, policy_decision="allow", approval_request_id="ap-resolved-allow"),
            label="linked resolved",
        ),
        step("update_receipt_policy_decision", "receipt-001", "block", label="escalate plain"),
        step("update_receipt_policy_decision", "receipt-001", "allow", label="cannot lower below stored block"),
        step("update_receipt_policy_decision", "receipt-002", "block", label="escalate with envelope"),
        step("update_receipt_policy_decision", "receipt-003", "allow", label="pending approval floor"),
        step("update_receipt_policy_decision", "receipt-004", "allow", label="resolved approval"),
        step("update_receipt_policy_decision", "receipt-004", "bogus", label="unknown decision"),
        step("update_receipt_policy_decision", "receipt-404", "block", label="missing receipt"),
        sql(
            "pending event uploaded",
            (
                "update guard_cloud_events set uploaded_at = '2026-04-03T00:00:00+00:00' where idempotency_key = 'receipt.created:receipt-003'",
                [],
            ),
        ),
        step("update_receipt_policy_decision", "receipt-003", "block", label="uploaded event rejects change"),
        sql(
            "pending event removed",
            ("delete from guard_cloud_events where idempotency_key = 'receipt.created:receipt-002'", []),
        ),
        step("update_receipt_policy_decision", "receipt-002", "sandbox-required", label="missing event rejects change"),
        step("update_receipt_policy_decision", "receipt-001", "block", label="unchanged decision skips event"),
        sql(
            "event payload corrupt",
            (
                "update guard_cloud_events set payload_json = '{\"payload\": 1}' where idempotency_key = 'receipt.created:receipt-001'",
                [],
            ),
        ),
        step("update_receipt_policy_decision", "receipt-001", "sandbox-required", label="corrupt event rejects change"),
        sql(
            "malformed envelope row",
            ("update runtime_receipt_envelopes set envelope_full_json = 'nope' where receipt_id = 'receipt-002'", []),
        ),
        step("update_receipt_policy_decision", "receipt-002", "block", label="malformed envelope"),
        sql(
            "null envelope row",
            ("update runtime_receipt_envelopes set envelope_full_json = null where receipt_id = 'receipt-002'", []),
        ),
        step("update_receipt_policy_decision", "receipt-002", "block", label="null full envelope"),
    ],
}

UPDATE_CONTEXT = {
    "name": "update_receipt_approval_context",
    "steps": [
        sql(
            "approvals",
            approval_sql("ap-pending", policy_action="review"),
            approval_sql("ap-pending-2", policy_action="review"),
            approval_sql("ap-pending-block", policy_action="block"),
            approval_sql(
                "ap-resolved-allow",
                status="resolved",
                policy_action="review",
                resolution_action="allow",
                resolved_at="2026-04-01T01:00:00+00:00",
            ),
        ),
        step("add_receipt", receipt(1, policy_decision="review"), label="plain review"),
        step("add_receipt", receipt(2, policy_decision="allow", approval_request_id="ap-pending"), label="linked"),
        step(
            "update_receipt_approval_context",
            "receipt-001",
            approval_source="center",
            approval_request_id="ap-pending",
            label="link equal action",
        ),
        step(
            "update_receipt_approval_context",
            "receipt-001",
            approval_source="center",
            approval_request_id="ap-pending",
            label="same link",
        ),
        step(
            "update_receipt_approval_context",
            "receipt-001",
            approval_source=None,
            approval_request_id=None,
            label="clear link",
        ),
        step(
            "update_receipt_approval_context",
            "receipt-002",
            approval_source="center",
            approval_request_id="ap-pending-2",
            label="switch link",
        ),
        step(
            "update_receipt_approval_context",
            "receipt-002",
            approval_source="center",
            approval_request_id="ap-pending-block",
            label="stronger link rejected",
        ),
        step(
            "update_receipt_approval_context",
            "receipt-002",
            approval_source="center",
            approval_request_id="ap-resolved-allow",
            label="resolved link rejected",
        ),
        step(
            "update_receipt_approval_context",
            "receipt-002",
            approval_source="x",
            approval_request_id="ap-missing",
            label="missing approval row",
        ),
        step(
            "update_receipt_approval_context",
            "receipt-404",
            approval_source="x",
            approval_request_id=None,
            label="missing receipt",
        ),
        step(
            "update_receipt_approval_context",
            "receipt-001",
            approval_source="x",
            approval_request_id="ap-pending-block",
            label="plain receipt to stronger",
        ),
    ],
}


MUTATOR_SCENARIOS = [SET_ENVELOPE, UPDATE_DECISION, UPDATE_CONTEXT]
