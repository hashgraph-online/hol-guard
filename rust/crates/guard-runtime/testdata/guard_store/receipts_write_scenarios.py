"""Receipt write scenarios: add_receipt and the three receipt mutators."""

# ruff: noqa: E501

from __future__ import annotations

import json

from receipts_scenario_support import approval_sql, envelope, receipt, sql, step


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def _decision_v2(action: str, product: str) -> str:
    return _json({"guard_action": action, "action": product, "reason": "r"})


ADD_PLAIN = {
    "name": "add_plain_decisions",
    "steps": [
        step("add_receipt", receipt(1, policy_decision="allow", artifact_name="  Mixed Case  "), label="allow"),
        step("add_receipt", receipt(2, policy_decision="warn", artifact_name="mixed case"), label="warn"),
        step("add_receipt", receipt(3, policy_decision="block", artifact_name=""), label="block empty name"),
        step("add_receipt", receipt(4, policy_decision="review", artifact_name=None), label="review"),
        step("add_receipt", receipt(5, policy_decision="require-reapproval", harness="claude"), label="reapproval"),
        step("add_receipt", receipt(6, policy_decision="sandbox-required", harness="claude"), label="sandbox"),
        step("add_receipt", receipt(7, policy_decision="ask"), label="ask alias"),
        step("add_receipt", receipt(8, policy_decision="bogus"), label="unknown decision"),
        step(
            "add_receipt",
            receipt(
                9,
                capabilities_summary="café ☃ \U0001f600",
                changed_capabilities=("é", "plain"),
                scanner_evidence=({"b": 1, "a": [1, 2.5, "é"], "c": None},),
                user_override="user",
                source_scope="project",
                diff_summary="diff",
                approval_source="center",
                raw_command_text="echo é",
            ),
            label="non-ascii and full fields",
        ),
        step("add_receipt", receipt(1, policy_decision="block"), label="duplicate id"),
        step("add_receipt", receipt(10, timestamp="short"), label="short timestamp"),
        step("add_receipt", receipt(11, changed_capabilities=()), label="no capabilities"),
    ],
}

ADD_ENVELOPE = {
    "name": "add_with_envelope",
    "steps": [
        step("add_receipt", receipt(1, policy_decision="allow"), action_envelope=envelope(), label="no result"),
        step(
            "add_receipt",
            receipt(2, policy_decision="block"),
            action_envelope=envelope(pre_execution_result="block", command="rm -rf /tmp/é"),
            label="matching block",
        ),
        step(
            "add_receipt",
            receipt(3, policy_decision="allow"),
            action_envelope=envelope(pre_execution_result="block"),
            label="contradiction rejected",
        ),
        step(
            "add_receipt",
            receipt(4, policy_decision="review"),
            action_envelope=envelope(
                action_type="mcp_tool",
                mcp_server="srv",
                mcp_tool="tool",
                command=None,
                target_paths=(),
                network_hosts=(),
                pre_execution_result="review",
            ),
            label="mcp",
        ),
        step(
            "add_receipt",
            receipt(5, policy_decision="warn"),
            action_envelope=envelope(
                action_type="package_script",
                package_manager="npm",
                package_name="left-pad",
                package_intent_kind="install",
                package_targets=("left-pad", "right-pad"),
                script_name="postinstall",
                command_category="package",
                raw_payload_redacted={"k": "v", "n": [1, 2]},
            ),
            label="package",
        ),
        step(
            "add_receipt",
            receipt(6, policy_decision="allow"),
            action_envelope=envelope(command=None, workspace=None, workspace_hash=None, tool_name=None),
            label="sparse",
        ),
        step(
            "add_receipt",
            receipt(7, policy_decision="bogus"),
            action_envelope=envelope(pre_execution_result="bogus"),
            label="unknown with envelope",
        ),
        step(
            "add_receipt",
            receipt(8, policy_decision="sandbox-required"),
            action_envelope=envelope(pre_execution_result="sandbox-required", prompt_text="hello", prompt_excerpt="h"),
            label="prompt fields",
        ),
    ],
}

_PENDING_BLOCK_ENVELOPE = _json({"policy_action": "block", "pre_execution_result": "block", "action_id": "x"})
ADD_LINKED = {
    "name": "add_linked_approvals",
    "steps": [
        sql(
            "approvals",
            approval_sql("ap-pending", policy_action="review"),
            approval_sql("ap-pending-envelope", policy_action="review", action_envelope_json=_PENDING_BLOCK_ENVELOPE),
            approval_sql(
                "ap-resolved-allow",
                status="resolved",
                policy_action="review",
                resolution_action="allow",
                resolved_at="2026-04-01T01:00:00+00:00",
            ),
            approval_sql(
                "ap-resolved-block",
                status="resolved",
                policy_action="review",
                resolution_action="block",
                resolved_at="2026-04-01T01:00:00+00:00",
            ),
            approval_sql(
                "ap-resolved-hard-block",
                status="resolved",
                policy_action="block",
                resolution_action="allow",
                resolved_at="2026-04-01T01:00:00+00:00",
            ),
            approval_sql("ap-resolved-no-time", status="resolved", policy_action="review", resolution_action="allow"),
            approval_sql(
                "ap-resolved-unknown",
                status="resolved",
                policy_action="review",
                resolution_action="deny",
                resolved_at="2026-04-01T01:00:00+00:00",
            ),
            approval_sql("ap-weird-status", status="weird", policy_action="review"),
            approval_sql(
                "ap-pending-resolved-fields",
                policy_action="review",
                resolution_action="allow",
                resolved_at="2026-04-01T01:00:00+00:00",
            ),
            approval_sql("ap-bogus-action", policy_action="bogus"),
            approval_sql(
                "ap-contradictory-v2", policy_action="review", decision_v2_json=_decision_v2("review", "allow")
            ),
            approval_sql(
                "ap-hidden-v2",
                policy_action="warn",
                decision_v2_json=_json({"guard_action": "warn", "action": "warn", "final_action": "block"}),
            ),
            approval_sql(
                "ap-bad-json", policy_action="review", decision_v2_json="{not json", action_envelope_json="[1]"
            ),
            approval_sql(
                "ap-resolved-envelope",
                status="resolved",
                policy_action="review",
                resolution_action="allow",
                resolved_at="2026-04-01T01:00:00+00:00",
                action_envelope_json=_json(
                    {
                        "policy_action": "review",
                        "policyAction": "review",
                        "final_action": "block",
                        "action_id": "a",
                        "actionId": "b",
                    }
                ),
            ),
        ),
        *[
            step(
                "add_receipt", receipt(index, policy_decision=decision, approval_request_id=link), label=link or "none"
            )
            for index, (decision, link) in enumerate(
                [
                    ("allow", "ap-pending"),
                    ("allow", "ap-pending-envelope"),
                    ("allow", "ap-resolved-allow"),
                    ("review", "ap-resolved-allow"),
                    ("allow", "ap-resolved-block"),
                    ("allow", "ap-resolved-hard-block"),
                    ("allow", "ap-resolved-no-time"),
                    ("allow", "ap-resolved-unknown"),
                    ("allow", "ap-weird-status"),
                    ("allow", "ap-pending-resolved-fields"),
                    ("allow", "ap-bogus-action"),
                    ("allow", "ap-contradictory-v2"),
                    ("allow", "ap-hidden-v2"),
                    ("allow", "ap-bad-json"),
                    ("allow", "ap-resolved-envelope"),
                    ("allow", "ap-missing"),
                    ("allow", None),
                ],
                start=1,
            )
        ],
        step(
            "add_receipt",
            receipt(40, policy_decision="allow", approval_request_id="ap-pending"),
            action_envelope=envelope(pre_execution_result="allow"),
            label="linked with envelope",
        ),
    ],
}

ADD_EVENTS = {
    "name": "add_event_queue_and_context",
    "steps": [
        sql(
            "oauth workspace",
            (
                "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
                ["oauth_local_credentials", _json({"workspace_id": "ws-1", "other": 1}), "2026-04-01T00:00:00+00:00"],
            ),
        ),
        step("add_receipt", receipt(1), label="first event with workspace"),
        sql(
            "blank workspace",
            (
                "update sync_state set payload_json = ? where state_key = 'oauth_local_credentials'",
                [_json({"workspace_id": "   "})],
            ),
        ),
        step("add_receipt", receipt(2), label="blank workspace"),
        sql(
            "non-string workspace",
            (
                "update sync_state set payload_json = ? where state_key = 'oauth_local_credentials'",
                [_json({"workspace_id": 7})],
            ),
        ),
        step("add_receipt", receipt(3), label="reaches the limit"),
        step("add_receipt", receipt(4), label="rejected 1"),
        step("add_receipt", receipt(5), label="rejected 2"),
        sql(
            "uploaded frees a slot",
            (
                "update guard_cloud_events set uploaded_at = '2026-04-03T00:00:00+00:00' where idempotency_key = 'receipt.created:receipt-001'",
                [],
            ),
        ),
        step("add_receipt", receipt(6), label="accepted after upload"),
        step("add_receipt", receipt(7), label="rejected 3"),
        sql(
            "existing event row for a new receipt",
            (
                "insert into guard_cloud_events (event_id, idempotency_key, event_type, payload_json, occurred_at) "
                "values ('pre-existing', 'receipt.created:receipt-050', 'receipt.created', '{}', '2026-04-01T00:00:00+00:00')",
                [],
            ),
        ),
        step("add_receipt", receipt(50), label="existing key is kept"),
        sql(
            "capacity payload variants",
            (
                "update sync_state set payload_json = ? where state_key = 'guard_event_queue_capacity'",
                ["not json"],
            ),
        ),
        step("add_receipt", receipt(8), label="rejected over invalid capacity json"),
        sql(
            "capacity payload non-dict",
            ("update sync_state set payload_json = '[1]' where state_key = 'guard_event_queue_capacity'", []),
        ),
        step("add_receipt", receipt(9), label="rejected over non-dict capacity"),
        sql(
            "capacity payload with strings",
            (
                "update sync_state set payload_json = ? where state_key = 'guard_event_queue_capacity'",
                [_json({"rejectedCount": "x", "firstRejectedAt": "2026-01-01T00:00:00+00:00"})],
            ),
        ),
        step("add_receipt", receipt(12), label="rejected over odd capacity"),
        sql(
            "bool rejected count",
            (
                "update sync_state set payload_json = ? where state_key = 'guard_event_queue_capacity'",
                [_json({"rejectedCount": True})],
            ),
        ),
        step("add_receipt", receipt(13), label="rejected over bool count"),
        sql("drop device", ("delete from guard_devices", [])),
        step("add_receipt", receipt(14), label="device recreated"),
        sql(
            "invalid oauth json",
            ("update sync_state set payload_json = '{oops' where state_key = 'oauth_local_credentials'", []),
        ),
        step("add_receipt", receipt(15), label="oauth json error"),
        sql(
            "non-dict oauth json",
            ("update sync_state set payload_json = '[1]' where state_key = 'oauth_local_credentials'", []),
        ),
        step("add_receipt", receipt(16), label="oauth non-dict"),
    ],
}


WRITE_SCENARIOS = [ADD_PLAIN, ADD_ENVELOPE, ADD_LINKED, ADD_EVENTS]
