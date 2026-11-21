"""Receipt read, rollup and analytics scenarios (executed on the ORIGINAL Python)."""

# ruff: noqa: E501

from __future__ import annotations

import json

from receipts_scenario_support import approval_sql, envelope, receipt, sql, step


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def _seed_receipts() -> list[dict[str, object]]:
    return [
        step(
            "add_receipt",
            receipt(
                1, harness="codex", artifact_id="a-0", artifact_name="Alpha", timestamp="2026-04-01T08:00:00+00:00"
            ),
        ),
        step(
            "add_receipt",
            receipt(
                2,
                harness="codex",
                artifact_id="a-0",
                artifact_name=" alpha ",
                policy_decision="block",
                timestamp="2026-04-01T09:00:00+00:00",
            ),
        ),
        step(
            "add_receipt",
            receipt(
                3,
                harness="claude",
                artifact_id="a-1",
                artifact_name=None,
                policy_decision="review",
                timestamp="2026-03-31T10:00:00+00:00",
            ),
            action_envelope=envelope(pre_execution_result="review"),
        ),
        step(
            "add_receipt",
            receipt(
                4, harness="claude", artifact_id="A-1", policy_decision="warn", timestamp="2026-03-30T10:00:00+00:00"
            ),
            action_envelope=envelope(command="echo é", pre_execution_result="warn"),
        ),
        step(
            "add_receipt",
            receipt(
                5,
                harness="cursor",
                artifact_id="a-2",
                policy_decision="require-reapproval",
                timestamp="2026-03-29T23:59:59+00:00",
            ),
            action_envelope=envelope(pre_execution_result="require-reapproval", action_type="file_read"),
        ),
        step(
            "add_receipt",
            receipt(
                6,
                harness="cursor",
                artifact_id="a-2",
                policy_decision="sandbox-required",
                timestamp="2026-03-15T00:00:00+00:00",
            ),
        ),
        step(
            "add_receipt",
            receipt(
                7,
                harness="codex",
                artifact_id="a-3",
                policy_decision="allow",
                timestamp="2026-01-02T00:00:00+00:00",
                scanner_evidence=({"b": 1, "a": "é"},),
            ),
        ),
        step(
            "add_receipt",
            receipt(
                8,
                harness="codex",
                artifact_id="a-3",
                policy_decision="ask",
                timestamp="2026-04-02T12:00:00+00:00",
                approval_request_id="ap-pending",
            ),
        ),
    ]


_APPROVALS = sql(
    "approvals",
    approval_sql("ap-pending", policy_action="review"),
    approval_sql(
        "ap-resolved",
        status="resolved",
        policy_action="review",
        resolution_action="allow",
        resolved_at="2026-04-01T01:00:00+00:00",
    ),
)


def _reads() -> list[dict[str, object]]:
    return [
        step("list_receipts", label="default"),
        step("list_receipts", 3, label="limit 3"),
        step("list_receipts", 50, "codex", label="harness"),
        step("list_receipts", limit=2, harness="cursor", label="kw"),
        step("list_receipts", 0, label="limit 0"),
        step("list_receipts_since_rowid", after_rowid=None, label="since none"),
        step("list_receipts_since_rowid", after_rowid=3, limit=2, label="since 3"),
        step("list_receipts_since_rowid", after_rowid=0, harness="claude", label="since harness"),
        step("latest_receipt_rowid", label="latest"),
        step("latest_receipt_rowid", harness="cursor", label="latest harness"),
        step("latest_receipt_rowid", harness="none", label="latest none"),
        step("get_receipt", "receipt-003", label="get"),
        step("get_receipt", "receipt-008", label="get linked"),
        step("get_receipt", "missing", label="get missing"),
        step("get_receipt_for_approval_request", "ap-pending", policy_decision="review", label="by approval"),
        step("get_receipt_for_approval_request", "ap-pending", policy_decision="allow", label="by approval none"),
        step("get_latest_receipt", "codex", "a-0", label="latest receipt"),
        step("get_latest_receipt", "codex", "zzz", label="latest receipt none"),
        step("count_receipts", label="count"),
        step("count_receipts", harness="codex", label="count harness"),
        step("count_receipts", harness="none", label="count harness none"),
        step("receipt_decision_counts", "claude", "a-1", label="counts"),
        step("receipt_decision_counts", "codex", "a-3", label="counts linked"),
        step("receipt_decision_counts", "none", "none", label="counts none"),
        step(
            "receipt_summary_between",
            start_at="2026-03-30T00:00:00+00:00",
            before_at="2026-04-02T00:00:00+00:00",
            label="summary",
        ),
        step(
            "receipt_summary_between",
            start_at="2030-01-01T00:00:00+00:00",
            before_at="2030-02-01T00:00:00+00:00",
            label="summary empty",
        ),
        step("receipt_analytics", label="analytics default"),
        step("receipt_analytics", activity_days=10, trend_days=3, top_limit=2, label="analytics small"),
        step("receipt_analytics", activity_days=0, trend_days=0, top_limit=0, label="analytics clamp low"),
        step("receipt_analytics", activity_days=1000, trend_days=1000, top_limit=1000, label="analytics clamp high"),
        step("list_receipts_for_command_detail_backfill", label="backfill default"),
        step("list_receipts_for_command_detail_backfill", limit=2, days=30, label="backfill limited"),
        step("list_receipts_for_command_detail_backfill", days=0, before_rowid=6, limit=0, label="backfill before"),
    ]


READ_BASIC = {"name": "read_basic", "steps": [*_seed_receipts(), _APPROVALS, *_reads()]}

CORRUPT = {
    "name": "read_corrupt_rows",
    "steps": [
        *_seed_receipts(),
        _APPROVALS,
        sql(
            "corrupt envelopes",
            (
                "update runtime_receipt_envelopes set envelope_full_json = '{not json' where receipt_id = 'receipt-003'",
                [],
            ),
            (
                "update runtime_receipt_envelopes set envelope_redacted_json = '[1, 2]' where receipt_id = 'receipt-004'",
                [],
            ),
            (
                "update runtime_receipt_envelopes set envelope_full_json = ? where receipt_id = 'receipt-005'",
                [_json({"policy_action": "allow", "pre_execution_result": "block", "finalAction": "allow"})],
            ),
            (
                "update runtime_receipts set scanner_evidence_json = '[1, {\"a\": 2}, \"x\"]' where receipt_id = 'receipt-001'",
                [],
            ),
            ("update runtime_receipts set scanner_evidence_json = '{\"a\": 1}' where receipt_id = 'receipt-002'", []),
            ("update runtime_receipts set scanner_evidence_json = 'garbage' where receipt_id = 'receipt-006'", []),
            ("update runtime_receipts set policy_decision = 'weird' where receipt_id = 'receipt-007'", []),
        ),
        step("list_receipts", 50, label="corrupt list"),
        step("get_receipt", "receipt-003", label="invalid full"),
        step("get_receipt", "receipt-004", label="invalid redacted"),
        step("get_receipt", "receipt-005", label="hidden action key"),
        step("get_receipt", "receipt-007", label="unknown decision"),
        step("receipt_decision_counts", "claude", "a-1", label="counts invalid"),
        sql(
            "bad changed capabilities",
            ("update runtime_receipts set changed_capabilities_json = '{' where receipt_id = 'receipt-001'", []),
        ),
        step("get_receipt", "receipt-001", label="bad capabilities json"),
        step("list_receipts", 50, label="bad capabilities list"),
        sql(
            "approval states",
            ("update approval_requests set status = 'weird' where request_id = 'ap-pending'", []),
        ),
        step("get_receipt", "receipt-008", label="bad approval status"),
        sql(
            "approval resolved with action and no resolved_at",
            (
                "update approval_requests set status = 'resolved', resolution_action = 'allow', resolved_at = null where request_id = 'ap-pending'",
                [],
            ),
        ),
        step("get_receipt", "receipt-008", label="resolved without resolved_at"),
        sql(
            "approval carries envelope",
            (
                "update approval_requests set status = 'pending', resolution_action = null, resolved_at = null, "
                "action_envelope_json = ? where request_id = 'ap-pending'",
                [
                    _json(
                        {
                            "schema_version": 1,
                            "action_id": "z",
                            "harness": "codex",
                            "event_name": "PreToolUse",
                            "action_type": "shell_command",
                            "command": "ls",
                        }
                    )
                ],
            ),
            ("delete from runtime_receipt_envelopes where receipt_id = 'receipt-008'", []),
        ),
        step("get_receipt", "receipt-008", label="approval envelope fallback"),
    ],
}

ROLLUPS = {
    "name": "rollup_backfill_and_reconcile",
    "steps": [
        *_seed_receipts(),
        _APPROVALS,
        step("receipt_analytics", label="initial analytics"),
        sql("drop totals", ("delete from receipt_aggregate_totals", [])),
        step("count_receipts", label="count after totals dropped"),
        step("receipt_analytics", label="analytics rebuilds"),
        sql(
            "approval resolves",
            (
                "update approval_requests set status = 'resolved', resolution_action = 'block', resolved_at = '2026-04-02T00:00:00+00:00' where request_id = 'ap-pending'",
                [],
            ),
        ),
        step(
            "receipt_summary_between",
            start_at="2026-04-01T00:00:00+00:00",
            before_at="2026-04-03T00:00:00+00:00",
            label="dirty reconcile",
        ),
        step("update_receipt_policy_decision", "receipt-001", "block", label="escalate one"),
        step("receipt_analytics", label="after escalation"),
        sql(
            "stale rollup",
            ("update receipt_daily_rollups set total = total + 5", []),
            ("update receipt_aggregate_totals set total = total + 1", []),
        ),
        step("count_receipts", label="stale count"),
        step(
            "receipt_summary_between",
            start_at="2026-04-01T00:00:00+00:00",
            before_at="2026-04-03T00:00:00+00:00",
            label="stale summary",
        ),
        step("receipt_analytics", label="rebuilt after stale"),
        sql(
            "archived receipts", ("update guard_storage_maintenance set archived_receipts = 4 where singleton = 1", [])
        ),
        step("count_receipts", label="count archived"),
        step("receipt_analytics", label="analytics archived"),
        sql(
            "missing action rows",
            ("delete from receipt_rollup_actions where receipt_id in ('receipt-001', 'receipt-002')", []),
        ),
        step("list_receipts_for_command_detail_backfill", label="backfill archived"),
        sql("totals dropped again", ("delete from receipt_aggregate_totals", [])),
        step(
            "receipt_summary_between",
            start_at="2026-01-01T00:00:00+00:00",
            before_at="2027-01-01T00:00:00+00:00",
            label="rebuild archived path",
        ),
        step("receipt_analytics", label="analytics archived rebuild"),
    ],
}

_EVENT_ID = "guard-event-x"


def _event(payload: dict[str, object]) -> str:
    return _json(payload)


EVENTS = {
    "name": "reconcile_receipt_events",
    "steps": [
        *_seed_receipts(),
        _APPROVALS,
        step("reconcile_receipt_events", label="clean"),
        step("update_receipt_policy_decision", "receipt-001", "block", label="escalate"),
        sql(
            "receipt rows drift",
            ("update runtime_receipts set policy_decision = 'allow' where receipt_id = 'receipt-002'", []),
            ("delete from receipt_rollup_actions where receipt_id = 'receipt-002'", []),
            (
                "insert into receipt_rollup_actions (receipt_id, policy_decision, dirty) values ('receipt-002', 'allow', 0)",
                [],
            ),
        ),
        step("reconcile_receipt_events", label="actions drift"),
        sql(
            "mark one uploaded",
            (
                "update guard_cloud_events set uploaded_at = '2026-04-03T00:00:00+00:00' where idempotency_key = 'receipt.created:receipt-003'",
                [],
            ),
            ("update receipt_rollup_actions set policy_decision = 'block' where receipt_id = 'receipt-003'", []),
        ),
        step("reconcile_receipt_events", label="uploaded untouched"),
        sql(
            "event payload invalid",
            (
                "update guard_cloud_events set payload_json = '[1]' where idempotency_key = 'receipt.created:receipt-004'",
                [],
            ),
        ),
        step("reconcile_receipt_events", label="invalid event payload"),
        sql(
            "event payload fixed with hidden decision",
            (
                "update guard_cloud_events set payload_json = ? where idempotency_key = 'receipt.created:receipt-004'",
                [_event({"payload": {"policyDecision": "allow"}, "finalDecision": "allow"})],
            ),
        ),
        step("reconcile_receipt_events", label="hidden decision key"),
        sql(
            "event payload fixed with nested action",
            (
                "update guard_cloud_events set payload_json = ? where idempotency_key = 'receipt.created:receipt-004'",
                [_event({"payload": {"policyDecision": "allow", "nested": [{"Action": "x"}]}})],
            ),
        ),
        step("reconcile_receipt_events", label="nested action key"),
        sql(
            "event payload clean",
            (
                "update guard_cloud_events set payload_json = ? where idempotency_key = 'receipt.created:receipt-004'",
                [_event({"payload": {"policyDecision": "allow", "receiptId": "receipt-004"}})],
            ),
            (
                "update guard_cloud_events set payload_json = ? where idempotency_key = 'receipt.created:receipt-005'",
                [_event({"payload": {"policyDecision": "block"}})],
            ),
        ),
        step("reconcile_receipt_events", label="clean payloads"),
    ],
}

READ_SCENARIOS = [READ_BASIC, CORRUPT, ROLLUPS, EVENTS]
