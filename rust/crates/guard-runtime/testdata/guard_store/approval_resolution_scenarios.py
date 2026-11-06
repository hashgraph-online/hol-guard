"""Approval resolution scenarios for `record_approval_resolution_vectors.py`.

Each scenario seeds `approval_requests` rows; every call runs against a fresh
copy of them, so one resolution never sees another's writes.
"""

from __future__ import annotations

from approval_read_scenarios import GROUP, SOURCE, row
from approval_resolution_sweep_scenarios import BLOCK_DECISION, HASH_A, HASH_B, SANDBOX_DECISION, seen

RESOLVED_AT = "2026-03-02T10:00:00+00:00"
OTHER_GROUP = "qg-other"


def resolution(method: str, request_id: str, **args: object) -> dict[str, object]:
    return {
        "method": method,
        "source": SOURCE,
        "args": {
            "request_id": request_id,
            "resolution_action": "allow",
            "resolution_scope": "artifact",
            "reason": f"{method} {request_id}",
            "resolved_at": RESOLVED_AT,
            **args,
        },
    }


def harness_native(request_id: str, **args: object) -> dict[str, object]:
    return {
        "method": "resolve_harness_native_approval_request",
        "source": SOURCE,
        "args": {
            "request_id": request_id,
            "reason": f"harness-native {request_id}",
            "resolved_at": RESOLVED_AT,
            "expected_harness": "codex",
            "expected_artifact_id": None,
            "expected_artifact_hash": None,
            **args,
        },
    }


def duplicates(request_id: str, queue_group_id: str | None = GROUP, source: str = SOURCE, **args: object):
    call = resolution("resolve_matching_duplicate_requests", request_id, queue_group_id=queue_group_id, **args)
    return {**call, "source": source}


SINGLE_ROWS = [
    row("r-ok", last_seen_at=seen(1)),
    row("r-block", policy_action="block", decision_v2_json=BLOCK_DECISION, last_seen_at=seen(2)),
    row("r-sandbox", policy_action="sandbox-required", decision_v2_json=SANDBOX_DECISION, last_seen_at=seen(3)),
    row("r-malformed", decision_v2_json="{bad", last_seen_at=seen(4)),
    row("r-unknown", policy_action="frobnicate", decision_v2_json=None, last_seen_at=seen(5)),
    row(
        "r-null-decision", policy_action="block", decision_v2_json=None, action_envelope_json=None, last_seen_at=seen(6)
    ),
    row("r-resolved", status="resolved", resolution_action="block", resolution_scope="global", last_seen_at=seen(7)),
    row("r-expired", status="expired", reason="superseded_by_fresh_review:r-ok", last_seen_at=seen(8)),
    row("r-claude", harness="claude", artifact_id="claude:native-pretool:tool-action:Bash", last_seen_at=seen(9)),
    row("r-hash-b", artifact_hash=HASH_B, last_seen_at=seen(10)),
    row("r-blank-harness", harness="", last_seen_at=seen(11)),
    row(
        "r-bad-columns",
        changed_fields_json="{bad",
        risk_signals_json="nope",
        scanner_evidence_json="{",
        last_seen_at=seen(12),
    ),
    row("r-surrogate", decision_v2_json='{"action": "ask", "s": "\\ud800"}', last_seen_at=seen(13)),
    row(" r-ok ", last_seen_at=seen(14)),
    row("r-nan", decision_v2_json='{"score": NaN}', last_seen_at=seen(15)),
]
SINGLE_IDS = [str(item["request_id"]) for item in SINGLE_ROWS] + ["missing", "", "r-ok "]
SINGLE_CALLS = (
    [resolution("resolve_approval_request", request_id) for request_id in SINGLE_IDS]
    + [resolution("resolve_one_request_only", request_id) for request_id in SINGLE_IDS]
    + [harness_native(request_id) for request_id in [*SINGLE_IDS, "   "]]
    + [
        resolution(
            "resolve_approval_request", "r-ok", resolution_action="block", resolution_scope="global", reason=None
        ),
        resolution(
            "resolve_one_request_only", "r-ok", resolution_action="block", resolution_scope="harness", reason=None
        ),
        harness_native("r-ok", reason=None),
        harness_native("r-ok", expected_harness="claude"),
        harness_native("r-ok", expected_harness=""),
        harness_native("r-blank-harness", expected_harness=""),
        harness_native("r-claude", expected_harness="claude"),
        harness_native(
            "r-claude", expected_harness="claude", expected_artifact_id="claude:native-pretool:tool-action:Bash"
        ),
        harness_native("r-ok", expected_artifact_id="native-review:codex:cmd"),
        harness_native("r-ok", expected_artifact_id="native-review:codex:other"),
        harness_native("r-ok", expected_artifact_id=""),
        harness_native("r-ok", expected_artifact_hash=HASH_A),
        harness_native("r-ok", expected_artifact_hash=HASH_B),
        harness_native("r-hash-b", expected_artifact_id="native-review:codex:cmd", expected_artifact_hash=HASH_B),
        harness_native("r-ok", expected_artifact_hash=""),
    ]
)
DUPLICATE_ROWS = [
    row("d-target", last_seen_at=seen(1)),
    row("d-1", last_seen_at=seen(2)),
    row("d-2", last_seen_at=seen(3)),
    row("d-tie-b", last_seen_at=seen(4)),
    row("d-tie-a", last_seen_at=seen(4)),
    row("d-no-seen", last_seen_at=None),
    row("d-block", policy_action="block", decision_v2_json=BLOCK_DECISION, last_seen_at=seen(5)),
    row("d-malformed", decision_v2_json="{bad", last_seen_at=seen(6)),
    row("d-unknown", policy_action="frobnicate", decision_v2_json=None, last_seen_at=seen(7)),
    row("d-other-source", oauth_source="other", last_seen_at=seen(8)),
    row("d-null-source", oauth_source=None, last_seen_at=seen(9)),
    row("d-default-source", oauth_source="default", last_seen_at=seen(10)),
    row("d-resolved", status="resolved", last_seen_at=seen(11)),
    row("d-expired", status="expired", last_seen_at=seen(12)),
    row("d-other-group", queue_group_id=OTHER_GROUP, last_seen_at=seen(13)),
    row("d-null-group", queue_group_id=None, last_seen_at=seen(14)),
    row("d-claude", harness="claude", last_seen_at=seen(15)),
    row("d-nan", decision_v2_json='{"score": NaN}', last_seen_at=seen(16)),
]
DUPLICATE_CALLS = [
    duplicates("d-target"),
    duplicates("d-1"),
    duplicates("missing"),
    duplicates("d-target", queue_group_id=None),
    duplicates("d-target", queue_group_id=OTHER_GROUP),
    duplicates("d-target", queue_group_id="qg-none"),
    duplicates("d-target", queue_group_id=""),
    duplicates("d-target", source="other"),
    duplicates("d-target", source="Other"),
    duplicates("d-target", source="default"),
    duplicates("d-target", resolution_action="block", resolution_scope="global", reason=None),
]
BULK_ROWS = [
    row(f"b-{index:04d}", last_seen_at=f"2026-03-01T{index // 60:02d}:{index % 60:02d}:00+00:00")
    for index in range(1100)
] + [row("b-block", policy_action="block", decision_v2_json=BLOCK_DECISION)]
BULK_CALLS = [duplicates("b-0000")]
FAILURE_ROWS = [
    row("f-target", last_seen_at=seen(1)),
    row("f-ok", last_seen_at=seen(2)),
    row("f-surrogate", decision_v2_json='{"action": "ask", "s": "\\ud800"}', last_seen_at=seen(3)),
    row("f-other", queue_group_id=OTHER_GROUP, last_seen_at=seen(4)),
]
FAILURE_CALLS = [
    duplicates("f-target"),
    duplicates("f-surrogate"),
    duplicates("f-target", queue_group_id=OTHER_GROUP),
]

SCENARIOS: list[dict[str, object]] = [
    {"name": "single", "rows": SINGLE_ROWS, "calls": SINGLE_CALLS},
    {"name": "duplicates", "rows": DUPLICATE_ROWS, "calls": DUPLICATE_CALLS},
    {"name": "bulk", "rows": BULK_ROWS, "calls": BULK_CALLS},
    {"name": "failures", "rows": FAILURE_ROWS, "calls": FAILURE_CALLS},
]
