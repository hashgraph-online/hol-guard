"""Queue-result resolution scenarios for `record_approval_queue_result_vectors.py`.

Each scenario seeds `approval_requests` rows and `sync_state` entries; every
call runs against a fresh copy of them, so one resolution never sees another's
writes. Workspace-review calls name their expected request snapshot as
`"current"` (the request as the store reads it before the call) or `"stale"`
(that request with one field changed).
"""

from __future__ import annotations

import json

from approval_read_scenarios import SOURCE, row
from approval_resolution_scenarios import (
    DUPLICATE_ROWS,
    FAILURE_ROWS,
    OTHER_GROUP,
    RESOLVED_AT,
    SINGLE_IDS,
    SINGLE_ROWS,
)
from approval_resolution_sweep_scenarios import BLOCK_DECISION, seen

REVOCATION_KEY = "guard_exact_cloud_review_revocation"
RECEIPT_PREFIX = "native_workspace_review.receipt:"
BINDINGS = (
    "claim_id",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "scope_binding",
    "request_binding",
    "action_binding",
    "intent_binding",
    "revision_binding",
    "policy_binding",
    "retry_scope_binding",
    "request_snapshot_digest",
)


def queue(request_id: str, source: str = SOURCE, **args: object) -> dict[str, object]:
    return {
        "method": "resolve_request_with_queue_result",
        "source": source,
        "args": {
            "request_id": request_id,
            "resolution_action": "allow",
            "resolution_scope": "artifact",
            "reason": f"queue {request_id}",
            "resolved_at": RESOLVED_AT,
            **args,
        },
    }


def receipt(request_id: str, *, decision: str = "allow", replayed: bool = False, digit: str = "a") -> dict[str, object]:
    fields: dict[str, object] = {name: digit * 64 for name in (*BINDINGS, "envelope_digest", "authority_record_digest")}
    return {
        **fields,
        "request_id": request_id,
        "decision": decision,
        "status": "replayed" if replayed else "verified",
        "replayed": replayed,
    }


def review(
    request_id: str,
    *,
    action: str = "allow",
    expected: str = "current",
    replayed: bool = False,
    with_receipt: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "method": "resolve_native_workspace_review_request",
        "source": SOURCE,
        "args": {
            "request_id": request_id,
            "resolution_action": action,
            "expected_request": expected,
            "resolved_at": RESOLVED_AT,
            "native_replayed": replayed,
            "native_receipt": with_receipt,
        },
    }


def grouped(request_id: str, **overrides: object) -> dict[str, object]:
    return row(request_id, queue_group_id=f"g-{request_id}", **overrides)


SINGLE_CALLS = [queue(request_id) for request_id in SINGLE_IDS] + [
    queue("r-ok", resolution_action="block", resolution_scope="global", reason=None),
    queue("r-ok", source="other"),
]
# Without the rows the resident cannot project, so the remaining-queue
# summaries read and every resolution path is reachable.
PROJECTABLE_ROWS = [item for item in SINGLE_ROWS if item["request_id"] not in {"r-surrogate", "r-nan"}]
DUPLICATE_CALLS = [
    queue(request_id)
    for request_id in (
        "d-target",
        "d-1",
        "d-tie-a",
        "d-no-seen",
        "d-block",
        "d-malformed",
        "d-other-source",
        "d-null-source",
        "d-default-source",
        "d-resolved",
        "d-expired",
        "d-other-group",
        "d-null-group",
        "d-claude",
        "d-nan",
        "missing",
    )
] + [
    queue("d-target", source="other"),
    queue("d-target", resolution_action="block", resolution_scope="global", reason=None),
]
FAILURE_CALLS = [queue("f-target"), queue("f-surrogate"), queue("f-other")]
REMAINING = [
    {
        "name": f"remaining-{count}",
        "rows": [grouped(f"q-{index}", last_seen_at=seen(index)) for index in range(count + 1)],
    }
    for count in (0, 1, 2)
]
REVIEW_ROWS = [
    row("w-ok", last_seen_at=seen(1)),
    row("w-dup", last_seen_at=seen(2)),
    grouped("w-solo", last_seen_at=seen(3)),
    grouped(
        "w-allowed",
        status="resolved",
        resolution_action="allow",
        resolution_scope="artifact",
        resolved_at=RESOLVED_AT,
        last_seen_at=seen(4),
    ),
    grouped(
        "w-global",
        status="resolved",
        resolution_action="allow",
        resolution_scope="global",
        resolved_at=RESOLVED_AT,
        last_seen_at=seen(5),
    ),
    grouped("w-expired", status="expired", last_seen_at=seen(6)),
    grouped("w-block", policy_action="block", decision_v2_json=BLOCK_DECISION, last_seen_at=seen(7)),
    grouped("w-malformed", decision_v2_json="{bad", last_seen_at=seen(8)),
    row("w-other", queue_group_id=OTHER_GROUP, last_seen_at=seen(9)),
]
REVIEW_CALLS = [
    review("w-ok"),
    review("w-ok", action="block"),
    review("w-ok", with_receipt=receipt("w-ok")),
    review("w-ok", action="block", with_receipt=receipt("w-ok", decision="deny")),
    review("w-ok", expected="stale"),
    review("w-solo", replayed=True),
    review("w-solo", with_receipt=receipt("w-solo")),
    review("w-dup"),
    review("missing"),
    review("w-allowed"),
    review("w-allowed", action="block"),
    review("w-allowed", with_receipt=receipt("w-allowed")),
    review("w-allowed", replayed=True, with_receipt=receipt("w-allowed", replayed=True)),
    review("w-allowed", replayed=True, with_receipt=receipt("w-allowed", replayed=True, digit="b")),
    review("w-global"),
    review("w-expired"),
    review("w-block"),
    review("w-malformed"),
]
REVIEW_STATE = [
    [RECEIPT_PREFIX + "w-allowed", '{"decision":"allow","claim_id":"' + "a" * 64 + '"}', RESOLVED_AT],
]
RECEIPT_STATES = {
    "matching": [
        [
            RECEIPT_PREFIX + "w-allowed",
            json.dumps(receipt("w-allowed"), sort_keys=True, separators=(",", ":")),
            RESOLVED_AT,
        ]
    ],
    "unreadable": [[RECEIPT_PREFIX + "w-allowed", "{bad", RESOLVED_AT]],
    "not-an-object": [[RECEIPT_PREFIX + "w-allowed", "[1]", RESOLVED_AT]],
    "partial": REVIEW_STATE,
}
RECEIPT_CALLS = [
    review("w-allowed", replayed=True, with_receipt=receipt("w-allowed", replayed=True)),
    review("w-allowed", replayed=True, with_receipt=receipt("w-allowed", replayed=True, digit="b")),
    review("w-allowed", with_receipt=receipt("w-allowed")),
    review(
        "w-allowed", action="block", replayed=True, with_receipt=receipt("w-allowed", decision="deny", replayed=True)
    ),
    review("w-ok", with_receipt=receipt("w-ok")),
]

SCENARIOS: list[dict[str, object]] = [
    {"name": "single", "rows": SINGLE_ROWS, "calls": SINGLE_CALLS},
    {"name": "single-projectable", "rows": PROJECTABLE_ROWS, "calls": SINGLE_CALLS},
    {"name": "duplicates", "rows": DUPLICATE_ROWS, "calls": DUPLICATE_CALLS},
    {"name": "failures", "rows": FAILURE_ROWS, "calls": FAILURE_CALLS},
    *({**scenario, "calls": [queue("q-0")]} for scenario in REMAINING),
    {"name": "review", "rows": REVIEW_ROWS, "calls": REVIEW_CALLS},
    *(
        {"name": f"review-receipt-{name}", "rows": REVIEW_ROWS, "sync_state": state, "calls": RECEIPT_CALLS}
        for name, state in RECEIPT_STATES.items()
    ),
    {
        "name": "review-revoked",
        "rows": REVIEW_ROWS,
        "sync_state": [[REVOCATION_KEY, "{}", RESOLVED_AT]],
        "calls": [review("w-ok"), review("w-allowed"), review("missing")],
    },
]
