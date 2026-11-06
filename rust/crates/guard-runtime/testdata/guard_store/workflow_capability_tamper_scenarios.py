"""Tamper, rollback and control-blob scenarios for the workflow-capability vectors.

`sql` steps carry a callable run against a recording connection; `blob` steps
carry a callable `(ctx) -> str | None` that rewrites the external control blob.
The recorder turns both into literal statements/values in the vectors.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from workflow_capability_factories import autotime, claim, claim_step, issue, lookup, receipt_lookup, revoke, signed

LAST = "@last_receipt"
_COMPACT = {"sort_keys": True, "separators": (",", ":")}


def sqlfn(label: str, fn: Callable[[Any], None]) -> dict[str, object]:
    return {"op": "sql", "label": label, "fn": fn}


def blobfn(label: str, fn: Callable[[Any], str | None]) -> dict[str, object]:
    return {"op": "blob", "label": label, "fn": fn}


def run(label: str, *statements: str) -> dict[str, object]:
    return sqlfn(label, lambda conn: [conn.execute(statement) for statement in statements])


def marked(step: dict[str, object], name: str = "good") -> dict[str, object]:
    return {**step, "mark": name}


def _state_capture(store: dict[str, object]) -> Callable[[Any], None]:
    def capture(conn: Any) -> None:
        store["prior"] = conn.query("select * from guard_workflow_capability_authority_state")[0]

    return capture


def _state_restore(store: dict[str, object]) -> Callable[[Any], None]:
    def restore(conn: Any) -> None:
        prior = store["prior"]
        conn.execute(
            "update guard_workflow_capability_authority_state set signed_state_json = ?, key_id = ?, "
            "revision = ?, use_high_water = ?, observed_at = ?, revocation_id = ?",
            tuple(prior[1:7]),  # type: ignore[index]
        )

    return restore


def _edit_blob(**changes: object) -> Callable[[Any], str | None]:
    def edit(ctx: Any) -> str | None:
        control = json.loads(ctx.marks["good"])
        control.update(changes)
        return json.dumps(control, **_COMPACT)

    return edit


def _pending_forward(ctx: Any) -> str | None:
    control = json.loads(ctx.marks["good"])
    control.update(
        committed_sequence=1,
        committed_head_sha256=ctx.transition_hash(1),
        pending_sequence=2,
        pending_head_sha256=control["committed_head_sha256"],
    )
    return json.dumps(control, **_COMPACT)


def _tampered_receipts() -> dict[str, object]:
    return {
        "name": "receipt_tamper",
        "steps": [
            issue("wc-receipt"),
            claim_step("wc-receipt", invocation_id="invocation-lookup"),
            receipt_lookup(receipt_id=LAST),
            run("drop receipt update trigger", "drop trigger trg_guard_workflow_receipt_immutable_update"),
            run("tamper invocation id", "update guard_workflow_capability_receipts set invocation_id = 'invocation-row-tampered'"),
            receipt_lookup(invocation_id="invocation-row-tampered"),
            run("restore invocation id", "update guard_workflow_capability_receipts set invocation_id = 'invocation-lookup'"),
            run(
                "rewrite claimed event",
                "update guard_events set payload_json = '{\"tampered\":true}' where event_name = 'workflow_capability.claimed'",
            ),
            receipt_lookup(receipt_id=LAST),
            lookup("wc-receipt"),
        ],
    }


def _noncanonical_receipt() -> dict[str, object]:
    return {
        "name": "receipt_noncanonical_json",
        "steps": [
            issue("wc-noncanon"),
            claim_step("wc-noncanon", invocation_id="invocation-noncanonical"),
            run("drop receipt update trigger", "drop trigger trg_guard_workflow_receipt_immutable_update"),
            run("append whitespace", "update guard_workflow_capability_receipts set signed_receipt_json = signed_receipt_json || ' '"),
            receipt_lookup(receipt_id=LAST),
        ],
    }


def _forged_history() -> dict[str, object]:
    forged = (
        "insert into guard_workflow_capability_receipts (receipt_id, capability_id, task_id, invocation_id, "
        "approval_provenance_id, signed_receipt_json, claimed_at, use_number, event_id) "
        "select 'wcr-forged', 'wc-forged', 'task-local-check', 'invocation-forged', 'provenance-wc-forged', "
        "'{}', '2026-07-19T12:01:00.000000Z', 2, max(event_id) from guard_events"
    )
    return {
        "name": "forged_receipt_history",
        "steps": [
            issue("wc-forged", max_uses=3),
            claim_step("wc-forged", invocation_id="invocation-legitimate", max_uses=3),
            run(
                "insert forged event",
                "insert into guard_events (event_name, payload_json, occurred_at) "
                "values ('workflow_capability.claimed', '{}', '2026-07-19T12:01:00.000000Z')",
            ),
            run("insert forged receipt", forged),
            lookup("wc-forged"),
            receipt_lookup(receipt_id=LAST),
            claim_step("wc-forged", invocation_id="invocation-real", max_uses=3),
        ],
    }


def _state_rollbacks() -> list[dict[str, object]]:
    counter: dict[str, object] = {}
    combined: dict[str, object] = {}
    revoked: dict[str, object] = {}
    history: dict[str, object] = {}
    return [
        {
            "name": "use_counter_reset",
            "steps": [
                issue("wc-use-reset"),
                claim_step("wc-use-reset", invocation_id="invocation-first"),
                run("reset use counter", "update guard_workflow_capabilities set used_count = 0"),
                claim_step("wc-use-reset", invocation_id="invocation-revived"),
            ],
        },
        {
            "name": "revocation_reset",
            "steps": [
                issue("wc-revocation-reset"),
                revoke("wc-revocation-reset"),
                run("clear revocation", "update guard_workflow_capabilities set revoked_at = null, revocation_code = null"),
                claim_step("wc-revocation-reset", invocation_id="invocation-revived"),
            ],
        },
        {
            "name": "state_revision_tamper",
            "steps": [
                issue("wc-state-tamper"),
                run("bump revision", "update guard_workflow_capability_authority_state set revision = revision + 1"),
                claim_step("wc-state-tamper", invocation_id="invocation-state-tamper"),
            ],
        },
        {
            "name": "prior_state_restore",
            "steps": [
                issue("wc-state-rollback", max_uses=2),
                sqlfn("capture prior state", _state_capture(counter)),
                claim_step("wc-state-rollback", invocation_id="invocation-first", max_uses=2),
                sqlfn("restore prior state", _state_restore(counter)),
                claim_step("wc-state-rollback", invocation_id="invocation-second", max_uses=2),
            ],
        },
        {
            "name": "receipt_counter_and_state_rollback",
            "steps": [
                issue("wc-combined"),
                sqlfn("capture prior state", _state_capture(combined)),
                claim_step("wc-combined", invocation_id="invocation-first"),
                run(
                    "roll back receipts and counter",
                    "drop trigger trg_guard_workflow_receipt_immutable_delete",
                    "delete from guard_workflow_capability_receipts",
                    "update guard_workflow_capabilities set used_count = 0",
                ),
                sqlfn("restore prior state", _state_restore(combined)),
                claim_step("wc-combined", invocation_id="invocation-second"),
            ],
        },
        {
            "name": "revocation_evidence_rollback",
            "steps": [
                issue("wc-revocation-rollback"),
                sqlfn("capture prior state", _state_capture(revoked)),
                revoke("wc-revocation-rollback"),
                run(
                    "roll back revocation",
                    "drop trigger trg_guard_workflow_revocation_immutable_delete",
                    "delete from guard_workflow_capability_revocations",
                    "update guard_workflow_capabilities set revoked_at = null, revocation_code = null",
                ),
                sqlfn("restore prior state", _state_restore(revoked)),
                claim_step("wc-revocation-rollback", invocation_id="invocation-after-revoke"),
            ],
        },
        {
            "name": "whole_history_rollback",
            "steps": [
                issue("wc-whole-history"),
                sqlfn("capture prior state", _state_capture(history)),
                claim_step("wc-whole-history", invocation_id="invocation-first"),
                run(
                    "delete second transition and receipt",
                    "drop trigger trg_guard_workflow_transition_immutable_delete",
                    "drop trigger trg_guard_workflow_receipt_immutable_delete",
                    "drop trigger trg_guard_workflow_event_preserve_link",
                    "delete from guard_workflow_capability_authority_transitions where sequence = 2",
                    "delete from guard_workflow_capability_receipts",
                    "delete from guard_events where event_name = 'workflow_capability.claimed'",
                    "update guard_workflow_capabilities set used_count = 0",
                ),
                sqlfn("restore prior state", _state_restore(history)),
                claim_step("wc-whole-history", invocation_id="invocation-second"),
            ],
        },
    ]


def _event_scenarios() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for suffix in ("issued", "revoked"):
        name = f"workflow_capability.{suffix}"
        prefix = [issue(f"wc-event-{suffix}")] + ([revoke(f"wc-event-{suffix}")] if suffix == "revoked" else [])
        out.append(
            {
                "name": f"event_rewrite_{suffix}",
                "steps": [
                    *prefix,
                    run("rewrite event", f"update guard_events set payload_json = '{{}}' where event_name = '{name}'"),
                    lookup(f"wc-event-{suffix}"),
                ],
            }
        )
        out.append(
            {
                "name": f"event_delete_{suffix}",
                "steps": [
                    *prefix,
                    run(
                        "delete event",
                        "drop trigger trg_guard_workflow_event_preserve_link",
                        f"delete from guard_events where event_name = '{name}'",
                    ),
                    lookup(f"wc-event-{suffix}"),
                ],
            }
        )
    return out


def _schema_scenarios() -> list[dict[str, object]]:
    trigger_swap = (
        "create trigger trg_guard_workflow_revocation_immutable_delete "
        "before delete on guard_workflow_capability_revocations begin select 1; end"
    )
    return [
        {
            "name": "schema_trigger_tamper",
            "steps": [
                issue("wc-schema", max_uses=2),
                claim_step("wc-schema", invocation_id="invocation-before", max_uses=2),
                run("swap trigger", "drop trigger trg_guard_workflow_revocation_immutable_delete", trigger_swap),
                lookup("wc-schema"),
                receipt_lookup(receipt_id=LAST),
                claim_step("wc-schema", invocation_id="invocation-after", max_uses=2),
                revoke("wc-schema"),
            ],
        },
        {
            "name": "schema_legacy_index_reaped",
            "steps": [
                issue("wc-legacy-index", max_uses=2),
                run(
                    "recreate retired index",
                    "drop index if exists idx_guard_workflow_receipt_event",
                    "create index idx_guard_workflow_receipt_event on guard_workflow_capability_receipts (event_id)",
                ),
                lookup("wc-legacy-index"),
                claim_step("wc-legacy-index", invocation_id="invocation-after", max_uses=2),
            ],
        },
        {
            "name": "schema_extra_object",
            "steps": [
                issue("wc-extra"),
                run("add hostile index", "create index idx_guard_workflow_hostile on guard_workflow_capabilities (key_id)"),
                lookup("wc-extra"),
                claim_step("wc-extra", invocation_id="invocation-extra"),
            ],
        },
    ]


def _control_scenarios() -> list[dict[str, object]]:
    return [
        {
            "name": "control_missing_blob",
            "steps": [
                lookup("wc-control", now=1),
                claim_step("wc-control", invocation_id="invocation-none", now=1),
                revoke("wc-control", now=1),
                issue("wc-control", now=2),
                marked(claim_step("wc-control", invocation_id="invocation-1", now=3)),
                blobfn("drop blob", lambda ctx: None),
                lookup("wc-control", now=4),
                claim_step("wc-control", invocation_id="invocation-2", now=4),
                issue("wc-control-2", now=4),
                blobfn("restore blob", lambda ctx: ctx.marks["good"]),
                lookup("wc-control", now=5),
            ],
        },
        {
            "name": "control_pending_forward",
            "steps": [
                issue("wc-pending", max_uses=2),
                marked(claim_step("wc-pending", invocation_id="invocation-first", max_uses=2)),
                blobfn("pending forward", _pending_forward),
                lookup("wc-pending"),
                claim_step("wc-pending", invocation_id="invocation-second", max_uses=2),
            ],
        },
        {
            "name": "control_pending_unresolved",
            "steps": [
                marked(issue("wc-pending-old")),
                blobfn("pending ahead of database", _edit_blob(pending_sequence=2, pending_head_sha256="f" * 64)),
                lookup("wc-pending-old"),
                claim_step("wc-pending-old", invocation_id="invocation-1"),
            ],
        },
        {
            "name": "control_rollback_and_invalid",
            "steps": [
                issue("wc-ctl", max_uses=2),
                marked(claim_step("wc-ctl", invocation_id="invocation-1", max_uses=2)),
                blobfn("committed behind database", _edit_blob(committed_sequence=1, committed_head_sha256="a" * 64)),
                lookup("wc-ctl"),
                blobfn("not json", lambda ctx: "{not json"),
                lookup("wc-ctl"),
                blobfn("wrong version", _edit_blob(version=2)),
                lookup("wc-ctl"),
                blobfn("bad digest", _edit_blob(committed_head_sha256="ABC")),
                lookup("wc-ctl"),
                blobfn("bad pending pair", _edit_blob(pending_sequence=3)),
                lookup("wc-ctl"),
                blobfn("bad observed_at", _edit_blob(observed_at="yesterday")),
                lookup("wc-ctl"),
                blobfn("extra field", _edit_blob(extra=1)),
                lookup("wc-ctl"),
                blobfn("noncanonical encoding", lambda ctx: json.dumps(json.loads(ctx.marks["good"]), sort_keys=True)),
                lookup("wc-ctl"),
            ],
        },
        {
            "name": "control_faults",
            "steps": [
                {**issue("wc-fault-final", now=1), "fault": "fail_store_3"},
                lookup("wc-fault-final", now=2),
                {**issue("wc-fault-precommit", now=3), "fault": "fail_store_2"},
                lookup("wc-fault-precommit", now=4),
            ],
        },
        {
            "name": "control_unavailable_store_and_key",
            "steps": [
                {**issue("wc-store-down", now=1), "fault": "fail_store_1"},
                lookup("wc-store-down", now=2),
                {**issue("wc-no-key", now=3), "fault": "no_key"},
                {**lookup("wc-no-key", now=3), "fault": "no_key"},
                {**revoke("wc-no-key", now=3), "fault": "no_key"},
                {**claim_step("wc-no-key", invocation_id="invocation-none", now=3), "fault": "no_key"},
            ],
        },
    ]


def _argument_validation() -> dict[str, object]:
    return {
        "name": "argument_validation",
        "steps": [
            issue("wc-args"),
            lookup("bad id with spaces"),
            lookup("x" * 200),
            receipt_lookup(),
            receipt_lookup(receipt_id="wcr-1", invocation_id="invocation-1"),
            receipt_lookup(receipt_id="bad id"),
            receipt_lookup(invocation_id="bad id"),
            claim_step("bad id", invocation_id="invocation-1"),
            claim_step("wc-args", invocation_id="bad id"),
            claim_step("wc-args", invocation_id="invocation-1", expected_subject_id="bad id"),
            revoke("bad id"),
            revoke("wc-args", reason_code="Bad Reason"),
            lookup("wc-args"),
        ],
    }


SCENARIOS: list[dict[str, object]] = [
    _argument_validation(),
    *_state_rollbacks(),
    _tampered_receipts(),
    _noncanonical_receipt(),
    _forged_history(),
    *_event_scenarios(),
    *_schema_scenarios(),
    *_control_scenarios(),
]

_EXPLICIT_TIME = {"control_missing_blob", "control_faults", "control_unavailable_store_and_key"}
SCENARIOS = [scenario if scenario["name"] in _EXPLICIT_TIME else autotime(scenario) for scenario in SCENARIOS]
