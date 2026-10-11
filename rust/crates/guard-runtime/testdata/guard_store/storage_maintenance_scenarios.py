"""Scenario definitions for the storage-maintenance vector recorder.

Each scenario seeds real Guard tables, then runs a list of steps against the
ORIGINAL Python `maintain_storage` (or applies raw SQL). Row ids ascend in
insertion order so SQLite rowids match across the Python-built and the
Rust-built databases; timestamps are deliberately not monotone in id order.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
SOURCE = "guard"


def ago(days: float) -> str:
    return (NOW - timedelta(days=days)).isoformat()


def receipt(connection: sqlite3.Connection, receipt_id: str, timestamp: str, approval: str | None = None) -> None:
    connection.execute(
        "insert into runtime_receipts (receipt_id, harness, artifact_id, artifact_hash, policy_decision, "
        "changed_capabilities_json, provenance_summary, timestamp, approval_request_id) "
        "values (?, 'pi', ?, ?, 'allow', '[]', '', ?, ?)",
        (receipt_id, f"artifact-{receipt_id}", f"hash-{receipt_id}", timestamp, approval),
    )
    connection.execute(
        "insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json) "
        'values (?, \'{"action":"allow"}\', \'{"action":"allow"}\')',
        (receipt_id,),
    )
    connection.execute("update receipt_rollup_actions set dirty = 0 where receipt_id = ?", (receipt_id,))


def cloud(
    connection: sqlite3.Connection,
    event_id: str,
    key: str,
    occurred_at: str,
    uploaded_at: str | None,
    payload: str = "{}",
) -> None:
    connection.execute(
        "insert into guard_cloud_events (event_id, idempotency_key, event_type, payload_json, occurred_at, "
        "uploaded_at) values (?, ?, 'receipt.created', ?, ?, ?)",
        (event_id, key, payload, occurred_at, uploaded_at),
    )


def approval(connection: sqlite3.Connection, request_id: str, status: str) -> None:
    connection.execute(
        "insert into approval_requests (request_id, harness, artifact_id, artifact_name, artifact_type, "
        "artifact_hash, policy_action, recommended_scope, changed_fields_json, source_scope, config_path, "
        "review_command, approval_url, status, created_at) "
        "values (?, 'pi', 'a', 'a', 'mcp_server', 'h', 'require-reapproval', 'artifact', '[]', 'project', "
        "'/tmp/c.json', 'hol-guard approvals approve', 'http://localhost', ?, ?)",
        (request_id, status, ago(1)),
    )


def native_receipt(connection: sqlite3.Connection, table: str, decision_id: str, recorded_at: str) -> None:
    prompt = table == "native_prompt_decision_receipts"
    connection.execute(
        f"insert into {table} (decision_id, schema, version, authority, request_id, request_digest, harness, "
        f"event_name, payload_kind, policy_generation, decision, model_output_action, reason_code, "
        f"workspace_bound, source_ref_external_allowed, observe_mode, "
        f"{'prompt_risk_classes_json, ' if prompt else ''}recorded_at) "
        f"values (?, 'guard-native-hook-decision-receipt.v1', 1, 'rust', ?, 'sha256:x', 'pi', ?, 'tool', 1, "
        f"'allow', 'allow', 'ok', 0, 0, 0, {'?, ' if prompt else ''}?)",
        (
            decision_id,
            f"req-{decision_id}",
            "UserPromptSubmit" if prompt else "PreToolUse",
            *(("[]",) if prompt else ()),
            recorded_at,
        ),
    )


def event(connection: sqlite3.Connection, occurred_at: str) -> int:
    cursor = connection.execute(
        "insert into guard_events (event_name, payload_json, occurred_at) values ('e', '{}', ?)", (occurred_at,)
    )
    return int(cursor.lastrowid or 0)


def capability(connection: sqlite3.Connection, capability_id: str) -> None:
    connection.execute(
        "insert into guard_workflow_capabilities (capability_id, approval_provenance_id, nonce, signed_claim_json, "
        "key_id, issued_at, not_before, expires_at, max_uses) values (?, 'p', ?, '{}', 'k', ?, ?, ?, 5)",
        (capability_id, f"nonce-{capability_id}", ago(300), ago(300), ago(-30)),
    )


def workflow_receipt(connection: sqlite3.Connection, receipt_id: str, capability_id: str, event_id: int) -> None:
    connection.execute(
        "insert into guard_workflow_capability_receipts (receipt_id, capability_id, task_id, invocation_id, "
        "approval_provenance_id, signed_receipt_json, claimed_at, use_number, event_id) "
        "values (?, ?, 't', ?, 'p', '{}', ?, 1, ?)",
        (receipt_id, capability_id, f"inv-{receipt_id}", ago(250), event_id),
    )


def transition(connection: sqlite3.Connection, sequence: int, capability_id: str, event_id: int) -> None:
    connection.execute(
        "insert into guard_workflow_capability_authority_transitions (sequence, capability_id, revision, "
        "transition_kind, previous_transition_sha256, signed_transition_json, key_id, event_id) "
        "values (?, ?, 0, 'issued', '', '{}', 'k', ?)",
        (sequence, capability_id, event_id),
    )


def _receipts_age(connection: sqlite3.Connection) -> None:
    approval(connection, "ap-done", "approved")
    approval(connection, "ap-pending", "pending")
    spec = [
        ("r00", 150, None),
        ("r01", 190, None),
        ("r02", 170, "ap-done"),
        ("r03", 160, "ap-pending"),
        ("r04", 180, None),
        ("r05", 2, None),
        ("r06", 1, None),
        ("r07", 3, None),
    ]
    for receipt_id, days, approval_id in spec:
        receipt(connection, receipt_id, ago(days), approval_id)
    uploaded = ago(100)
    cloud(connection, "c00", "receipt.created:r00", ago(150), uploaded)
    cloud(connection, "c01", "receipt.created:r01", ago(190), None)
    cloud(connection, "c02", "receipt.created:r02", ago(170), uploaded)
    cloud(connection, "c04", "receipt.created:r04", ago(180), uploaded)
    cloud(connection, "c05", "receipt.created:r05", ago(2), uploaded)


def _receipts_limit(connection: sqlite3.Connection) -> None:
    for index, days in enumerate((5, 1, 4, 2, 6, 3)):
        receipt(connection, f"r{index:02d}", ago(days))
        cloud(connection, f"c{index:02d}", f"receipt.created:r{index:02d}", ago(days), ago(days))


def _native_receipts(connection: sqlite3.Connection) -> None:
    for index, days in enumerate((200, 150, 3, 180, 170, 1)):
        native_receipt(connection, "native_hook_decision_receipts", f"h{index:02d}", ago(days))
    for index, days in enumerate((160, 210, 190, 2, 140, 175)):
        native_receipt(connection, "native_prompt_decision_receipts", f"p{index:02d}", ago(days))


def _guard_events(connection: sqlite3.Connection) -> None:
    capability(connection, "cap-1")
    ids = [event(connection, ago(days)) for days in (200, 190, 180, 170, 2, 3, 2, 1)]
    workflow_receipt(connection, "wr-1", "cap-1", ids[1])
    transition(connection, 1, "cap-1", ids[3])


def _cloud_uploaded(connection: sqlite3.Connection) -> None:
    uploads = (30, 2, 20, 9, 25, 1, 15, 40, 12, 3)
    for index, days in enumerate(uploads):
        cloud(connection, f"c{index:02d}", f"key-{index:02d}", ago(days + 1), ago(days))
    cloud(connection, "c10", "key-10", ago(300), None)
    cloud(connection, "c11", "key-11", ago(250), None)


def _mixed(connection: sqlite3.Connection) -> None:
    _receipts_age(connection)
    _native_receipts(connection)
    _guard_events(connection)
    for index, days in enumerate((30, 2, 20)):
        cloud(connection, f"u{index:02d}", f"u-key-{index:02d}", ago(days + 1), ago(days))


def _freelist(connection: sqlite3.Connection) -> None:
    payload = "x" * 20_000
    for index in range(12):
        cloud(connection, f"c{index:02d}", f"key-{index:02d}", ago(50), ago(40), payload)


def _empty(connection: sqlite3.Connection) -> None:
    del connection


def maintain(label: str, **kwargs: object) -> dict[str, object]:
    return {"label": label, "maintain": kwargs}


def sql(label: str, *statements: tuple[str, tuple[object, ...]]) -> dict[str, object]:
    return {"label": label, "sql": list(statements)}


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "empty_store",
        "seed": _empty,
        "steps": [maintain("defaults"), maintain("again", detail_retain_days=1)],
    },
    {
        "name": "receipts_age_and_protection",
        "seed": _receipts_age,
        "steps": [
            maintain("batch two", detail_retain_days=30, batch_size=2),
            maintain("batch two again", detail_retain_days=30, batch_size=2),
            maintain("batch five", detail_retain_days=30, batch_size=5),
        ],
    },
    {
        "name": "receipts_detail_limit_boundary",
        "seed": _receipts_limit,
        "steps": [
            maintain("limit two", detail_retain_days=30, batch_size=3, receipt_detail_limit=2),
            maintain("limit two again", detail_retain_days=30, batch_size=3, receipt_detail_limit=2),
            maintain("limit one", detail_retain_days=30, batch_size=3, receipt_detail_limit=1),
        ],
    },
    {
        "name": "native_decision_receipt_budgets",
        "seed": _native_receipts,
        "steps": [
            maintain("batch four", detail_retain_days=30, batch_size=4),
            maintain("batch four again", detail_retain_days=30, batch_size=4),
            maintain("batch four drained", detail_retain_days=30, batch_size=4),
        ],
    },
    {
        "name": "native_decision_receipt_single_batch",
        "seed": _native_receipts,
        "steps": [
            maintain("batch one", detail_retain_days=30, batch_size=1),
            maintain("batch one again", detail_retain_days=30, batch_size=1),
            maintain("limit two", detail_retain_days=500, batch_size=3, receipt_detail_limit=2),
        ],
    },
    {
        "name": "guard_events_protection_and_limit",
        "seed": _guard_events,
        "steps": [
            maintain("batch one", detail_retain_days=30, batch_size=1),
            maintain("event limit", detail_retain_days=500, batch_size=10, guard_event_limit=3),
            maintain("batch ten", detail_retain_days=30, batch_size=10),
        ],
    },
    {
        "name": "uploaded_cloud_events",
        "seed": _cloud_uploaded,
        "steps": [
            maintain("batch three", detail_retain_days=30, batch_size=3),
            maintain("batch three again", detail_retain_days=30, batch_size=3),
            maintain("cloud limit", detail_retain_days=30, batch_size=3, uploaded_cloud_event_limit=2),
            maintain("drain", detail_retain_days=30, batch_size=50, uploaded_cloud_event_limit=1),
        ],
    },
    {
        "name": "mixed_defaults",
        "seed": _mixed,
        "steps": [maintain("defaults", detail_retain_days=30), maintain("defaults again", detail_retain_days=30)],
    },
    {
        "name": "incremental_vacuum_reclaims_free_pages",
        "seed": _freelist,
        "auto_vacuum": 2,
        "page_dependent": True,
        "steps": [
            maintain("delete twelve", detail_retain_days=30, batch_size=12),
            maintain("reclaim ten", detail_retain_days=30, batch_size=10),
            maintain("reclaim all", detail_retain_days=30, batch_size=500),
        ],
    },
    {
        "name": "no_auto_vacuum_reclaims_nothing",
        "seed": _freelist,
        "auto_vacuum": 0,
        "page_dependent": True,
        "steps": [maintain("delete twelve", detail_retain_days=30, batch_size=12)],
    },
]
