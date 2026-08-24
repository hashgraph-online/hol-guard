from __future__ import annotations

import json
import sqlite3
from typing import TypedDict

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_event_integrity import review_event_payload_digest
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-08-24T14:00:00+00:00"


class Binding(TypedDict):
    oauth_subject_hash: str
    workspace_id: str
    machine_id: str
    machine_installation_id: str


def review_request(request_id: str, *, summary: str = "Review action") -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Test action",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/test/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        action_identity=request_id,
        queue_group_id=request_id,
        trigger_summary=summary,
        last_seen_at=NOW,
    )


def connect_store(store: GuardStore) -> Binding:
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "grant-1", "workspace_id": "workspace-1", "machine_id": "machine-1"},
        NOW,
    )
    binding = store.get_live_request_oauth_binding()
    assert binding is not None
    return {
        "oauth_subject_hash": binding["oauth_subject_hash"],
        "workspace_id": binding["workspace_id"],
        "machine_id": binding["machine_id"],
        "machine_installation_id": binding["machine_installation_id"],
    }


def auth_context(binding: Binding) -> dict[str, object]:
    return {"oauth_source": "default", **binding}


def event_row(store: GuardStore) -> sqlite3.Row:
    with store._connect() as connection:
        row = connection.execute("select * from guard_review_outbox_events").fetchone()
    assert row is not None
    return row


def replace_event_payload(store: GuardStore, row: sqlite3.Row, payload: dict[str, object]) -> None:
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    with store._connect() as connection:
        connection.execute(
            """
            update guard_review_outbox_events set payload_json = ?, payload_hash = ?
            where stream_sequence = ?
            """,
            (
                payload_json,
                review_event_payload_digest(
                    payload_json,
                    oauth_source=row["oauth_source"],
                    oauth_subject_hash=row["oauth_subject_hash"],
                    workspace_id=row["workspace_id"],
                    machine_id=row["machine_id"],
                    machine_installation_id=row["machine_installation_id"],
                ),
                row["stream_sequence"],
            ),
        )


def as_int(value: object) -> int:
    assert isinstance(value, int)
    return value
