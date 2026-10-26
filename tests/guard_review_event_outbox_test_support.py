from __future__ import annotations

import sqlite3
from typing import TypedDict

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-08-24T12:00:00+00:00"


class _DeliveryBinding(TypedDict):
    oauth_subject_hash: str
    workspace_id: str
    machine_id: str
    machine_installation_id: str


def _request(request_id: str, *, summary: str = "Review test action") -> GuardApprovalRequest:
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
        last_seen_at=_NOW,
    )


def _connect(
    store: GuardStore,
    *,
    grant_id: str = "grant-1",
    workspace_id: str = "workspace-1",
    machine_id: str = "machine-1",
) -> _DeliveryBinding:
    state_key = (
        "oauth_local_credentials"
        if store.guard_source == "default"
        else f"oauth_local_credentials:{store.guard_source}"
    )
    store.set_sync_payload(
        state_key,
        {"grant_id": grant_id, "workspace_id": workspace_id, "machine_id": machine_id},
        _NOW,
    )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    return {
        "oauth_subject_hash": binding["oauth_subject_hash"],
        "workspace_id": binding["workspace_id"],
        "machine_id": binding["machine_id"],
        "machine_installation_id": binding["machine_installation_id"],
    }


def _all_events(store: GuardStore) -> list[sqlite3.Row]:
    with store._connect() as connection:
        return connection.execute("select * from guard_review_outbox_events order by stream_sequence").fetchall()


def as_int(value: object) -> int:
    assert isinstance(value, int)
    return value
