"""Local approval persistence when Cloud Review binding tables are absent."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

_SAVED_AT = "2026-10-05T12:00:00Z"


def _request(request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="claude-code",
        artifact_id="claude:project:read",
        artifact_name="Read",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/approvals/{request_id}",
    )


def test_missing_sync_state_keeps_the_local_approval(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with store._connect() as connection:
        connection.execute("drop table sync_state")

    request_id = "req-missing-sync-state"
    assert store.add_approval_request(_request(request_id), _SAVED_AT) == request_id

    saved = store.get_approval_request(request_id)
    assert saved is not None
    assert saved["status"] == "pending"
    assert saved["harness"] == "claude-code"


def test_missing_guard_device_table_keeps_the_local_approval(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    payload = json.dumps(
        {
            "grant_id": "grant-1",
            "workspace_id": "workspace-1",
            "machine_id": "machine-1",
        }
    )
    with store._connect() as connection:
        connection.execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
            ("oauth_local_credentials", payload, _SAVED_AT),
        )
        connection.execute("drop table guard_devices")

    request_id = "req-missing-guard-devices"
    assert store.add_approval_request(_request(request_id), _SAVED_AT) == request_id
    saved = store.get_approval_request(request_id)
    assert saved is not None
    assert saved["status"] == "pending"


def test_locked_store_does_not_save_an_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS", "50")
    store = GuardStore(tmp_path / "guard-home")
    held = sqlite3.connect(store.path, timeout=0.05)
    held.execute("begin exclusive")
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            store.add_approval_request(_request("req-locked"), _SAVED_AT)
    finally:
        held.rollback()
        held.close()

    assert store.get_approval_request("req-locked") is None
