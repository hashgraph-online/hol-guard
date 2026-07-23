from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job
from codex_plugin_scanner.guard.runtime.live_request_repair import live_request_sync_repair_status
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-07-23T12:00:00+00:00"
_INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"


def _request(request_id: str) -> GuardApprovalRequest:
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
        trigger_summary="Review test action",
        last_seen_at=_NOW,
    )


def _connected_store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard")
    store.set_sync_payload(
        "oauth_local_credentials",
        {
            "grant_id": "grant-current",
            "machine_id": "machine-current",
            "machine_installation_id": _INSTALLATION_ID,
            "workspace_id": "workspace-1",
        },
        _NOW,
    )
    return store


def _replace_binding_with_stale_identity(store: GuardStore, request_id: str) -> None:
    with store._connect() as connection:
        connection.execute(
            """
            update guard_live_request_outbox
            set oauth_source = ?, oauth_subject_hash = ?, workspace_id = ?,
                machine_id = ?, machine_installation_id = ?
            where local_request_id = ?
            """,
            (
                "default",
                "stale-subject",
                "workspace-1",
                "machine-stale",
                "11111111-1111-4111-8111-111111111111",
                request_id,
            ),
        )


def test_repair_status_exposes_only_actionable_binding_metadata(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    store.add_approval_request(_request("request-1"), _NOW)
    _replace_binding_with_stale_identity(store, "request-1")

    status = live_request_sync_repair_status(store, now=_NOW)

    assert status == {
        "bindingState": "identity_mismatch",
        "quarantinedCount": 1,
        "repairable": True,
        "source": "default",
        "workspaceId": "workspace-1",
    }


def test_cloud_repair_rebinds_only_the_confirmed_source_and_workspace(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    store.add_approval_request(_request("request-current"), _NOW)
    store.add_approval_request(_request("request-other"), _NOW)
    _replace_binding_with_stale_identity(store, "request-current")
    _replace_binding_with_stale_identity(store, "request-other")
    with store._connect() as connection:
        connection.execute(
            """
            update guard_live_request_outbox
            set workspace_id = ?
            where local_request_id = ?
            """,
            ("workspace-other", "request-other"),
        )

    result = execute_guard_command_job(
        {
            "operation": "guard.liveRequests.reassignQuarantined",
            "payload": {
                "source": "default",
                "workspaceId": "workspace-1",
            },
        },
        context=HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path,
            guard_home=store.guard_home,
        ),
        store=store,
        now=lambda: _NOW,
    )

    data = result["data"]
    assert isinstance(data, dict)
    status = data["status"]
    assert isinstance(status, dict)
    assert data["reassignedCount"] == 1
    assert status["bindingState"] == "workspace_mismatch"
    with store._connect() as connection:
        rows = connection.execute(
            """
            select local_request_id, workspace_id, machine_id
            from guard_live_request_outbox
            order by local_request_id
            """
        ).fetchall()
    assert [(row["local_request_id"], row["workspace_id"], row["machine_id"]) for row in rows] == [
        ("request-current", "workspace-1", "machine-current"),
        ("request-other", "workspace-other", "machine-stale"),
    ]


def test_cloud_repair_rejects_a_different_workspace(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)

    result = execute_guard_command_job(
        {
            "operation": "guard.liveRequests.reassignQuarantined",
            "payload": {
                "source": "default",
                "workspaceId": "workspace-other",
            },
        },
        context=HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path,
            guard_home=store.guard_home,
        ),
        store=store,
        now=lambda: _NOW,
    )

    assert result["failureCode"] == "approved_workspace_mismatch"
