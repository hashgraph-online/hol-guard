"""Exact live-decision completion at the Codex daemon boundary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from codex_plugin_scanner.guard.codex_live_decision import complete_codex_live_decision
from codex_plugin_scanner.guard.codex_resume import seed_request_resume_record
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _seed_resolved_request(
    tmp_path: Path,
    *,
    request_id: str,
    action: str,
    with_exact_allow: bool,
) -> tuple[GuardStore, str]:
    store = GuardStore(tmp_path / "guard-home")
    observed = datetime.now(timezone.utc)
    now = observed.isoformat()
    artifact_id = f"codex:project:{request_id}"
    artifact_hash = f"hash-{request_id}"
    workspace = "/workspace/project"
    store.add_approval_request(
        GuardApprovalRequest(
            request_id=request_id,
            harness="codex",
            artifact_id=artifact_id,
            artifact_name="Codex tool action",
            artifact_type="tool_action_request",
            artifact_hash=artifact_hash,
            publisher=None,
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("shell_command",),
            source_scope="project",
            config_path=f"{workspace}/.guard/config.toml",
            workspace=workspace,
            launch_target="npm install is-even@1.0.0",
            review_command=f"hol-guard approvals approve {request_id}",
            approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
            action_envelope_json={
                "action_type": "shell_command",
                "command": "npm install is-even@1.0.0",
                "tool_name": "Bash",
            },
        ),
        now,
    )
    session = store.upsert_guard_session(
        session_id=f"session-{request_id}",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-hook",
        client_title="Codex hook",
        client_version="1.0.0",
        workspace=workspace,
        capabilities=["approval-resolution"],
        now=now,
    )
    store.upsert_guard_operation(
        operation_id=f"operation-{request_id}",
        session_id=str(session["session_id"]),
        harness="codex",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request_id],
        resume_token=None,
        metadata={"hook_event_name": "PreToolUse", "workspace": workspace},
        now=now,
    )
    assert seed_request_resume_record(store, request_id=request_id, now=now) is not None
    assert store.resolve_one_request_only(
        request_id,
        resolution_action=action,
        resolution_scope="artifact",
        reason="review decision",
        resolved_at=now,
    )
    if with_exact_allow:
        assert store.record_local_once_approval(
            request_id=request_id,
            harness="codex",
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=None,
            action="allow",
            created_at=now,
            expires_at=(observed + timedelta(minutes=5)).isoformat(),
        )
    return store, now


def test_allow_consumes_exact_authority_and_records_terminal_continuation(tmp_path: Path) -> None:
    request_id = "request-live-allow"
    store, now = _seed_resolved_request(
        tmp_path,
        request_id=request_id,
        action="allow",
        with_exact_allow=True,
    )

    result = complete_codex_live_decision(store, request_id=request_id, now=now)

    assert result["completed"] is True
    assert result["action"] == "allow"
    assert (
        store.peek_local_once_approval(
            harness="codex",
            artifact_id=f"codex:project:{request_id}",
            artifact_hash=f"hash-{request_id}",
            workspace="/workspace/project",
            publisher=None,
            now=now,
        )
        is None
    )
    resume = store.get_request_resume(request_id)
    assert resume is not None
    assert resume["status"] == "sent"


def test_allow_without_matching_exact_authority_stays_closed(tmp_path: Path) -> None:
    request_id = "request-live-missing"
    store, now = _seed_resolved_request(
        tmp_path,
        request_id=request_id,
        action="allow",
        with_exact_allow=False,
    )

    result = complete_codex_live_decision(store, request_id=request_id, now=now)

    assert result == {"completed": False, "error": "exact_approval_unavailable"}
    resume = store.get_request_resume(request_id)
    assert resume is not None
    assert resume["status"] == "pending"


def test_block_records_terminal_continuation_without_allow_authority(tmp_path: Path) -> None:
    request_id = "request-live-block"
    store, now = _seed_resolved_request(
        tmp_path,
        request_id=request_id,
        action="block",
        with_exact_allow=False,
    )

    result = complete_codex_live_decision(store, request_id=request_id, now=now)

    assert result["completed"] is True
    assert result["action"] == "block"
    resume = store.get_request_resume(request_id)
    assert resume is not None
    assert resume["status"] == "skipped"
