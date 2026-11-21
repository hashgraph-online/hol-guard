"""Unbound once consent is rejected before saving a misleading allow receipt."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_scope_support import IneligibleApprovalScopeError
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

BOUND_HASH = "native-review-v4:" + "a" * 64 + ":deny:review:review:native_sensitive_access_review"


def _native_request(request_id: str, *, artifact_hash: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="omp",
        artifact_id="omp:native-pretool:bash",
        artifact_name="bash",
        artifact_type="tool_call",
        artifact_hash=artifact_hash,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="project",
        config_path="/workspace/repo",
        workspace="/workspace/repo",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:1/requests/{request_id}",
        action_envelope_json={"action_type": "shell_command", "tool_name": "bash", "command": "python3 jokes.py"},
        raw_command_text="python3 jokes.py",
    )


def _approve_once(tmp_path: Path, request_id: str, artifact_hash: str) -> dict[str, object] | None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_native_request(request_id, artifact_hash=artifact_hash), "2026-10-16T00:00:00+00:00")
    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed once",
    )
    return store.get_receipt_for_approval_request(request_id, policy_decision="allow")


def test_approving_an_unbound_native_review_once_saves_no_allow_receipt(tmp_path: Path) -> None:
    # An unbound row's hash is its request id, so the retry cannot reuse the approval.
    with pytest.raises(IneligibleApprovalScopeError):
        _approve_once(tmp_path, "unbound-req", "unbound-req")
    store = GuardStore(tmp_path / "guard-home")
    assert store.get_approval_request("unbound-req")["status"] == "pending"
    assert store.get_receipt_for_approval_request("unbound-req", policy_decision="allow") is None


def test_approving_a_bound_native_review_once_records_a_plain_approval(tmp_path: Path) -> None:
    receipt = _approve_once(tmp_path, "bound-req", BOUND_HASH)
    assert receipt is not None
    assert receipt["user_override"] == "approval-approved"
