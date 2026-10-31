"""Exact-action regressions for MCP calls that are not executed."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import (
    ToolCallDecision,
    block_tool_call,
    resolve_tool_call_policy_action,
)
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


def _runtime_tool_artifact() -> GuardArtifact:
    return GuardArtifact(
        artifact_id="codex:runtime:mcp:example:read_file",
        name="example:read_file",
        harness="codex",
        artifact_type="tool_call",
        source_scope="mcp",
        config_path="/tmp/example-mcp.json",
        command="read_file",
        transport="stdio",
        metadata={"server_name": "example"},
    )


@pytest.mark.parametrize(
    "policy_action",
    ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block"),
)
def test_first_time_tool_call_action_is_preserved(policy_action: GuardAction) -> None:
    decision = ToolCallDecision(
        action=policy_action,
        source="policy",
        signals=(),
        summary="exact action",
        approval_reuse_status="not-applicable",
        approval_reuse_reason_code="approval_reuse_no_saved_decision",
        policy_action=policy_action,
    )

    assert resolve_tool_call_policy_action(decision) == policy_action


def test_rejected_prior_authority_surfaces_the_native_reapproval() -> None:
    decision = ToolCallDecision(
        action="review",
        source="policy",
        signals=(),
        summary="stale approval",
        approval_reuse_status="rejected",
        approval_reuse_reason_code="approval_reuse_content_changed",
        current_action="review",
        saved_action="allow",
        policy_action="require-reapproval",
    )

    assert resolve_tool_call_policy_action(decision) == "require-reapproval"


def test_a_decision_without_a_native_policy_action_is_unreadable() -> None:
    decision = ToolCallDecision(
        action="review",
        source="policy",
        signals=(),
        summary="no native answer",
        approval_reuse_status="rejected",
        approval_reuse_reason_code="approval_reuse_content_changed",
    )

    with pytest.raises(ValueError, match="tool_call_policy_action_missing"):
        resolve_tool_call_policy_action(decision)


@pytest.mark.parametrize(
    ("policy_action", "event_name", "provenance_action"),
    [
        ("review", "runtime_tool_call_review_required", "runtime tool call awaiting review"),
        (
            "require-reapproval",
            "runtime_tool_call_reapproval_required",
            "runtime tool call awaiting fresh approval",
        ),
        (
            "sandbox-required",
            "runtime_tool_call_sandbox_required",
            "runtime tool call requires an enforceable sandbox",
        ),
        ("block", "runtime_tool_call_blocked", "runtime tool call blocked"),
    ],
)
def test_block_tool_call_records_exact_non_execution_action(
    tmp_path: Path,
    policy_action: GuardAction,
    event_name: str,
    provenance_action: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact = _runtime_tool_artifact()

    receipt = block_tool_call(
        store=store,
        artifact=artifact,
        artifact_hash="sha256:exact-action",
        decision_source="policy-evaluation",
        now="2026-07-18T00:00:00+00:00",
        signals=("sensitive_file_read",),
        arguments={"path": ".env"},
        policy_action=policy_action,
    )

    assert receipt.policy_decision == policy_action
    assert receipt.provenance_summary == f"{provenance_action} from {artifact.config_path}"
    events = store.list_events(limit=10)
    assert len(events) == 1
    assert events[0]["event_name"] == event_name
    assert events[0]["payload"]["policy_action"] == policy_action
    assert events[0]["payload"]["execution_outcome"] == "not-executed"


@pytest.mark.parametrize("executing_action", ["allow", "warn"])
def test_block_tool_call_rejects_executing_actions_without_persistence(
    tmp_path: Path,
    executing_action: GuardAction,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    with pytest.raises(ValueError, match="cannot record executing action"):
        block_tool_call(
            store=store,
            artifact=_runtime_tool_artifact(),
            artifact_hash="sha256:executing-action",
            decision_source="invalid-call-site",
            now="2026-07-18T00:00:00+00:00",
            signals=(),
            policy_action=executing_action,
        )

    assert store.list_receipts(limit=10) == []
    assert store.list_events(limit=10) == []
