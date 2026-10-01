"""Regression coverage for terminal saved blocks in hook-specific flows."""

from __future__ import annotations

import argparse
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.receipts import build_receipt
from codex_plugin_scanner.guard.store import GuardStore


def _artifact(tmp_path: Path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="copilot:project:tool-action:saved-block",
        name="Copilot saved-block tool call",
        harness="copilot",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(tmp_path / ".vscode" / "mcp.json"),
        command="dangerous_delete",
    )


def _context(tmp_path: Path) -> HarnessContext:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=tmp_path / "guard-home",
    )


def _saved_block_decision() -> ToolCallDecision:
    return ToolCallDecision(
        action="block",
        source="policy",
        signals=("tool name implies destructive file or system changes",),
        summary="Local Guard kept this tool call blocked by saved policy.",
        risk_categories=("destructive_mutation",),
        approval_reuse_status="accepted",
        approval_reuse_reason_code="approval_reuse_saved_block",
        current_action="review",
        saved_action="block",
    )


def _fresh_block_decision() -> ToolCallDecision:
    return ToolCallDecision(
        action="block",
        source="heuristic",
        signals=("tool name implies destructive file or system changes",),
        summary="The current call is destructive.",
        risk_categories=("destructive_mutation",),
    )


def _saved_allow_decision() -> ToolCallDecision:
    return ToolCallDecision(
        action="allow",
        source="policy",
        signals=("tool name implies destructive file or system changes",),
        summary="Local Guard reused an exact saved approval for this tool call.",
        risk_categories=("destructive_mutation",),
        approval_reuse_status="accepted",
        approval_reuse_reason_code="approval_reuse_accepted",
        current_action="review",
        saved_action="allow",
    )


def _copilot_args(*, json_output: bool = False) -> argparse.Namespace:
    return argparse.Namespace(harness="copilot", json=json_output)


def _fail_queue(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
    raise AssertionError("a terminal saved block must not be queued for approval")


def _receipt_reuse_evidence(store: GuardStore) -> dict[str, object]:
    receipt = store.list_receipts(limit=1)[0]
    evidence = receipt["scanner_evidence"]
    assert isinstance(evidence, list)
    typed_evidence = [item for item in evidence if isinstance(item, dict)]
    return next(item for item in typed_evidence if item.get("source") == "approval_reuse")


def _runtime_receipt(artifact: GuardArtifact, artifact_hash: str, policy_action: str):
    return build_receipt(
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_action,
        capabilities_summary="runtime tool action",
        changed_capabilities=["runtime_tool_call"],
        provenance_summary=f"runtime tool request evaluated from {artifact.config_path}",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
    )
