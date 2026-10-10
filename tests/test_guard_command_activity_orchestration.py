"""End-to-end orchestration regressions for command activity ownership."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnusedCallResult=false

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_support_command_activity import command_activity_was_prompted
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact


def _context(tmp_path: Path) -> HarnessContext:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=tmp_path / "guard-home",
    )


def _artifact(tmp_path: Path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="copilot:project:tool-action:partition",
        name="Copilot partition tool call",
        harness="copilot",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(tmp_path / ".vscode" / "mcp.json"),
        command="git push origin release/2.2 --force",
    )


def _decision(action: GuardAction) -> ToolCallDecision:
    return ToolCallDecision(
        action=action,
        source="heuristic",
        signals=("fixture signal",),
        summary="Fixture decision.",
        risk_categories=("destructive_mutation",),
    )


def _args() -> argparse.Namespace:
    return argparse.Namespace(harness="copilot", json=False)


@pytest.mark.parametrize(
    ("reuse_status", "expected"),
    (
        ("accepted", False),
        ("rejected", True),
        ("not-applicable", True),
    ),
)
def test_prompt_attribution_excludes_accepted_approval_reuse(
    reuse_status: str,
    expected: bool,
) -> None:
    from codex_plugin_scanner.guard.runtime.command_activity_contract import ActivityApprovalReuseStatus

    assert command_activity_was_prompted("review", ActivityApprovalReuseStatus(reuse_status)) is expected
