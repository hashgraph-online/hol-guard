from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


def test_exact_failed_job_rerun_is_prompt_free() -> None:
    args = ("run", "rerun", "31707639186", "--repo", "hashgraph-online/hol-guard", "--failed")

    assessment = classify_github_cli(args)
    match = extract_sensitive_tool_action_request("Bash", {"command": f"gh {' '.join(args)}"})

    assert assessment.capabilities == ("routine_workflow_remote",)
    assert assessment.reason_code == "github.command.routine-failed-run-rerun"
    assert match is None


@pytest.mark.parametrize(
    "args",
    (
        ("run", "rerun", "31707639186", "--repo", "hashgraph-online/hol-guard"),
        ("run", "rerun", "31707639186", "--failed"),
        ("run", "rerun", "31707639186", "--repo", "hashgraph-online/hol-guard", "--job", "44"),
        ("run", "rerun", "31707639186", "--repo", "hashgraph-online/hol-guard", "--failed", "--debug"),
        ("run", "rerun", "$RUN_ID", "--repo", "hashgraph-online/hol-guard", "--failed"),
        ("run", "rerun", "31707639186", "--repo", "$REPO", "--failed"),
        ("run", "rerun", "31707639186", "--repo", "github.example/owner/repository", "--failed"),
    ),
)
def test_failed_job_rerun_rejects_broader_variants(args: tuple[str, ...]) -> None:
    assessment = classify_github_cli(args)

    assert assessment.capabilities != ("routine_workflow_remote",)


def test_indirect_failed_job_rerun_still_requires_reapproval(tmp_path: Path) -> None:
    result = evaluate_command(
        "xargs gh run rerun 31707639186 --repo hashgraph-online/hol-guard --failed",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert result.decision_plane.action == "require-reapproval"
