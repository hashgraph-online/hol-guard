from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_critical_floors import command_critical_floor_factors
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.effect_decision import EffectDecisionRequest, evaluate_effect_decision
from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request
from tests.native_command_test_support import real_native_review_fixture


def test_exact_failed_job_rerun_requires_confirmation() -> None:
    args = ("run", "rerun", "31707639186", "--repo", "hashgraph-online/hol-guard", "--failed")

    assessment = classify_github_cli(args)
    match = extract_sensitive_tool_action_request("Bash", {"command": f"gh {' '.join(args)}"})

    assert assessment.capabilities == ("routine_workflow_remote",)
    assert assessment.reason_code == "github.command.routine-failed-run-rerun"
    assert assessment.action_floor == "require-reapproval"
    assert match is not None
    assert match.action_class == "GitHub workflow rerun"


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
    command = "xargs gh run rerun 31707639186 --repo hashgraph-online/hol-guard --failed"
    # Preserve the independent workflow policy floor. Native transport is
    # stricter for this unsupported wrapper, as asserted separately below.
    result = evaluate_effect_decision(
        EffectDecisionRequest(
            factors=command_critical_floor_factors(parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path))
        )
    )

    assert result.action == "require-reapproval"
    native = real_native_review_fixture(command).payload
    assert native["minimum_action"] == "block"
    assert native["command_model"]["uncertainty_reason"] == "nested_command_executor_not_yet_supported"
    assert native["command_extensions"]["evaluation_error"] == "native_command_evaluation_failed"
    assert native["command_extensions"]["observations"] == []
