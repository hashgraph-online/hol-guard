"""Command activity persists the authoritative native-backed baseline."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import codex_plugin_scanner.guard.cli.commands_support_command_activity as command_activity
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
)
from tests.native_command_test_support import real_native_command_evaluation


def test_activity_shadow_records_native_backed_baseline_without_a_second_oracle(tmp_path: Path) -> None:
    command = "git push origin main --force"
    evaluation = real_native_command_evaluation(command).evaluation

    observation, failed = command_activity._build_shadow_best_effort(
        evaluation=evaluation,
        command_text=command,
        guard_home=tmp_path,
        cwd=tmp_path,
        home_dir=tmp_path,
        policy_action="review",
        activity_id="activity:native-baseline",
        occurred_at=datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc),
    )

    assert failed is False
    assert observation is not None
    assert observation.authoritative_action == "review"
    assert observation.proposal_version == COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION
