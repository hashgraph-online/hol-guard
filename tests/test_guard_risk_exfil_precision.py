"""Regression coverage for ordinary transfer vocabulary in runtime commands."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact
from tests.artifact_risk_support import artifact_risk_signals


@pytest.mark.parametrize(
    "command",
    (
        "uv sync --frozen --extra dev",
        "git sync",
        "rg -n 'post|send|sync' src tests",
        "node -e 'client.post(record); await state.sync()'",
    ),
)
def test_routine_transfer_words_are_not_exfiltration(command: str) -> None:
    artifact = GuardArtifact(
        artifact_id="codex:session:routine-command",
        name="Bash",
        harness="codex",
        artifact_type="runtime_action",
        source_scope="session",
        config_path="/workspace",
        command="bash",
        args=("-lc", command),
        transport="stdio",
    )

    assert "includes exfiltration-oriented intent" not in artifact_risk_signals(artifact)
