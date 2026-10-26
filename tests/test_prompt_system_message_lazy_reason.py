"""An allowed prompt must not pay for a reason it never shows."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cli.commands_support_prompts import (
    _claude_prompt_system_message,
    _codex_prompt_block_system_message,
)
from codex_plugin_scanner.guard.models import GuardArtifact


def _artifact() -> GuardArtifact:
    return GuardArtifact(
        artifact_id="prompt",
        name="prompt",
        harness="claude-code",
        artifact_type="prompt_request",
        source_scope="user",
        config_path="",
    )


def _refuses() -> str:
    raise AssertionError("the resident was asked for a reason nothing shows")


@pytest.mark.parametrize(
    ("event_name", "policy_action"),
    [("UserPromptSubmit", "allow"), ("PreToolUse", "allow"), ("PostToolUse", "block")],
)
def test_claude_asks_for_no_reason_it_will_not_show(event_name: str, policy_action: str) -> None:
    assert (
        _claude_prompt_system_message(
            event_name=event_name,
            policy_action=policy_action,
            artifact=_artifact(),
            native_reason=_refuses,
        )
        is None
    )


def test_codex_asks_for_no_reason_a_running_prompt_will_not_show() -> None:
    assert _codex_prompt_block_system_message(policy_action="allow", native_reason=_refuses) is None


def test_a_paused_codex_prompt_still_reads_the_residents_reason() -> None:
    message = _codex_prompt_block_system_message(
        policy_action="block", native_reason=lambda: "Open HOL Guard to review this prompt."
    )
    assert message == "HOL Guard paused your Codex prompt. Open HOL Guard to review this prompt."
