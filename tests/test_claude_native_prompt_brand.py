"""The branded Claude prompt overlay must reach ``additionalContext``."""

from __future__ import annotations

from codex_plugin_scanner.guard.daemon.hook_worker_native import (
    _claude_native_prompt_brand,
)


def _branded_response() -> dict[str, object]:
    return _claude_native_prompt_brand(
        {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}},
        {
            "minimum_action": "require-reapproval",
            "reason": "the prompt asks for local secrets",
            "prompt_risk_classes": ["secret_read"],
        },
    )


def test_a_reapproval_prompt_is_briefed_in_additional_context() -> None:
    hook_output = _branded_response()["hookSpecificOutput"]

    assert isinstance(hook_output, dict)
    briefing = hook_output["additionalContext"]
    assert isinstance(briefing, str)
    assert "HOL Guard" in briefing
    assert "the prompt asks for local secrets." in briefing


def test_a_reapproval_prompt_still_carries_the_branded_system_message() -> None:
    assert "HOL Guard intercepted this prompt" in str(_branded_response()["systemMessage"])
