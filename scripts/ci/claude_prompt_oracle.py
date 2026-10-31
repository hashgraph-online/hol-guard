"""The retired Python prompt notices, frozen as a parity oracle.

These are the helpers ``commands_support_prompts.py`` used to compose the
Claude and Codex prompt notices before the native runtime took them over,
kept here so the artifact and prompt-notice vector recorders never call the
code they check.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from codex_plugin_scanner.guard.text import ensure_terminal_punctuation as _ensure_terminal_punctuation


def _canonical_harness_name(value: str) -> str:
    from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import (
        _canonical_harness_name as canonical,
    )

    return canonical(value)


def _prompt_requires_hard_block(artifact: Any) -> bool:
    prompt_classes = artifact.metadata.get("prompt_request_classes")
    if isinstance(prompt_classes, list):
        return "guard_bypass_intent" in {str(item) for item in prompt_classes}
    prompt_class = artifact.metadata.get("prompt_request_class")
    return isinstance(prompt_class, str) and prompt_class == "guard_bypass_intent"


def _prompt_request_classes(artifact: Any) -> set[str]:
    prompt_classes = artifact.metadata.get("prompt_request_classes")
    values = prompt_classes if isinstance(prompt_classes, list) else [artifact.metadata.get("prompt_request_class")]
    return {str(item) for item in values if isinstance(item, str) and item.strip()}


def _claude_prompt_additional_context(
    *,
    harness: str,
    event_name: str,
    policy_action: str,
    artifact: Any,
    native_reason: str,
) -> str | None:
    if _canonical_harness_name(harness) != "claude-code":
        return None
    if event_name != "UserPromptSubmit":
        return None
    if policy_action != "require-reapproval":
        return None
    if _prompt_requires_hard_block(artifact):
        return None
    return _claude_prompt_briefing(native_reason, secret="secret_read" in _prompt_request_classes(artifact))


def _claude_prompt_briefing(native_reason: str, *, secret: bool) -> str:
    briefing_sentence = "HOL Guard will intercept Claude's next sensitive action and open a branded approval question."
    if secret:
        briefing_sentence = (
            "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded approval "
            "question to protect you."
        )
    return (
        f"{_ensure_terminal_punctuation(native_reason)} "
        "Do not ask for approval at the prompt stage. Attempt the intended sensitive tool once so HOL Guard can "
        "evaluate the exact tool, path, and arguments, then route that concrete action into a HOL Guard approval "
        "question with Allow once, Allow during this session, and Keep blocked. First tell the user exactly: "
        f"'{briefing_sentence}' "
        "Attempt that sensitive tool at most once. If HOL Guard or Claude denies it, do not retry the same sensitive "
        "action automatically. Instead, tell the user approval is required in Claude to continue."
    )


def _claude_prompt_intercept_message(*, secret: bool) -> str:
    cause = "asks Claude to access local secrets" if secret else "leads to a sensitive action"
    return (
        f"HOL Guard intercepted this prompt because it {cause}. "
        "If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt."
    )


def _claude_prompt_system_message(
    *,
    event_name: str,
    policy_action: str,
    artifact: Any,
    native_reason: Callable[[], str],
) -> str | None:
    """The system message Claude is shown, or ``None``.

    The reason is read through a callable so a pass that needs no message
    never composes one.
    """

    if event_name == "UserPromptSubmit":
        if policy_action == "require-reapproval" and not _prompt_requires_hard_block(artifact):
            return _claude_prompt_intercept_message(secret="secret_read" in _prompt_request_classes(artifact))
        if policy_action in {"block", "sandbox-required"}:
            return _ensure_terminal_punctuation(native_reason())
        return None
    if event_name == "PreToolUse" and policy_action in {"require-reapproval", "block", "sandbox-required"}:
        return _ensure_terminal_punctuation(native_reason())
    return None


def _codex_prompt_block_system_message(*, policy_action: str, native_reason: Callable[[], str]) -> str | None:
    """What Codex is told about a paused prompt, or ``None``.

    The reason is read through a callable so a prompt that keeps running
    never composes one.
    """

    if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"}:
        return None
    reason = native_reason()
    if "open hol guard" not in reason.lower():
        return None
    return f"HOL Guard paused your Codex prompt. {reason}"
