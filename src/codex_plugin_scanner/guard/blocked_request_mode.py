"""Shared presentation policy for requests that need approval."""

from __future__ import annotations

SAFE_ALTERNATIVE_GUIDANCE = (
    "This action remains blocked. Continue with a safe, permitted alternative that respects "
    "the same protection. Do not retry an equivalent command, bypass Guard, or seek permission "
    "to run it. If no safe alternative can complete the task, explain the limitation."
)


def asks_for_approval(config: object) -> bool:
    """Prompt only after the operator explicitly opts in."""
    return getattr(config, "blocked_request_mode", None) == "ask"


def safe_alternative_reason(reason: str) -> str:
    return f"{reason.strip()} {SAFE_ALTERNATIVE_GUIDANCE}".strip()
