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


_APPROVAL_WAIT = (
    "It is waiting for the user to approve it in the HOL Guard inbox (`hol-guard approvals`). "
    "Do not retry the same action until it is approved; continue with other work meanwhile."
)
_NOT_QUEUED = (
    "No approval is waiting in HOL Guard for this action. Do not retry it or work around the block; "
    "continue with a permitted alternative or tell the user what is blocked."
)

# Plain-language next steps keyed by the reason code Rust already returned.
_REASON_CODE_HINTS = {
    "native_destructive_command": (
        "This command deletes or overwrites data. Use `git worktree remove` for a worktree, "
        "or target one specific path."
    ),
    "native_package_review": (
        "Package installs run code from a registry. Use `--ignore-scripts` where the package manager allows it."
    ),
    "native_network_review": "This makes a network request that Guard has not seen before.",
    "native_file_read_review": "This reads a file outside what Guard treats as safe to read.",
    "native_pre_tool_unknown_review": "Guard does not recognize this tool call.",
    "native_command_review_required": (
        "Guard could not prove this exact command is read-only. Use a simpler built-in tool where one fits."
    ),
}


def safe_alternative_reason(
    reason: str,
    *,
    reason_code: str | None = None,
    approval_queued: bool | None = None,
) -> str:
    """Format deny text; the verdict and reason code come from the native decision."""
    if reason_code is None and approval_queued is None:
        return f"{reason.strip()} {SAFE_ALTERNATIVE_GUIDANCE}".strip()
    hint = _REASON_CODE_HINTS.get(reason_code or "", "")
    wait = _APPROVAL_WAIT if approval_queued else _NOT_QUEUED
    return " ".join(part for part in (reason.strip(), hint, wait) if part)
