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
# A queued row whose retry cannot reuse a one-time approval (no retry binding):
# telling the agent to wait for approval sends it into a retry that is blocked again.
_APPROVAL_ALWAYS_ONLY = (
    "It is waiting in the HOL Guard inbox (`hol-guard approvals`), but approving it just once will not "
    'let you run it; only "Always allow exact action" will. Do not retry it unless the user says they '
    "chose that; continue with other work meanwhile."
)
_APPROVAL_CANNOT_UNBLOCK = (
    "It is recorded in the HOL Guard inbox, but approving it there will not let you run it. "
    "Do not retry this exact command. Tell the user exactly what is blocked so they can run it themselves, "
    "or continue with a permitted alternative."
)
_NOT_QUEUED = (
    "No approval is waiting in HOL Guard for this action. Do not retry the same action or work around the block; "
    "continue with a permitted alternative or tell the user what is blocked."
)

# Plain-language next steps keyed by the reason code Rust already returned.
_REASON_CODE_HINTS = {
    "native_destructive_command": (
        "This command deletes or overwrites data. Use `git worktree remove` for a worktree, "
        "or target one specific path."
    ),
    "native_package_review": (
        "Package installs download code from a registry, so Guard reviews them. An install that "
        "only restores the committed lockfile and runs no scripts (`bun install --frozen-lockfile "
        "--ignore-scripts`, `pnpm install --frozen-lockfile --ignore-scripts` or `npm ci "
        "--ignore-scripts`) can proceed once Guard has checked the lockfile and settings. If this "
        "was already that form, reuse dependencies that are already installed where you can."
    ),
    "native_network_review": "This makes a network request that Guard has not seen before.",
    "native_file_read_review": (
        "This reads a file outside what Guard treats as safe to read. A search is checked "
        "against every file it can reach, so search a narrower folder or one file, use `rg` "
        "with a `-g` file filter, or find files by name with `find` or `glob`."
    ),
    "native_pre_tool_unknown_review": "Guard cannot check what this tool call will do before it runs.",
    "native_command_review_required": (
        "Guard could not prove this exact command is read-only. Use a simpler built-in tool where one fits. "
        "If it chains several steps, run each step as its own command; Guard checks each one on its own."
    ),
}

# A package review of a build or test (`cargo test`) says why in its own text;
# the install advice above does not apply to it.
_BUILD_REVIEW_PREFIX = "HOL Guard requires review before this build or test command"


# The native review text offers inbox approval. When no approval can let the
# action run, that offer contradicts the note that follows, so it is dropped.
_INBOX_APPROVAL_OFFER = (
    " Approve it in the HOL Guard inbox (choose Always for a repeated read-only command),"
    " or split it into simpler commands."
)


def safe_alternative_reason(
    reason: str,
    *,
    reason_code: str | None = None,
    approval_queued: bool | None = None,
    retry_reuses_approval: bool = True,
    exact_action_allowable: bool = False,
) -> str:
    """Format deny text; the verdict and reason code come from the native decision.

    ``retry_reuses_approval`` is False when the queued row has no retry binding, so a
    one-time approval cannot let the agent's retry run. ``exact_action_allowable``
    says whether "Always allow exact action" can.
    """
    if reason_code is None and approval_queued is None:
        return f"{reason.strip()} {SAFE_ALTERNATIVE_GUIDANCE}".strip()
    hint = "" if reason.lstrip().startswith(_BUILD_REVIEW_PREFIX) else _REASON_CODE_HINTS.get(reason_code or "", "")
    if not approval_queued:
        wait = _NOT_QUEUED
    elif retry_reuses_approval:
        wait = _APPROVAL_WAIT
    elif exact_action_allowable:
        wait = _APPROVAL_ALWAYS_ONLY
    else:
        wait = _APPROVAL_CANNOT_UNBLOCK
    reason = reason.strip()
    if wait in (_NOT_QUEUED, _APPROVAL_CANNOT_UNBLOCK):
        reason = reason.replace(_INBOX_APPROVAL_OFFER, "")
    return " ".join(part for part in (reason, hint, wait) if part)
