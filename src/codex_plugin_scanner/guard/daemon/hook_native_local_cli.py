"""Honor custom-extension grants for paused native PreToolUse reviews."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path

from .hook_native_saved_approval import _launch_cwd, _native_review_is_overridable, _saved_block_response
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import harness_json_from_native_pre_tool

_LOGGER = logging.getLogger(__name__)


def native_local_cli_grant_response(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """Return the custom-extension outcome for a native review, or ``None``.

    A custom block applies to any review. A custom allow only lifts a review
    that Rust marked overridable, so it never weakens a block or critical floor.
    """

    if native_result.get("policy_action") not in {"review", "require-reapproval"}:
        return None
    command = pre_tool_command(payload)
    cwd = _launch_cwd(payload, workspace)
    if command is None or cwd is None:
        return None
    from ..local_cli_trust import matching_local_cli_grant

    try:
        match = matching_local_cli_grant(
            store=store,
            command=command,
            cwd=cwd,
            home_dir=home_dir,
            current_action="review",
        )
    except Exception:
        _LOGGER.warning("custom extension grant lookup failed", exc_info=True)
        return None
    if match is None:
        return None
    identity, state = match
    if state == "blocked":
        return _saved_block_response(
            harness,
            native_result,
            reason_code="local_cli_extension_blocked",
            reason=f"Your custom extension rules block this {identity.name} command.",
        )
    if not _native_review_is_overridable(native_result):
        return None
    allowed = dict(native_result)
    allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
    response = harness_json_from_native_pre_tool(harness, allowed)
    response["approval_reuse_status"] = "accepted"
    return response


__all__ = ["native_local_cli_grant_response"]
