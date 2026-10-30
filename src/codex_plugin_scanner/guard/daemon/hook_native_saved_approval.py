"""Bind daemon native reviews to a stable exact-action identity.

The native once-retry binding embeds the Rust request digest, which changes on
every hook delivery. An "Always" decision needs an identity that survives new
sessions and tool-use ids while still changing whenever the code that would run,
the reviewed command, or the Rust rules that judged it change.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping
from pathlib import Path

from ..policy_integrity import REMOTE_POLICY_SOURCES
from ..store_policy import memory_lookup_candidates
from ..store_policy_decision import policy_decision_block_exists, policy_decision_hash_exists
from .hook_fail_closed import render_accepted_allow, render_pre_tool

_LOGGER = logging.getLogger(__name__)

EXACT_ACTION_CONTEXT_TOKEN_KEY = "exact_context_token"
EXACT_ACTION_IDENTITY_KIND_KEY = "exact_identity_kind"
ONCE_ONLY_REASON_KEY = "once_only_reason"
# Action types the native authority gives a shell command line. A tool call
# that only carries a ``command`` argument, such as an MCP tool, is not one.
_SHELL_ACTION_TYPES = frozenset({"command", "package", "process_service", "network", "shell", "shell_command"})
_EXACT_COMMAND_RETRY_HINT = "Do not retry it; continue with a permitted alternative."


def native_saved_decision_response(
    store: object,
    *,
    harness: str,
    token: str | None,
    artifact_id: str,
    native_result: Mapping[str, object],
    workspace: Path | None,
) -> dict[str, object] | None:
    """Apply a saved exact-action allow or block; ``None`` keeps the review flow."""

    if token is None:
        return None
    lookup = getattr(store, "resolve_policy_decision_lookup", None)
    if not callable(lookup):
        return None
    try:
        # The full lookup refreshes integrity state under a write lock. Skip it
        # on the hot hook path unless an exact decision for this token exists.
        if not policy_decision_hash_exists(store, harness=harness, artifact_id=artifact_id, artifact_hash=token):
            return None
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # Without a probe result the action still goes to a human review.
        _LOGGER.warning("Native saved approval probe failed (%s)", type(error).__name__)
        return None
    try:
        result = lookup(
            harness,
            artifact_id,
            artifact_hash=token,
            workspace=str(workspace) if workspace is not None else None,
            consume_one_shot=False,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # A saved decision exists but could not be read; it may be a block.
        _LOGGER.warning("Native saved approval lookup failed (%s)", type(error).__name__)
        return _saved_block_response(
            harness,
            native_result,
            reason_code="saved_exact_action_unreadable",
            reason="HOL Guard could not read your saved decision for this exact action.",
            guard_home=store_guard_home(store),
        )
    if not isinstance(result, Mapping) or result.get("ignored_local_integrity"):
        return None
    decision = result.get("decision")
    if not isinstance(decision, Mapping):
        return None
    if (
        decision.get("scope") != "artifact"
        or decision.get("artifact_id") != artifact_id
        or decision.get("artifact_hash") != token
    ):
        return None
    action = decision.get("action")
    if action == "block":
        return _saved_block_response(
            harness,
            native_result,
            reason_code="saved_exact_action_block",
            reason="You chose to always block this exact action in HOL Guard.",
            guard_home=store_guard_home(store),
        )
    if action != "allow" or decision.get("source") != "approval-gate" or decision.get("expires_at"):
        return None
    if not _native_review_is_approvable(native_result):
        return None
    allowed = dict(native_result)
    allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
    return render_accepted_allow(harness, allowed, guard_home=store_guard_home(store))


def native_exact_command_block_response(
    store: object,
    *,
    harness: str,
    command: str | None,
    native_result: Mapping[str, object],
    workspace: Path | None,
) -> dict[str, object] | None:
    """Apply a saved block on this exact shell command; ``None`` keeps the review flow.

    Guard Cloud policy rules and remembered decisions save "block this command"
    under the exact-command artifact ids, which a native review's exact-action
    token never names. The store's lookup owns expiry, harness scope and
    integrity; this only asks it about those ids, so a block keeps the command
    from running whatever allow the review would otherwise reuse.
    """

    if command is None or not _is_shell_action(native_result):
        return None
    try:
        exact_ids, _memory_id = memory_lookup_candidates(
            harness,
            None,
            memory_command=command,
            memory_artifact_type="shell_command",
            memory_artifact_name=None,
            guard_home=store_guard_home(store),
        )
        if not exact_ids or not policy_decision_block_exists(store, harness=harness, artifact_ids=exact_ids):
            return None
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # A failed probe cannot tell "no block" apart from a block it missed,
        # and an allowed command would run on that answer, so it stops here.
        _LOGGER.warning("Native exact-command block probe failed (%s)", type(error).__name__)
        return _saved_block_response(
            harness,
            native_result,
            reason_code="saved_exact_command_unreadable",
            reason="HOL Guard could not check this command against saved blocks. Try it again in a moment.",
            guard_home=store_guard_home(store),
        )
    lookup = getattr(store, "resolve_policy_decision_lookup", None)
    if not callable(lookup):
        return None
    for exact_id in exact_ids:
        try:
            result = lookup(
                harness,
                exact_id,
                workspace=str(workspace) if workspace is not None else None,
                consume_one_shot=False,
            )
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
            # A block for this command exists but could not be read.
            _LOGGER.warning("Native exact-command block lookup failed (%s)", type(error).__name__)
            return _saved_block_response(
                harness,
                native_result,
                reason_code="saved_exact_command_unreadable",
                reason=f"HOL Guard could not read the saved block for this exact command. {_EXACT_COMMAND_RETRY_HINT}",
                guard_home=store_guard_home(store),
            )
        decision = result.get("decision") if isinstance(result, Mapping) else None
        if (
            not isinstance(decision, Mapping)
            or decision.get("scope") != "artifact"
            or decision.get("artifact_id") != exact_id
            or decision.get("action") != "block"
        ):
            continue
        if decision.get("source") in REMOTE_POLICY_SOURCES:
            reason = f"Your Guard Cloud policy blocks this exact command. {_EXACT_COMMAND_RETRY_HINT}"
            reason_code = "policy_exact_command_block"
        else:
            reason = f"You chose to always block this exact command in HOL Guard. {_EXACT_COMMAND_RETRY_HINT}"
            reason_code = "saved_exact_command_block"
        return _saved_block_response(
            harness,
            native_result,
            reason_code=reason_code,
            reason=reason,
            guard_home=store_guard_home(store),
        )
    return None


def _is_shell_action(native_result: Mapping[str, object]) -> bool:
    action = native_result.get("action")
    return isinstance(action, Mapping) and action.get("action_type") in _SHELL_ACTION_TYPES


def store_guard_home(store: object) -> Path | None:
    """The store's Guard home, so the resident renders against the right state directory."""

    home = getattr(store, "guard_home", None)
    return home if isinstance(home, Path) else None


def _saved_block_response(
    harness: str,
    native_result: Mapping[str, object],
    *,
    reason_code: str,
    reason: str,
    guard_home: Path | None = None,
) -> dict[str, object]:
    blocked = dict(native_result)
    blocked.update(
        decision="deny",
        minimum_action="block",
        policy_action="block",
        reason_code=reason_code,
        reason=reason,
    )
    response = render_pre_tool(harness, blocked, guard_home=guard_home)
    response["approval_reuse_status"] = "blocked"
    return response


def _native_review_is_approvable(native_result: Mapping[str, object]) -> bool:
    """A review the user answers; their exact-action allow holds whatever its action type.

    See ``docs/guard/approval-invariant.md``.
    """

    return native_result.get("policy_action") in {"review", "require-reapproval"} and native_result.get(
        "minimum_action"
    ) in {"review", "require-reapproval"}


__all__ = [
    "EXACT_ACTION_CONTEXT_TOKEN_KEY",
    "EXACT_ACTION_IDENTITY_KIND_KEY",
    "ONCE_ONLY_REASON_KEY",
    "native_exact_command_block_response",
    "native_saved_decision_response",
]
