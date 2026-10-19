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

from ..store_policy_decision import policy_decision_hash_exists
from .hook_fail_closed import render_accepted_allow, render_pre_tool
from .hook_native_exact_action import GUARD_CONTROL_ACTION_TYPES, native_exact_action

_LOGGER = logging.getLogger(__name__)

EXACT_ACTION_CONTEXT_TOKEN_KEY = "exact_context_token"
EXACT_ACTION_IDENTITY_KIND_KEY = "exact_identity_kind"
ONCE_ONLY_REASON_KEY = "once_only_reason"


class TokenUnset:
    """Sentinel type: distinguishes "not supplied" from a computed ``None`` token."""


TOKEN_UNSET = TokenUnset()


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


def native_saved_review_response(
    store: object,
    *,
    harness: str,
    tool_name: str,
    artifact_id: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
    precomputed_token: str | None | TokenUnset = TOKEN_UNSET,
    guard_home: Path | None = None,
) -> dict[str, object] | None:
    """Return the saved exact-action outcome for a paused native review.

    ``precomputed_token`` lets the caller reuse the token it already derived for
    this exact request instead of repeating its filesystem and resident work.
    """

    token = (
        native_exact_action(
            harness=harness,
            tool_name=tool_name,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )[0]
        if isinstance(precomputed_token, TokenUnset)
        else precomputed_token
    )
    return native_saved_decision_response(
        store,
        harness=harness,
        token=token,
        artifact_id=artifact_id,
        native_result=native_result,
        workspace=workspace,
    )


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


def _native_review_is_overridable(native_result: Mapping[str, object]) -> bool:
    """A review a broad local-CLI grant may lift: never Guard control or a package action."""

    if not _native_review_is_approvable(native_result):
        return False
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    return action_type not in {*GUARD_CONTROL_ACTION_TYPES, "package"}


__all__ = [
    "EXACT_ACTION_CONTEXT_TOKEN_KEY",
    "EXACT_ACTION_IDENTITY_KIND_KEY",
    "ONCE_ONLY_REASON_KEY",
    "TOKEN_UNSET",
    "TokenUnset",
    "native_saved_decision_response",
    "native_saved_review_response",
]
