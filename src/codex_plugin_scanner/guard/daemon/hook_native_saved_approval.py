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

from ..runtime.approval_context import build_approval_context_token, parse_approval_context_token
from ..store_policy_decision import policy_decision_hash_exists
from .hook_native_exact_identity import (
    GUARD_CONTROL,
    NO_COMMAND_IDENTITY,
    NON_OVERRIDABLE,
    PACKAGE_ACTION,
    UNPROVEN_LAUNCH,
    OnceOnlyError,
    tool_target_identity,
)
from .hook_native_launch_identity import launch_cwd, launch_identity
from .hook_native_review_binding import native_review_policy_binding
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import harness_json_from_native_pre_tool

_LOGGER = logging.getLogger(__name__)

EXACT_ACTION_CONTEXT_TOKEN_KEY = "exact_context_token"
EXACT_ACTION_IDENTITY_KIND_KEY = "exact_identity_kind"
ONCE_ONLY_REASON_KEY = "once_only_reason"
_NATIVE_EXACT_ACTION_POLICY_VERSION = "native-exact-action-v1"
_GUARD_CONTROL_ACTION_TYPES = frozenset({"guard_control", "guard-control", "guard_control_operation"})


class TokenUnset:
    """Sentinel type: distinguishes "not supplied" from a computed ``None`` token."""


TOKEN_UNSET = TokenUnset()


def native_exact_action_token(
    *,
    harness: str,
    tool_name: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
) -> str | None:
    """Return a persistent exact-action token, or ``None`` when only once is safe."""

    return native_exact_action_decision(
        harness=harness,
        tool_name=tool_name,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        home_dir=home_dir,
    )[0]


def native_exact_action_decision(
    *,
    harness: str,
    tool_name: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
) -> tuple[str | None, str | None]:
    """Return ``(token, once_only_reason)``; exactly one of them is set."""

    try:
        return _exact_action_token(
            harness=harness,
            tool_name=tool_name,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            home_dir=home_dir,
        ), None
    except OnceOnlyError as once_only:
        return None, once_only.reason


def _exact_action_token(
    *,
    harness: str,
    tool_name: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
) -> str:
    if not _native_review_is_overridable(native_result):
        raise OnceOnlyError(_non_overridable_reason(native_result))
    command = pre_tool_command(payload)
    has_command = command is not None and bool(command.strip())
    try:
        policy_binding = native_review_policy_binding(
            harness=harness, native_result=native_result, verified_receipt=native_receipt
        )
    except ValueError as error:
        raise OnceOnlyError(UNPROVEN_LAUNCH if has_command else NO_COMMAND_IDENTITY) from error
    cwd = launch_cwd(payload, workspace)
    if not has_command:
        if cwd is None:
            raise OnceOnlyError(NO_COMMAND_IDENTITY)
        launch, content = tool_target_identity(tool_name, payload, cwd=cwd, workspace=workspace, home_dir=home_dir)
    else:
        if cwd is None:
            raise OnceOnlyError(UNPROVEN_LAUNCH)
        try:
            launch = launch_identity(str(command), cwd=cwd, home_dir=home_dir)
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise OnceOnlyError(UNPROVEN_LAUNCH) from error
        content = {"command": command}
    if policy_binding is None:
        raise OnceOnlyError(UNPROVEN_LAUNCH)
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    try:
        token = build_approval_context_token(
            identity={
                "harness": harness,
                "tool_name": tool_name,
                "workspace": str(workspace.resolve()) if workspace is not None else None,
                "cwd": str(cwd),
                "launch": launch,
            },
            content=content,
            capabilities={
                "action_type": action_type if isinstance(action_type, str) else None,
                "minimum_action": str(native_result.get("minimum_action") or ""),
                "policy_action": str(native_result.get("policy_action") or ""),
                "reason_code": str(native_result.get("reason_code") or ""),
            },
            policy={
                "version": _NATIVE_EXACT_ACTION_POLICY_VERSION,
                "rule_digest": policy_binding["rule_digest"],
                "command_extensions": policy_binding["command_extensions"],
            },
            sandbox={"required": native_result.get("minimum_action") == "sandbox-required"},
        )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise OnceOnlyError(UNPROVEN_LAUNCH) from error
    if parse_approval_context_token(token) is None:
        raise OnceOnlyError(UNPROVEN_LAUNCH)
    return token


def _non_overridable_reason(native_result: Mapping[str, object]) -> str:
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    if action_type in _GUARD_CONTROL_ACTION_TYPES:
        return GUARD_CONTROL
    if action_type == "package":
        return PACKAGE_ACTION
    return NON_OVERRIDABLE


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
        )
    if action != "allow" or decision.get("source") != "approval-gate" or decision.get("expires_at"):
        return None
    if not _native_review_is_overridable(native_result):
        return None
    allowed = dict(native_result)
    allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
    response = harness_json_from_native_pre_tool(harness, allowed)
    response["approval_reuse_status"] = "accepted"
    return response


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
) -> dict[str, object] | None:
    """Return the saved exact-action outcome for a paused native review.

    ``precomputed_token`` lets the caller reuse the token it already derived for
    this exact request instead of repeating its filesystem and resident work.
    """

    token = (
        native_exact_action_token(
            harness=harness,
            tool_name=tool_name,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            home_dir=home_dir,
        )
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


def _saved_block_response(
    harness: str, native_result: Mapping[str, object], *, reason_code: str, reason: str
) -> dict[str, object]:
    blocked = dict(native_result)
    blocked.update(
        decision="deny",
        minimum_action="block",
        policy_action="block",
        reason_code=reason_code,
        reason=reason,
    )
    response = harness_json_from_native_pre_tool(harness, blocked)
    response["approval_reuse_status"] = "blocked"
    return response


def _native_review_is_overridable(native_result: Mapping[str, object]) -> bool:
    if native_result.get("policy_action") not in {"review", "require-reapproval"}:
        return False
    if native_result.get("minimum_action") not in {"review", "require-reapproval"}:
        return False
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    return action_type not in {*_GUARD_CONTROL_ACTION_TYPES, "package"}


__all__ = [
    "EXACT_ACTION_CONTEXT_TOKEN_KEY",
    "EXACT_ACTION_IDENTITY_KIND_KEY",
    "ONCE_ONLY_REASON_KEY",
    "TOKEN_UNSET",
    "TokenUnset",
    "native_exact_action_decision",
    "native_exact_action_token",
    "native_saved_decision_response",
    "native_saved_review_response",
]
