"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_runtime_artifacts import _optional_string


from ..native_hook_authority_state import (
    HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE,
    hook_authority_state,
)
from ..native_hook_decision import native_permission_persist_plan
from ._commands_shared import *
from .commands_parser_helpers import *

_CURSOR_PENDING_MAX_AGE_SECONDS = 30 * 60


def _persist_claude_native_permission_plan(
    *,
    store: GuardStore,
    artifact_id: str,
    artifact_hash: str,
    artifact_type: str | None,
    config_path: str | None,
    source_scope: str | None,
    raw_command_text: object,
    wrapper_chain: object,
    action: str,
    reason: str,
    source: str,
    authoritative_action: str | None,
) -> dict[str, Any]:
    """Ask the resident what a native approval saves; raises before any write when it cannot say."""

    return native_permission_persist_plan(
        {
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
            "config_path": config_path,
            "source_scope": source_scope,
            "raw_command_text": raw_command_text,
            "wrapper_chain": wrapper_chain,
            "action": action,
            "reason": reason,
            "source": source,
            "authoritative_action": authoritative_action,
        },
        guard_home=Path(store.guard_home),
    )


def _write_claude_native_permission_plan(
    *,
    store: GuardStore,
    plan: Mapping[str, Any],
    artifact_id: str,
    reason: str,
    source: str,
    now: str,
) -> bool:
    """Write the policy row and the events the plan names, in its order."""

    try:
        for event in plan["events"]:
            if event["before_policy"]:
                store.add_event(event["name"], event["payload"], now)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action=plan["policy_action"],
                artifact_id=artifact_id,
                artifact_hash=plan["stored_artifact_hash"],
                reason=reason,
                source=source,
            ),
            now,
        )
        for event in plan["events"]:
            if not event["before_policy"]:
                store.add_event(event["name"], event["payload"], now)
    except (ApprovalGateError, OSError, sqlite3.Error):
        return False
    return True


def _persist_claude_native_permission_policy(
    *,
    store: GuardStore,
    artifact_id: str,
    artifact_hash: str,
    artifact_type: str | None = None,
    config_path: str | None = None,
    source_scope: str | None = None,
    raw_command_text: str | None = None,
    wrapper_chain: Sequence[object] | None = None,
    action: str,
    reason: str,
    now: str,
    source: str = "claude-native-approval",
) -> bool:
    # The resident decides the stored hash (a well-formed v1 approval-context
    # token as given, else the runtime exact-match key) and the events; a
    # resident that cannot answer raises here and nothing is saved.
    plan = _persist_claude_native_permission_plan(
        store=store,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        artifact_type=artifact_type,
        config_path=config_path,
        source_scope=source_scope,
        raw_command_text=raw_command_text,
        wrapper_chain=wrapper_chain,
        action=action,
        reason=reason,
        source=source,
        authoritative_action=None,
    )
    return _write_claude_native_permission_plan(
        store=store,
        plan=plan,
        artifact_id=artifact_id,
        reason=reason,
        source=source,
        now=now,
    )


def _discard_claude_pending_permissions(store: GuardStore, payload: dict[str, object]) -> int:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return 0
    reply = hook_authority_state(
        store,
        "claude_discard_session",
        now=_now(),
        required_feature=HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE,
        session_id=session_id,
    )
    discarded = reply.get("discarded") if reply is not None else None
    return discarded if isinstance(discarded, int) and not isinstance(discarded, bool) else 0


__all__ = [
    "_discard_claude_pending_permissions",
    "_persist_claude_native_permission_policy",
]
