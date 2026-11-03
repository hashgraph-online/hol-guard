"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


from ._commands_shared import *
from .commands_parser_helpers import *


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


__all__ = [
    "_write_claude_native_permission_plan",
]
