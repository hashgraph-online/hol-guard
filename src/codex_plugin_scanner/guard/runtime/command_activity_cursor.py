"""Trust boundary for Cursor command-activity post observers."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..adapters.cursor_native_approval import (
    after_shell_proof_from_env,
    cursor_observer_event_for_payload,
    managed_cursor_hook_invocation,
    resolve_cursor_approval_binding,
)
from ..native_cursor_observer_proof import native_cursor_observer_proof_valid
from .harness_attribution import cursor_runtime_detected


def cursor_command_activity_observer_trusted(
    *,
    guard_home: Path,
    payload: Mapping[str, object],
    conversation_id: str,
    command: str,
    env: Mapping[str, str],
) -> bool:
    """Verify a managed Cursor observer without requiring a pending approval."""

    if not managed_cursor_hook_invocation(env) or not cursor_runtime_detected(env):
        return False
    approval_binding = resolve_cursor_approval_binding(payload, env=env)
    proof = after_shell_proof_from_env(env)
    if approval_binding is None or proof is None:
        return False
    return native_cursor_observer_proof_valid(
        guard_home=guard_home,
        conversation_id=conversation_id,
        command=command,
        approval_binding=approval_binding,
        observer_event=cursor_observer_event_for_payload(payload),
        proof=proof,
    )


__all__ = ["cursor_command_activity_observer_trusted"]
