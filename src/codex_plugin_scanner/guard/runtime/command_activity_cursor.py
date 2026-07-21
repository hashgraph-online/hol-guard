"""Trust boundary for Cursor command-activity post observers."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..adapters.cursor_native_approval import (
    after_shell_proof_from_env,
    cursor_observer_event_for_payload,
    ensure_cursor_hook_attestation_secret,
    managed_cursor_hook_invocation,
    normalize_cursor_shell_command,
    resolve_cursor_approval_binding,
    verify_cursor_after_observer_proof,
)
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
    try:
        secret = ensure_cursor_hook_attestation_secret(guard_home)
    except OSError:
        return False
    return verify_cursor_after_observer_proof(
        secret=secret,
        conversation_id=conversation_id,
        command=normalize_cursor_shell_command(command),
        approval_binding=approval_binding,
        proof=proof,
        observer_event=cursor_observer_event_for_payload(payload),
    )


__all__ = ["cursor_command_activity_observer_trusted"]
