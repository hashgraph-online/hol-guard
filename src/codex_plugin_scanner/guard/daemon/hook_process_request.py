"""Request shaping for persistent daemon hook workers."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .hook_process_protocol import HOOK_ENV_ALLOWLIST


def build_hook_process_review_request(
    *,
    payload: Mapping[str, object],
    harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    hook_env: Mapping[str, str],
    claim_saved_approval: bool,
    claimed_saved_allow_hash: str | None,
    claimed_trusted_request_override: bool,
    claimed_approval_request_id: str | None,
) -> dict[str, object]:
    return {
        "payload": dict(payload),
        "harness": harness,
        "home_dir": str(home_dir),
        "guard_home": str(guard_home),
        "workspace": str(workspace) if workspace is not None else None,
        "hook_env": {key: value for key, value in hook_env.items() if key in HOOK_ENV_ALLOWLIST},
        "claim_saved_approval": claim_saved_approval,
        "claimed_saved_allow_hash": claimed_saved_allow_hash,
        "claimed_trusted_request_override": claimed_trusted_request_override,
        "claimed_approval_request_id": claimed_approval_request_id,
    }


def runtime_hook_review_is_idempotent(payload: Mapping[str, object]) -> bool:
    event_name = payload.get("hook_event_name") or payload.get("hookEventName")
    if not isinstance(event_name, str):
        return False
    return any(
        isinstance(payload.get(identity_key), str) and bool(payload.get(identity_key))
        for identity_key in ("tool_call_id", "toolCallId", "action_id", "operation_id")
    )


__all__ = ["build_hook_process_review_request", "runtime_hook_review_is_idempotent"]
