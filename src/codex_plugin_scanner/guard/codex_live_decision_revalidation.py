"""Bind live Codex completion to the exact action and current policy result."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from .cli.commands_support_hook_payload import _action_envelope_json, _hook_action_envelope

FreshHookReviewer = Callable[
    [dict[str, object], Path | None, str | None, str | None],
    Mapping[str, object] | None,
]


def revalidate_codex_live_allow(
    request: object,
    payload: Mapping[str, object],
    *,
    home_dir: Path,
    reviewer: FreshHookReviewer,
    claimed_saved_allow_hash: str | None = None,
    claimed_approval_request_id: str | None = None,
) -> bool:
    """Return true only when the exact original action is freshly allowed."""

    if not isinstance(request, Mapping):
        return False
    request_mapping = cast(Mapping[str, object], request)
    if request_mapping.get("resolution_action") != "allow":
        return False
    raw_hook_input = payload.get("hook_input")
    if not isinstance(raw_hook_input, str):
        return False
    try:
        decoded_hook_payload = cast(object, json.loads(raw_hook_input))
    except json.JSONDecodeError:
        return False
    if not isinstance(decoded_hook_payload, dict):
        return False
    hook_payload = cast(dict[str, object], decoded_hook_payload)
    if hook_payload.get("hook_event_name") != "PreToolUse":
        return False
    workspace_value = request_mapping.get("workspace")
    workspace = Path(workspace_value) if isinstance(workspace_value, str) and workspace_value else None
    envelope = _hook_action_envelope(
        harness="codex",
        payload=hook_payload,
        home_dir=home_dir,
        workspace=workspace,
    )
    if _action_envelope_json(envelope) != request_mapping.get("action_envelope_json"):
        return False
    fresh_review = reviewer(
        hook_payload,
        workspace,
        claimed_saved_allow_hash,
        claimed_approval_request_id,
    )
    if not isinstance(fresh_review, Mapping):
        return False
    hook_output = fresh_review.get("hookSpecificOutput")
    if not isinstance(hook_output, Mapping):
        return False
    hook_output_mapping = cast(Mapping[str, object], hook_output)
    return hook_output_mapping.get("hookEventName") == "PreToolUse" and hook_output_mapping.get(
        "permissionDecision"
    ) not in {"deny", "block"}


__all__ = ["FreshHookReviewer", "revalidate_codex_live_allow"]
