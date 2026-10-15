"""Cursor hook payload normalization and response mapping."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..action_lattice import is_guard_action
from ..approval_hook_copy import with_approval_review_url
from ..daemon.hook_availability_policy import hook_reason_continues_session
from ..native_hook_adapter import native_prepare_payload


def prepare_cursor_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Cursor hook stdin JSON into Guard hook normalization shape."""

    return native_prepare_payload("cursor", payload)


def _validated_hol_guard_src_path(path_str: str) -> str | None:
    """Accept only directories that look like a hol-guard source tree."""

    try:
        if not isinstance(path_str, str) or not path_str.strip():
            return None
        candidate = Path(path_str.strip()).expanduser().resolve()
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    if not candidate.is_dir():
        return None
    if not (candidate / "codex_plugin_scanner").is_dir():
        return None
    return str(candidate)


def cursor_hook_would_prompt_user(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> bool:
    """Return True when Guard maps this hook result to Cursor permission ask."""

    del guard_payload
    return policy_action in {"require-reapproval", "review"}


def cursor_hook_requires_approval_center_queue(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> bool:
    """Return True when Cursor native prompts should also appear in the approval center.

    Currently equivalent to ``cursor_hook_would_prompt_user``; kept separate so the
    two concepts can diverge without touching call sites.
    """

    return cursor_hook_would_prompt_user(
        policy_action=policy_action,
        guard_payload=guard_payload,
    )


def cursor_hook_response_from_guard(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object],
    hook_event_name: str,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Translate Guard hook JSON into Cursor hook stdout JSON."""

    permission = _cursor_permission_for_policy(policy_action, guard_payload)
    reason = _cursor_block_reason(guard_payload, guard_home=guard_home)
    raw_event = hook_event_name.strip().lower()
    if raw_event == "beforereadfile":
        read_permission = _cursor_read_file_permission(permission)
        response: dict[str, object] = {"permission": read_permission}
        if read_permission == "deny":
            response["user_message"] = reason
        return {key: value for key, value in response.items() if value is not None}
    if raw_event == "pretooluse" and permission == "ask":
        # Cursor's preToolUse only stops the tool on deny; ask would let the write run.
        permission = "deny"
    response: dict[str, object] = {"permission": permission}
    if permission != "allow":
        response["user_message"] = reason
        response["agent_message"] = reason
    return {key: value for key, value in response.items() if value is not None}


def cursor_hook_should_block(*, policy_action: str) -> bool:
    return policy_action in {"block", "sandbox-required"}


def _cursor_permission_for_policy(
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> str:
    payload = {} if guard_payload is None else guard_payload
    reason_code = str(payload.get("reason_code") or "")
    if hook_reason_continues_session(reason_code):
        return "allow"
    if not is_guard_action(policy_action):
        return "deny"
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action in {"require-reapproval", "review"}:
        return "ask"
    return "allow"


def _cursor_read_file_permission(permission: str) -> str:
    if permission in {"deny", "ask"}:
        return "deny"
    return "allow"


def _cursor_block_reason(guard_payload: Mapping[str, object], *, guard_home: Path | None = None) -> str:
    reason: str | None = None
    for key in ("reason", "stopReason", "systemMessage", "review_hint", "risk_summary", "why_now", "risk_headline"):
        value = guard_payload.get(key)
        if isinstance(value, str) and value.strip():
            reason = value.strip()
            break
    if reason is None:
        hook_output = guard_payload.get("hookSpecificOutput")
        if isinstance(hook_output, Mapping):
            nested_reason = hook_output.get("permissionDecisionReason")
            if isinstance(nested_reason, str) and nested_reason.strip():
                reason = nested_reason.strip()
    if reason is None:
        decision = guard_payload.get("decision_v2_json")
        if isinstance(decision, Mapping):
            for key in ("harness_message", "retry_instruction", "user_body", "user_title"):
                value = decision.get(key)
                if isinstance(value, str) and value.strip():
                    reason = value.strip()
                    break
    if reason is None:
        reason = "HOL Guard blocked this Cursor action."
    return with_approval_review_url(reason, guard_payload, guard_home=guard_home)
