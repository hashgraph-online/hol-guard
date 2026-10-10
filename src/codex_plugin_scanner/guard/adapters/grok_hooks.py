"""Grok Build CLI hook payload and response helpers for HOL Guard."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from typing import TextIO

from ..native_hook_adapter import native_prepare_payload
from .grok_approval_resume import grok_resume_metadata_from_guard_payload

_GROK_EVENT_NAMES: dict[str, str] = {
    "pretooluse": "PreToolUse",
    "userpromptsubmit": "UserPromptSubmit",
    "userpromptsubmitted": "UserPromptSubmit",
    "posttooluse": "PostToolUse",
    "posttoolusefailure": "PostToolUse",
    "sessionstart": "SessionStart",
    "sessionend": "SessionEnd",
    "stop": "Stop",
    "subagentstart": "SubagentStart",
    "subagentstop": "SubagentStop",
    "subagentend": "SubagentStop",
    "permissiondenied": "PermissionDenied",
}

# These lifecycle events cannot reject a prompt or tool action.
# UserPromptSubmit is a gate: Grok honors decision:block, not decision:deny.
_OBSERVE_ONLY_EVENTS = frozenset(
    {
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "SubagentStop",
        "PostToolUse",
        "PermissionDenied",
    }
)


def _canonical_grok_event_name(raw_event: str) -> str:
    normalized = raw_event.replace("_", "").replace("-", "").lower()
    return _GROK_EVENT_NAMES.get(normalized, raw_event or "PreToolUse")


def is_grok_observe_only_event(event_name: str | None) -> bool:
    """Return whether Guard observes this Grok event without enforcement."""

    if not isinstance(event_name, str) or not event_name.strip():
        return False
    return _canonical_grok_event_name(event_name.strip()) in _OBSERVE_ONLY_EVENTS


def prepare_grok_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Grok hook stdin JSON into Guard hook normalization shape."""

    return native_prepare_payload("grok", payload)


def grok_hook_response_from_guard(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
    approval_payload: Mapping[str, object] | None = None,
    recording_only: bool = False,
) -> dict[str, object]:
    """Translate Guard policy action into Grok hook stdout JSON."""

    if is_grok_observe_only_event(event_name):
        # Passive callbacks do not authorize a prompt or tool action.
        return {}
    if _canonical_grok_event_name(event_name or "") == "UserPromptSubmit":
        if recording_only or policy_action in {"allow", "warn"}:
            return {}
        return {"decision": "block", "reason": reason.strip() or "Blocked by HOL Guard."}
    if recording_only:
        return {"decision": "allow"}
    if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
        cleaned_reason = _dedupe_grok_block_reason(reason.strip() if isinstance(reason, str) else "")
        response: dict[str, object] = {
            "decision": "deny",
            "reason": cleaned_reason or "Blocked by HOL Guard.",
        }
        response.update(grok_resume_metadata_from_guard_payload(approval_payload))
        return response
    return {"decision": "allow"}


def _dedupe_grok_block_reason(reason: str) -> str:
    if not reason:
        return reason
    marker = "Open HOL Guard to approve or keep this blocked:"
    first = reason.find(marker)
    if first == -1:
        return reason
    second = reason.find(marker, first + len(marker))
    if second == -1:
        return reason
    return reason[:second].rstrip()


_last_grok_policy_action = ""


def emit_grok_hook_response(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
    approval_payload: Mapping[str, object] | None = None,
    output_stream: TextIO | None = None,
) -> None:
    global _last_grok_policy_action
    recording_only = _recording_only_from_guard_home()
    live_action, live_reason, live_payload = _apply_live_approval_wait(
        policy_action=policy_action,
        reason=reason,
        event_name=event_name,
        approval_payload=approval_payload,
        recording_only=recording_only,
    )
    payload = grok_hook_response_from_guard(
        policy_action=live_action,
        reason=live_reason,
        event_name=event_name,
        approval_payload=live_payload,
        recording_only=recording_only,
    )
    _last_grok_policy_action = "allow" if payload.get("decision") not in {"deny", "block"} else live_action
    stream = output_stream if output_stream is not None else sys.stdout
    # stdout is the harness delivery channel; approval payloads must reach the operator.
    stream.write(json.dumps(payload, separators=(",", ":")) + "\n")  # codeql[py/clear-text-logging-sensitive-data]
    stream.flush()


def grok_hook_process_exit(policy_action: str) -> int:
    if _last_grok_policy_action == "allow":
        return 0
    if _recording_only_from_guard_home():
        return 0
    return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2


def _apply_live_approval_wait(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None,
    approval_payload: Mapping[str, object] | None,
    recording_only: bool = False,
) -> tuple[str, str, Mapping[str, object] | None]:
    if recording_only:
        return "allow", reason, approval_payload
    if policy_action not in {"review", "require-reapproval"} or not isinstance(approval_payload, Mapping):
        return policy_action, reason, approval_payload
    store = _guard_store_from_argv()
    if store is None:
        return policy_action, reason, approval_payload
    from ..config import load_guard_config
    from .grok_approval_resume import wait_for_grok_live_approval

    response_payload = dict(approval_payload)
    decision = wait_for_grok_live_approval(
        event_name=event_name or "",
        policy_action=policy_action,
        response_payload=response_payload,
        store=store,
        timeout_seconds=load_guard_config(store.guard_home).approval_wait_timeout_seconds,
        json_mode="--json" in sys.argv,
        payload=response_payload,
    )
    if decision == "allow":
        return "allow", "", response_payload
    if decision == "block":
        return "block", reason, response_payload
    return policy_action, reason, response_payload


def _guard_store_from_argv():
    home_value = None
    if "--guard-home" in sys.argv:
        index = sys.argv.index("--guard-home")
        if index + 1 < len(sys.argv):
            home_value = sys.argv[index + 1]
    if not home_value:
        home_value = os.environ.get("HOL_GUARD_HOME")
    if not home_value:
        return None
    from pathlib import Path

    from ..store import GuardStore

    return GuardStore(Path(home_value))


def grok_hook_should_block(*, policy_action: str, event_name: str | None = None) -> bool:
    if _recording_only_from_guard_home() or is_grok_observe_only_event(event_name):
        return False
    return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}


def _recording_only_from_guard_home() -> bool:
    store = _guard_store_from_argv()
    if store is None:
        return False
    from ..config import load_guard_config
    from ..protection_posture import protection_is_off

    config = load_guard_config(store.guard_home)
    return protection_is_off(posture=config.protection_posture, mode=config.mode)


__all__ = [
    "emit_grok_hook_response",
    "grok_hook_process_exit",
    "grok_hook_response_from_guard",
    "grok_hook_should_block",
    "is_grok_observe_only_event",
    "prepare_grok_hook_payload",
]
