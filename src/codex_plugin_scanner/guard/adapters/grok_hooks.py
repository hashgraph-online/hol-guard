"""Grok Build CLI hook payload and response helpers for HOL Guard."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

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


def grok_hook_process_exit(policy_action: str) -> int:
    if _last_grok_policy_action == "allow":
        return 0
    if _recording_only_from_guard_home():
        return 0
    return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2


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


def _recording_only_from_guard_home() -> bool:
    store = _guard_store_from_argv()
    if store is None:
        return False
    from ..config import load_guard_config
    from ..protection_posture import protection_is_off

    config = load_guard_config(store.guard_home)
    return protection_is_off(posture=config.protection_posture, mode=config.mode)


__all__ = [
    "grok_hook_process_exit",
    "grok_hook_response_from_guard",
    "is_grok_observe_only_event",
]
