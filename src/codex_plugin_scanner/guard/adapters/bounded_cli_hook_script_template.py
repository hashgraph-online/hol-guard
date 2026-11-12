"""The managed Grok hook client the native bridge reads its constants from."""

from __future__ import annotations

BOUNDED_HOOK_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run hol-guard install after moving Guard home.

The HOL Guard native runtime reads the constants below and answers the hook
itself; it never runs this file. Run without it, the hook fails closed.
"""
import json
import sys

GUARD_HOME = __GUARD_HOME__
HARNESS = __HARNESS__
TIMEOUT_SECONDS = __TIMEOUT_SECONDS__

_REASON = "HOL Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."
_OBSERVED = {"sessionstart", "sessionend", "subagentstart", "subagentstop", "posttooluse", "permissiondenied"}


def _event():
    try:
        payload = json.loads(sys.stdin.read(1000000))
    except (OSError, ValueError):
        return ""
    event = payload.get("hook_event_name") if isinstance(payload, dict) else None
    return event.strip().lower().replace("_", "").replace("-", "") if isinstance(event, str) else ""


_DECISION = "allow" if _event() in _OBSERVED else "deny"
sys.stdout.write(json.dumps({"decision": _DECISION, "reason": _REASON}, separators=(",", ":")) + "\\n")
'''
