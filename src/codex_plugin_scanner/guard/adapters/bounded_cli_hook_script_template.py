"""The managed Grok hook client the native bridge reads its constants from."""

from __future__ import annotations

BOUNDED_HOOK_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run hol-guard install after moving Guard home.

The HOL Guard native runtime reads the constants below and answers the hook
itself; it never runs this file. Run without it, the hook fails closed.
"""
import json
import os
import sys
import threading

GUARD_HOME = __GUARD_HOME__
HARNESS = __HARNESS__
TIMEOUT_SECONDS = __TIMEOUT_SECONDS__

_MAX_INPUT_BYTES = 1000000
_REASON = "HOL Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."
_PROMPT_REASON = (
    "HOL Guard could not check this prompt, so it was blocked. If HOL Guard is not running or not responding, "
    "open HOL Guard and choose Troubleshoot Guard, then Restart Guard, or run hol-guard daemon recovery restart, "
    "then send the prompt again. For a custom Guard home, run hol-guard daemon recovery restart --guard-home <path>."
)
_EVENT_KEYS = ("hook_event_name", "hookEventName", "event", "eventName", "hook_name", "hookName")
_OBSERVED = {"sessionstart", "sessionend", "subagentstart", "subagentstop", "posttooluse", "permissiondenied"}
_PROMPTS = {"userpromptsubmit", "userpromptsubmitted"}
_LIFECYCLE = {"notification", "sessionshutdown", "stop", "subagentend", "taskerror", "taskstart", "posttool"}


def _read_input():
    chunks = []

    def _drain():
        size = 0
        while size <= _MAX_INPUT_BYTES:
            chunk = os.read(0, 65536)
            if not chunk:
                chunks.append(None)
                return
            chunks.append(chunk)
            size += len(chunk)

    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()
    reader.join(TIMEOUT_SECONDS)
    if reader.is_alive() or not chunks or chunks[-1] is not None:
        return None
    raw = b"".join(chunks[:-1])
    return raw[3:] if raw.startswith(b"\\xef\\xbb\\xbf") else raw


def _event(raw):
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return "pretooluse"
    if not isinstance(payload, dict):
        return "pretooluse"
    labels = [
        payload[key].strip().lower().replace("_", "").replace("-", "")
        for key in _EVENT_KEYS
        if isinstance(payload.get(key), str)
    ]
    events = {"pretooluse" if label == "pretoolcall" else label for label in labels}
    if not labels or not labels[0] or not all(label.isascii() for label in labels):
        return "pretooluse"
    if "pretooluse" in events and len(events) > 1:
        return "pretooluse"
    return labels[0]


def _decide(event):
    if event in _OBSERVED:
        return {}
    if event in _PROMPTS:
        return {
            "decision": "block",
            "reason": _PROMPT_REASON,
            "systemMessage": _PROMPT_REASON,
            "policy_action": "block",
            "reason_code": "native_prompt_unavailable",
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
        }
    if event in _LIFECYCLE or event.startswith("after"):
        return {"decision": "allow", "reason": _REASON}
    return {"decision": "deny", "reason": _REASON}


def _main():
    try:
        raw = _read_input()
        answer = _decide("pretooluse" if raw is None else _event(raw))
    except Exception:
        answer = _decide("pretooluse")
    sys.stdout.write(json.dumps(answer, separators=(",", ":")) + "\\n")
    sys.stdout.flush()
    os._exit(0)


_main()
'''
