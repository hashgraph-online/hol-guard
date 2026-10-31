"""The generated Cursor hook client.

Cursor runs this client behind Guard's native runtime, as ``guard-runtime
cursor-hook-bridge <python> -I <script> --cursor-hook-event <event>``. The
runtime reads the six constants the renderer writes and answers the hook
itself, so the client's own code never runs there. Every hook review needs
that runtime, so a hook that reaches the client directly has nothing left to
ask: Cursor's ``after*`` observers continue and every other hook is denied,
with the answer the runtime gives a hook it cannot complete.
"""

from __future__ import annotations

HOOK_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""
import json
import sys

GUARD_HOME = __GUARD_HOME__
GUARD_CLI = __GUARD_CLI__
GUARD_RECOVERY_COMMAND = __GUARD_RECOVERY_COMMAND__
GUARD_HOOK_ARGV = __GUARD_HOOK_ARGV__
GUARD_INHERIT_ENV_KEYS = __GUARD_INHERIT_ENV_KEYS__
GUARD_HOOK_TIMEOUT_SECONDS = __GUARD_HOOK_TIMEOUT_SECONDS__
_OBSERVER_EVENTS = frozenset({"aftershellexecution", "aftermcpexecution"})
_UNAVAILABLE_REASON = "HOL Guard could not complete the native hook decision safely."


def _hook_event() -> str:
    args = sys.argv
    if "--cursor-hook-event" not in args:
        return ""
    index = args.index("--cursor-hook-event") + 1
    return str(args[index]) if index < len(args) else ""


def main() -> int:
    """Answer a hook Guard's native runtime did not answer in front of this client."""

    compact = _hook_event().strip().lower().replace("_", "").replace("-", "")
    if compact in _OBSERVER_EVENTS:
        print("{}")
        return 0
    print(json.dumps({"permission": "deny", "user_message": _UNAVAILABLE_REASON}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
'''

__all__ = ["HOOK_SCRIPT_TEMPLATE"]
