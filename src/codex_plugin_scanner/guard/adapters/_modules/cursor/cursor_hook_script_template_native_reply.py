"""Installed Cursor hook copy that takes a daemon reply the native bridge already received."""

from __future__ import annotations

HOOK_SCRIPT_TEMPLATE_NATIVE_REPLY = """
_NATIVE_DAEMON_REPLY_FLAG = "--cursor-native-daemon-reply"
_NATIVE_DAEMON_REPLY_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})


def _native_daemon_reply_from_argv() -> tuple[int, str, str] | None:
    # The native bridge already posted this hook to the daemon and hands over
    # a reply it could not render, so the daemon never reviews it twice. Only
    # a restrictive reply is taken; anything else asks the daemon as usual.
    args = sys.argv
    try:
        index = args.index(_NATIVE_DAEMON_REPLY_FLAG)
    except ValueError:
        return None
    if index + 1 >= len(args):
        return None
    body = str(args[index + 1]).strip()
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    policy_action = parsed.get("policy_action")
    if not isinstance(policy_action, str) or policy_action not in _NATIVE_DAEMON_REPLY_ACTIONS:
        return None
    return (0, body, "")

"""
