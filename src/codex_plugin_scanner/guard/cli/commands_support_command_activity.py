"""How a post-tool hook payload reports whether its tool call failed."""

from __future__ import annotations

from collections.abc import Mapping


def hook_post_succeeded(event: str, payload: Mapping[str, object]) -> bool:
    """Interpret only bounded native failure signals; absence means success."""

    if "failure" in event.strip().lower():
        return False
    for name in ("hook_event_name", "hookEventName"):
        raw_event = payload.get(name)
        if isinstance(raw_event, str) and raw_event.replace("_", "").replace("-", "").lower() == "posttoolusefailure":
            return False
    for key in ("is_error", "isError", "failed"):
        if payload.get(key) is True:
            return False
    if payload.get("success") is False:
        return False
    exit_code = payload.get("exit_code", payload.get("exitCode"))
    return not (type(exit_code) is int and exit_code != 0)


__all__ = [
    "hook_post_succeeded",
]
