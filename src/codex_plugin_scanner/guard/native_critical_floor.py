"""Present request-bound native command floors; unavailable authority blocks."""

from __future__ import annotations

from pathlib import Path
from typing import cast, get_args

from .models import GuardAction
from .native_request_context import NativeRequestContextFailure, _absolute_text, _call


def native_critical_floor_action(
    command_text: str, *, cwd: Path | None = None, home_dir: Path | None = None
) -> GuardAction:
    try:
        payload = _call(
            {
                "kind": "critical_floor",
                "body": {
                    "script": command_text,
                    "cwd": _absolute_text(cwd or Path.cwd()),
                    "home_dir": _absolute_text(home_dir or Path.home()),
                },
            },
            source="direct_command",
            guard_home=None,
            budget_ms=500,
        )
        if isinstance(payload, NativeRequestContextFailure):
            return "block"
        if set(payload) != {"kind", "action"} or payload["kind"] != "critical_floor":
            return "block"
        action = payload["action"]
        if not isinstance(action, str) or action not in get_args(GuardAction):
            return "block"
        return cast(GuardAction, action)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        return "block"
