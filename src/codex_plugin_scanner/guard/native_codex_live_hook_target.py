"""Transport for the resident's Codex continuation target facts."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

from .native_runner_authority import native_runner_authority

_WAITS_KEY = "codex_hook_waits_for_browser_approval"
_PROCESS_KEY = "codex_browser_wait_process"
_METADATA_TEXT_KEYS = (
    "codex_browser_wait_deadline_at",
    "browser_wait_deadline_at",
    "hook_event_name",
    "event",
    "workspace",
)


class LiveHookTarget(NamedTuple):
    wait_deadline: datetime | None
    process_unavailable: bool


def native_live_hook_target(
    guard_home: Path,
    *,
    operation: Mapping[str, object] | None = None,
    metadata: Mapping[str, object],
) -> LiveHookTarget:
    declared = metadata.get(_WAITS_KEY) is True
    fallback = LiveHookTarget(None, declared)
    identity = metadata.get(_PROCESS_KEY)
    if not isinstance(identity, Mapping) or (operation is None and not declared):
        return fallback
    facts = {key: value for key in _METADATA_TEXT_KEYS if isinstance(value := metadata.get(key), str)}
    try:
        answer = native_runner_authority(
            "codex_live_hook_target",
            {
                "operation": None
                if operation is None
                else {
                    key: value
                    for key in ("status", "updated_at", "created_at")
                    if isinstance(value := operation.get(key), str)
                },
                "metadata": {**facts, _WAITS_KEY: declared, _PROCESS_KEY: dict(identity)},
            },
            guard_home=guard_home,
        )
        unavailable = answer.get("process_unavailable")
        deadline_text = answer["wait_deadline"]
        if not isinstance(unavailable, bool) or (deadline_text is not None and not isinstance(deadline_text, str)):
            return fallback
        deadline = datetime.fromisoformat(deadline_text) if deadline_text is not None else None
        if deadline is not None and deadline.utcoffset() is None:
            return fallback
    except (KeyError, TypeError, ValueError):
        return fallback
    return LiveHookTarget(deadline, unavailable)
