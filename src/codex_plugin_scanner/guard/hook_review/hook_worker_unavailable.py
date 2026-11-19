"""Deterministic responses when the resident cannot identify a hook event."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .hook_availability_policy import availability_harness_response, canonical_hook_event_name

if TYPE_CHECKING:
    from .hook_worker import HookWorker

_PERMISSION_PASSTHROUGH_HARNESSES = frozenset({"codex", "copilot", "devin", "zcode", "muse"})


def unavailable_event_response(
    worker: HookWorker,
    *,
    payload: dict[str, object],
    harness: str,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None,
) -> dict[str, object]:
    """Return a fail-safe response after the resident misses event identity."""

    fallback_event = canonical_hook_event_name(payload, guard_home=guard_home, deadline=deadline)
    if fallback_event in {"PostToolUse", "PostToolUseFailure"}:
        from ..cli.commands_support_command_activity import hook_post_succeeded

        worker._record_post_tool_activity(
            harness=harness,
            payload=payload,
            succeeded=hook_post_succeeded(fallback_event, payload),
        )
    normalized_harness = harness.strip().lower().replace("_", "-")
    if fallback_event == "PermissionRequest":
        if normalized_harness == "claude-code":
            return {
                "guard_permission_passthrough": True,
                "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
            }
        if normalized_harness in _PERMISSION_PASSTHROUGH_HARNESSES:
            return {"hookSpecificOutput": {"hookEventName": "PermissionRequest"}}
    response = availability_harness_response(
        harness=harness,
        event_name=fallback_event,
        reason_code="native_hook_event_unavailable",
        reason="HOL Guard could not identify this hook event safely.",
    )
    return worker._apply_structured_unavailable_overlay(
        response,
        harness=harness,
        event_name=fallback_event,
        guard_home=guard_home,
        workspace=workspace,
    )
