"""Harness responses when native review cannot complete without stopping the session."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

_CLI_AVAILABILITY_FEATURE = "native-hook-availability-v1"
_CLI_AVAILABILITY_COMMAND = "hook-availability"
_EVENT_FIELDS = ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName")


def _runtime_availability(
    payload: Mapping[str, object], *, deadline: float | None = None
) -> dict[str, object] | None:
    """Ask the standalone Rust hook command for outage posture."""

    from ..mdm.runtime_request import runtime_answer

    request = {key: payload[key] for key in _EVENT_FIELDS if key in payload}
    answer = runtime_answer(
        _CLI_AVAILABILITY_FEATURE,
        _CLI_AVAILABILITY_COMMAND,
        request,
        output_limit=64 * 1024,
        timeout_seconds=1.0,
        deadline=deadline,
    )
    return dict(answer) if isinstance(answer, Mapping) else None


def canonical_hook_event_name(
    payload: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> str:
    """Recover only the wire event label for an outage response.

    Normal hook semantics use the resident's normalized event fact. The
    standalone Rust command preserves the same normalized wire label when the
    resident cannot be reached.
    """

    if guard_home is not None:
        from ..native_hook_render import native_hook_availability

        native = native_hook_availability(payload, guard_home=guard_home, deadline=deadline)
        event = native.get("event_name") if isinstance(native, dict) else None
        if isinstance(event, str) and event:
            return event
    native = _runtime_availability(payload, deadline=deadline)
    event = native.get("event_name") if native is not None else None
    if isinstance(event, str) and event:
        return event
    # A missing runtime cannot prove the wire event. Treat it as the protected
    # pre-tool envelope so the caller never turns an unknown hook into an allow.
    return "PreToolUse"


def hook_event_pauses_when_unavailable(
    event_name: str, *, guard_home: Path | None = None, deadline: float | None = None
) -> bool:
    """True when native miss must pause the harness instead of continuing the turn.

    Rust owns this answer in both the resident and standalone outage paths.
    """

    if guard_home is not None:
        from ..native_hook_render import native_hook_availability

        native = native_hook_availability({"event": event_name}, guard_home=guard_home, deadline=deadline)
        pauses = native.get("pauses") if isinstance(native, dict) else None
        if isinstance(pauses, bool):
            return pauses
    native = _runtime_availability({"event": event_name}, deadline=deadline)
    pauses = native.get("pauses") if native is not None else None
    return pauses if isinstance(pauses, bool) else True


def hook_event_is_permission_request(
    event_name: str, *, guard_home: Path | None = None, deadline: float | None = None
) -> bool:
    if guard_home is not None:
        from ..native_hook_render import native_hook_availability

        native = native_hook_availability({"event": event_name}, guard_home=guard_home, deadline=deadline)
        permission_request = native.get("permission_request") if isinstance(native, dict) else None
        if isinstance(permission_request, bool):
            return permission_request
    native = _runtime_availability({"event": event_name}, deadline=deadline)
    permission_request = native.get("permission_request") if native is not None else None
    return permission_request if isinstance(permission_request, bool) else False


def availability_harness_response(
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    reason: str,
    prompt_reason: str | None = None,
) -> dict[str, object]:
    """Fixed harness result when native review is unavailable.

    A missing resident never authorizes the tool. Watch recording continues
    only through the resident renderer, which the caller applies after this
    deny. Integrity failures stay denied as well.
    """

    from .hook_fail_closed import fail_closed_response

    return fail_closed_response(
        harness, event_name, reason=reason, reason_code=reason_code, prompt_reason=prompt_reason
    )


__all__ = [
    "availability_harness_response",
    "hook_event_is_permission_request",
    "hook_event_pauses_when_unavailable",
]
