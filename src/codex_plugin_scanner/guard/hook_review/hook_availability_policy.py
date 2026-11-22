"""Transport bridge for the Rust-owned hook availability projection."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from threading import Lock

_CLI_AVAILABILITY_FEATURE = "native-hook-availability-v1"
_CLI_AVAILABILITY_COMMAND = "hook-availability"
_EVENT_FIELDS = ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName")
_PASSIVE_EVENT_COMPACT = frozenset(
    {
        "sessionstart",
        "sessionend",
        "subagentstart",
        "subagentstop",
        "subagentend",
        "stop",
        "notification",
        "taskstart",
        "taskerror",
        "sessionshutdown",
        "permissiondenied",
    }
)
_RUNTIME_AVAILABILITY_CACHE: dict[tuple[tuple[str, str], ...], dict[str, object]] = {}
_RUNTIME_AVAILABILITY_LOCK = Lock()


def _wire_event_name(payload: Mapping[str, object]) -> str:
    """Preserve a caller's wire label when Rust itself is unavailable."""

    for key in _EVENT_FIELDS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            stripped = value.strip()
            compact = stripped.lower().replace("_", "").replace("-", "")
            if compact in {"prompt", "userpromptsubmit", "userpromptsubmitted"}:
                return "UserPromptSubmit"
            return stripped
    return "PreToolUse"


def _runtime_availability(payload: Mapping[str, object], *, deadline: float | None = None) -> dict[str, object] | None:
    """Decode the standalone Rust availability projection."""

    from ..mdm.runtime_request import runtime_answer

    request = {key: payload[key] for key in _EVENT_FIELDS if key in payload}
    cache_key = tuple((key, value) for key, value in request.items() if isinstance(value, str))
    with _RUNTIME_AVAILABILITY_LOCK:
        cached = _RUNTIME_AVAILABILITY_CACHE.get(cache_key)
    if cached is not None:
        return dict(cached)
    answer = runtime_answer(
        _CLI_AVAILABILITY_FEATURE,
        _CLI_AVAILABILITY_COMMAND,
        request,
        output_limit=64 * 1024,
        timeout_seconds=1.0,
        deadline=deadline,
    )
    if not isinstance(answer, Mapping):
        return None
    result = dict(answer)
    with _RUNTIME_AVAILABILITY_LOCK:
        _RUNTIME_AVAILABILITY_CACHE[cache_key] = result
    return result


def _native_availability(
    payload: Mapping[str, object], *, guard_home: Path | None, deadline: float | None
) -> dict[str, object] | None:
    """Ask Rust for availability, using the resident before standalone transport."""

    from ..native_hook_render import native_hook_availability

    if guard_home is not None:
        resident = native_hook_availability(payload, guard_home=guard_home, deadline=deadline)
        if isinstance(resident, Mapping):
            return dict(resident)
    return _runtime_availability(payload, deadline=deadline)


def canonical_hook_event_name(
    payload: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> str:
    """Return the event label projected by Rust for an outage response."""

    native = _native_availability(payload, guard_home=guard_home, deadline=deadline)
    event = native.get("event_name") if native is not None else None
    if isinstance(event, str) and event:
        return event
    # A missing runtime cannot provide a trusted alias projection. Preserve
    # only the caller's wire label rather than interpreting aliases here.
    return _wire_event_name(payload)


def hook_event_pauses_when_unavailable(
    event_name: str, *, guard_home: Path | None = None, deadline: float | None = None
) -> bool:
    """Return Rust's outage posture, failing closed when no projection arrives."""

    native = _native_availability({"event": event_name}, guard_home=guard_home, deadline=deadline)
    pauses = native.get("pauses") if native is not None else None
    if isinstance(pauses, bool):
        return pauses
    compact = event_name.strip().lower().replace("_", "").replace("-", "")
    return not (
        compact in _PASSIVE_EVENT_COMPACT
        or compact.startswith("after")
        or compact in {"posttool", "posttooluse", "posttoolcall"}
    )


def hook_event_is_permission_request(
    event_name: str, *, guard_home: Path | None = None, deadline: float | None = None
) -> bool:
    """Return Rust's permission-request classification."""

    native = _native_availability({"event": event_name}, guard_home=guard_home, deadline=deadline)
    permission_request = native.get("permission_request") if native is not None else None
    return permission_request if isinstance(permission_request, bool) else False


def availability_harness_response(
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    reason: str,
    prompt_reason: str | None = None,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object]:
    """Render the fail-closed response through Rust, with the existing envelope fallback."""

    from ..native_hook_render import native_render_cli

    rendered = native_render_cli(
        "availability_response",
        harness,
        {
            "event_name": event_name,
            "reason": reason,
            "reason_code": reason_code,
            "prompt_reason": prompt_reason,
        },
        guard_home=guard_home,
        deadline=deadline,
    )
    if rendered is not None and rendered[0] == "document" and rendered[1] is not None:
        return rendered[1]

    from .hook_fail_closed import fail_closed_response

    return fail_closed_response(
        harness,
        event_name,
        reason=reason,
        reason_code=reason_code,
        prompt_reason=prompt_reason,
    )


__all__ = [
    "availability_harness_response",
    "canonical_hook_event_name",
    "hook_event_is_permission_request",
    "hook_event_pauses_when_unavailable",
]
