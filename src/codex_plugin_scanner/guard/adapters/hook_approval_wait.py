"""Ask the native runtime how a Grok or Muse hook waits on its approval.

The resident (``hook_approval_wait``) decides whether a ``PreToolUse``
review waits, which requests it waits on, what a settled wait means and how
the answer is rewritten. Python keeps the store and the wait itself. A
resident that cannot answer leaves the review unchanged, so the call stays
blocked.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_ID_KEYS = ("primary_approval_request_id", "approval_request_id", "guardApprovalRequestId")
_URL_KEYS = ("primary_approval_url", "approval_url", "approval_center_url")


def _leaf(value: object) -> object:
    """Keep a string; anything else only matters to the resident by its truthiness."""

    return value if isinstance(value, str) else bool(value)


def _answer_fields(response: Mapping[str, object]) -> dict[str, object]:
    projected: dict[str, object] = {key: _leaf(response[key]) for key in (*_ID_KEYS, *_URL_KEYS) if key in response}
    queued = response.get("approval_requests")
    if isinstance(queued, list):
        projected["approval_requests"] = [
            {"request_id": _leaf(item.get("request_id")), "id": _leaf(item.get("id"))}
            if isinstance(item, Mapping)
            else _leaf(item)
            for item in queued
        ]
    return projected


def ask(harness: str, op: str, **fields: object) -> dict[str, Any]:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("hook_approval_wait", {"op": op, "harness": harness, **fields})
    except NativeRunnerAuthorityError:
        return {}


def _pairs(value: object) -> list[tuple[str, object]]:
    return (
        [(str(pair[0]), pair[1]) for pair in value if isinstance(pair, list) and len(pair) == 2]
        if isinstance(value, list)
        else []
    )


def plan_wait(
    harness: str, *, event_name: str, response: Mapping[str, object], timeout_seconds: int
) -> tuple[list[str], int]:
    """The requests a review waits on and for how long; none when it does not wait."""

    action = str(response.get("policy_action") or "")
    fields = {"event": event_name, "policy_action": action, "timeout": int(timeout_seconds)}
    plan = ask(harness, "plan", **fields, response=_answer_fields(response))
    request_ids = [item for item in plan.get("request_ids", []) if isinstance(item, str)]
    seconds = plan.get("seconds")
    if not request_ids or not isinstance(seconds, int) or seconds <= 0:
        return [], 0
    return request_ids, seconds


def settle_wait(
    harness: str, *, wait_result: Mapping[str, object], request_id: str
) -> tuple[str | None, list[tuple[str, object]]]:
    """The decision a finished wait reached and the fields the answer carries."""

    items = wait_result.get("items")
    rows = [
        {"action": _leaf(item.get("resolution_action"))} if isinstance(item, dict) else None
        for item in (items if isinstance(items, list) else [])
    ]
    settled = ask(harness, "settle", resolved=bool(wait_result.get("resolved")), rows=rows, request_id=request_id)
    decision = settled.get("decision")
    return (decision if decision in {"allow", "block"} else None), _pairs(settled.get("fields"))


def rewrite_answer(harness: str, decision: str, response: Mapping[str, object]) -> dict[str, object] | None:
    """A copy of ``response`` rewritten to the settled allow or deny."""

    edits = ask(harness, "rewrite", decision=decision)
    if not edits:
        return None
    rewritten = _edited(response, edits.get("set"), edits.get("drop"))
    hook_specific = rewritten.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        rewritten["hookSpecificOutput"] = _edited(hook_specific, edits.get("hook_set"), edits.get("hook_drop"))
    return rewritten


def resume_metadata(payload: Mapping[str, object]) -> dict[str, object]:
    return dict(_pairs(ask("grok", "resume_metadata", payload=_answer_fields(payload)).get("fields")))


def _edited(source: Mapping[str, object], sets: object, drops: object) -> dict[str, object]:
    target = {**source, **dict(_pairs(sets))}
    for key in drops if isinstance(drops, list) else []:
        target.pop(str(key), None)
    return target


__all__ = ["plan_wait", "resume_metadata", "rewrite_answer", "settle_wait"]
