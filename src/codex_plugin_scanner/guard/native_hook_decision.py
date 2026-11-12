"""Hook decisions answered by the native runtime.

The shared ``hook_decide`` resident operation, the review response it
renders, and the shape of what a Claude-native approval saves. There is no Python evaluator: a reply that is
not a bound, strictly decoded ``ok`` raises ``NativeHookDecisionError`` and
callers fail closed.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_execution import _resident_request
from .native_resident_decision import ResidentOperation, resident_decide, shape_fields

HOOK_DECISION_FEATURE = "hook-decision-v1"
# The rendered response a native review shows the agent, silent or paused; a
# resident that predates it rejects the query, and the hook fails closed.
HOOK_DECISION_REVIEW_RESPONSE_FEATURE = "hook-decision-review-response-v1"
_UNAVAILABLE = "native_hook_decision_unavailable"
_INVALID = "native_hook_decision_payload_invalid"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024

_OPT_STR = (str, type(None))
_PERSIST_PLAN_FIELDS: dict[str, Any] = {
    "stored_artifact_hash": _OPT_STR,
    "policy_action": _OPT_STR,
    "events": list,
    "inventory_approved": bool,
}
_PERSIST_EVENT_FIELDS: dict[str, Any] = {"name": str, "payload": dict, "before_policy": bool}
# Whether each event the plan may carry is written before the policy row.
_PERSIST_EVENT_PHASE: dict[str, bool] = {
    "claude/native_permission_exact_key_missing": True,
    "claude/native_permission_saved": False,
    "claude/native_permission_current_policy_retained": False,
}
# The event sequences a plan may carry: with a policy row to write, and without.
_PERSIST_EVENT_SEQUENCES: dict[bool, frozenset[tuple[str, ...]]] = {
    True: frozenset(
        {
            ("claude/native_permission_saved",),
            ("claude/native_permission_exact_key_missing", "claude/native_permission_saved"),
        }
    ),
    False: frozenset({("claude/native_permission_current_policy_retained",)}),
}


class NativeHookDecisionError(RuntimeError):
    """No authoritative decision; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _shape(value: object, fields: Mapping[str, Any]) -> dict[str, Any]:
    return shape_fields(value, fields, lambda: NativeHookDecisionError(_INVALID))


_OPERATION = ResidentOperation(
    operation="hook_decide",
    feature=HOOK_DECISION_FEATURE,
    prefix="native_hook_decision",
    request_schema="guard-hook-decision-request.v1",
    result_schema="guard-hook-decision-result.v1",
    request_id_prefix="hook-decision",
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeHookDecisionError,
)


def _tilde_home() -> str | None:
    """``os.path.expanduser("~")``, or ``None`` when the host cannot resolve it."""

    home = os.path.expanduser("~")
    return None if home.startswith("~") else home


def validated_permission_persist_plan(value: object) -> dict[str, Any]:
    """``value`` when it is a well-formed persist plan, else ``NativeHookDecisionError``."""

    plan = _shape(value, _PERSIST_PLAN_FIELDS)
    stored, policy_action = plan["stored_artifact_hash"], plan["policy_action"]
    if (stored is None) != (policy_action is None) or policy_action not in {None, "allow", "block"}:
        raise NativeHookDecisionError(_INVALID)
    names: list[str] = []
    for event in plan["events"]:
        fields = _shape(event, _PERSIST_EVENT_FIELDS)
        if _PERSIST_EVENT_PHASE.get(fields["name"]) != fields["before_policy"]:
            raise NativeHookDecisionError(_INVALID)
        names.append(fields["name"])
    if tuple(names) not in _PERSIST_EVENT_SEQUENCES[stored is not None]:
        raise NativeHookDecisionError(_INVALID)
    return plan


def native_review_response(
    kind: str, inputs: Mapping[str, object], *, guard_home: Path, deadline: float | None = None
) -> dict[str, Any]:
    """The rendered PreToolUse response a native review shows the agent.

    ``kind`` is ``silent_review_block`` or ``paused_review``. The resident
    composes the reason and the signed review link from ``inputs``; this raises
    ``NativeHookDecisionError`` when it cannot, and the caller fails closed. A
    spent ``deadline`` (``time.monotonic()``) is an outage.
    """

    timeout = _TIMEOUT_SECONDS if deadline is None else min(_TIMEOUT_SECONDS, deadline - time.monotonic())
    if timeout <= 0:
        raise NativeHookDecisionError(_UNAVAILABLE)

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", "response"} or payload["kind"] != kind or not isinstance(payload["response"], dict):
            raise NativeHookDecisionError(_INVALID)

    operation = dataclasses.replace(_OPERATION, feature=HOOK_DECISION_REVIEW_RESPONSE_FEATURE, timeout_seconds=timeout)
    query = {"kind": kind, "inputs": dict(inputs)}
    request = functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES)
    return dict(resident_decide(operation, request, query, guard_home, validate)["response"])


__all__ = [
    "HOOK_DECISION_FEATURE",
    "HOOK_DECISION_REVIEW_RESPONSE_FEATURE",
    "NativeHookDecisionError",
    "native_review_response",
    "validated_permission_persist_plan",
]
