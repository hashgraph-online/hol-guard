"""The PreToolUse floor, answered by the native runtime.

A PreToolUse hook holds its verdict at the minimum action the resident's
pre-tool review returned for the command. The transport sends that review's
``minimum_action`` and ``reason_code`` and returns the floor the resident
answers: a canonical Guard action, or ``None`` when the review does not floor
the verdict. A reply that is not a bound, strictly decoded ``ok`` with a
well-formed floor raises ``NativeHookDecisionError`` and the caller answers
with the host outage response, so a floor is never guessed.
"""

from __future__ import annotations

import dataclasses
import functools
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_execution import _resident_request
from .native_hook_decision import (
    _INVALID,
    _MAX_REQUEST_BYTES,
    _OPERATION,
    NativeHookDecisionError,
    _action,
)
from .native_resident_decision import resident_decide

HOOK_DECISION_PRETOOL_FLOOR_FEATURE = "hook-decision-pretool-floor-v1"


def native_pretool_floor(review: Mapping[str, object], *, guard_home: Path | None) -> str | None:
    """The floor the resident's pre-tool ``review`` holds a PreToolUse verdict at."""

    minimum_action = review.get("minimum_action")
    reason_code = review.get("reason_code")
    if not isinstance(minimum_action, str) or not isinstance(reason_code, str) or not reason_code:
        raise NativeHookDecisionError(_INVALID)
    inputs = {"minimum_action": _action(minimum_action), "reason_code": reason_code}

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", "floor"}:
            raise NativeHookDecisionError(_INVALID)
        if payload["floor"] is not None:
            _action(payload["floor"])

    payload = resident_decide(
        dataclasses.replace(_OPERATION, feature=HOOK_DECISION_PRETOOL_FLOOR_FEATURE),
        functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
        {"kind": "pretool_floor", "inputs": inputs},
        guard_home,
        validate,
    )
    return payload["floor"]


__all__ = ["HOOK_DECISION_PRETOOL_FLOOR_FEATURE", "native_pretool_floor"]
