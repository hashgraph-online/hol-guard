"""Hook decisions answered by the native runtime.

The shared ``hook_decide`` resident operation, and the plan of what a
Claude-native approval saves. There is no Python evaluator: a reply that is
not a bound, strictly decoded ``ok`` raises ``NativeHookDecisionError`` and
callers fail closed.
"""

from __future__ import annotations

import dataclasses
import functools
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .native_execution import _resident_request
from .native_resident_decision import ResidentOperation, resident_decide, shape_fields

HOOK_DECISION_FEATURE = "hook-decision-v1"
# What a Claude-native approval saves; a resident that predates it rejects the
# query, so the capability is demanded first and nothing is saved without it.
HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE = "hook-decision-native-permission-persist-plan-v1"
_UNAVAILABLE = "native_hook_decision_unavailable"
_INVALID = "native_hook_decision_payload_invalid"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024

_ACTION_NAMES = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_OPT_STR = (str, type(None))
_PERSIST_INPUT_FIELDS = frozenset(
    {
        "artifact_id",
        "artifact_hash",
        "artifact_type",
        "config_path",
        "source_scope",
        "raw_command_text",
        "wrapper_chain",
        "action",
        "reason",
        "source",
        "authoritative_action",
    }
)
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


def _action(value: object) -> str:
    if not isinstance(value, str) or value not in _ACTION_NAMES:
        raise NativeHookDecisionError(_INVALID)
    return value


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


def _decide(
    query: Mapping[str, object],
    guard_home: Path | None,
    validate: Callable[[dict[str, Any]], None],
    feature: str = HOOK_DECISION_FEATURE,
) -> dict[str, Any]:
    # A request gets the same budget as the hook edge that accepted its payload.
    return resident_decide(
        _OPERATION if feature == _OPERATION.feature else dataclasses.replace(_OPERATION, feature=feature),
        functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
        query,
        guard_home,
        validate,
    )


def _tilde_home() -> str | None:
    """``os.path.expanduser("~")``, or ``None`` when the host cannot resolve it."""

    home = os.path.expanduser("~")
    return None if home.startswith("~") else home


def native_permission_persist_plan(
    inputs: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """What a Claude-native approval saves: the stored hash, the events, the inventory disposition.

    The stored hash is what a later lookup matches a saved approval by, so only
    the resident decides it. The caller performs the writes the plan names, in
    order, and writes nothing when this raises.
    """

    if set(inputs) != _PERSIST_INPUT_FIELDS:
        raise NativeHookDecisionError(_INVALID)

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", *_PERSIST_PLAN_FIELDS}:
            raise NativeHookDecisionError(_INVALID)
        plan = _shape({key: payload[key] for key in _PERSIST_PLAN_FIELDS}, _PERSIST_PLAN_FIELDS)
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

    payload = _decide(
        {
            "kind": "native_permission_persist_plan",
            "inputs": {**inputs, "tilde_home": _tilde_home()},
        },
        guard_home,
        validate,
        HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE,
    )
    return {key: payload[key] for key in _PERSIST_PLAN_FIELDS}


__all__ = [
    "HOOK_DECISION_FEATURE",
    "HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE",
    "NativeHookDecisionError",
    "native_permission_persist_plan",
]
