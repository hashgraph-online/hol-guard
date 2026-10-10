"""Generic-hook decisions answered by the native runtime.

The hook transport gathers facts (payload fields, store lookups, classifier
verdicts) and renders host output. The resident decides everything between:
event and action normalization, composition of the current action, which
grant lookups are permitted, the final action after approval reuse and Watch
mode, receipt and activity dispositions, and the response directive. There is
no Python evaluator: a reply that is not a bound, strictly decoded ``ok``
raises ``NativeHookDecisionError`` and callers fail closed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

HOOK_DECISION_FEATURE = "hook-decision-v1"
_REQUEST_SCHEMA = "guard-hook-decision-request.v1"
_RESULT_SCHEMA = "guard-hook-decision-result.v1"
_RESIDENT_CODE = re.compile(r"^native_hook_decision_[a-z_]{1,64}$")
_UNAVAILABLE = "native_hook_decision_unavailable"
_INVALID = "native_hook_decision_payload_invalid"
_TIMEOUT_SECONDS = 5.0
_MAX_FACT_ROUNDS = 12

_ACTION_NAMES = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_OPT_STR = (str, type(None))
_COMPOSITION_FIELDS: dict[str, Any] = {
    "event_name": _OPT_STR,
    "effective_event_name": str,
    "composed_action": str,
    "grant_lookups_allowed": bool,
    "tool_eligibility_needed": bool,
    "action_with_tool_grant": str,
    "action_without_tool_grant": str,
    "permission_decision_reason": _OPT_STR,
    "daemon_failure_reason": _OPT_STR,
    "token": dict,
}
_TOKEN_FIELDS: dict[str, Any] = {
    "current_config_action": str,
    "daemon_hint_disposition": _OPT_STR,
    "daemon_hint_reason_code": _OPT_STR,
    "trusted_cli_action": _OPT_STR,
    "untrusted_payload_action": _OPT_STR,
    "untrusted_payload_action_disposition": _OPT_STR,
    "untrusted_payload_action_reason": _OPT_STR,
}
_FINAL_FIELDS: dict[str, Any] = {
    "policy_action": str,
    "observed_policy_action": _OPT_STR,
    "effective_event_name": str,
    "approval_reuse_source": _OPT_STR,
    "policy_composition": dict,
    "evidence_tail": list,
    "silent_review": (dict, type(None)),
    "record_receipt": bool,
    "activity": dict,
    "directive": dict,
}
_ACTIVITY_FIELDS: dict[str, Any] = {"phase": str, "reuse_status": str, "prompted": bool}
_DIRECTIVE_FIELDS: dict[str, Any] = {
    "route": str,
    "queue_observe_request": bool,
    "queue_approval_request": bool,
    "emitter": str,
    "exit_code": (int, type(None)),
    "stderr_only_on_nonzero_exit": bool,
    "codex_native_reason": str,
    "include_remediation": bool,
    "terminal_notice": bool,
    "system_message": str,
    "try_json_document": bool,
    "after_json": str,
    "envelope_decision": str,
}


class NativeHookDecisionError(RuntimeError):
    """No authoritative decision; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _shape(value: object, fields: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise NativeHookDecisionError(_INVALID)
    for key, kinds in fields.items():
        item = value[key]
        allowed = kinds if isinstance(kinds, tuple) else (kinds,)
        if isinstance(item, bool) and bool not in allowed:
            raise NativeHookDecisionError(_INVALID)
        if not isinstance(item, allowed):
            raise NativeHookDecisionError(_INVALID)
    return value


def _action(value: object) -> str:
    if not isinstance(value, str) or value not in _ACTION_NAMES:
        raise NativeHookDecisionError(_INVALID)
    return value


def _record_resident(guard_home: Path, *, success: bool, reason: str = "") -> None:
    """Record resident health only once a reply has passed binding and validation.

    The shared transport would otherwise reset the failure streak on every
    reply that parses, so a resident that keeps sending unusable replies would
    never open the circuit.
    """

    status = native_runtime_status()
    if status.identity is None:
        return
    if success:
        native_record_resident_success(status.identity.sha256, guard_home)
    else:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=reason)


def _decide(
    query: Mapping[str, object],
    guard_home: Path | None,
    validate: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Ask the resident and return its payload once ``validate`` accepts it.

    Resident health is recorded only after binding and payload validation, so
    a resident that keeps sending well-bound but malformed payloads opens the
    circuit instead of resetting the failure streak on every reply.
    """

    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise NativeHookDecisionError("native_hook_decision_home_unbound") from None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-decision-{uuid4().hex}",
        "query": dict(query),
    }
    try:
        if not ensure_resident_prerequisite(home):
            raise NativeHookDecisionError(_UNAVAILABLE)
        digest = "sha256:" + _canonical_request_sha256(request)
    except (OSError, TypeError, ValueError):
        raise NativeHookDecisionError("native_hook_decision_request_invalid") from None
    response = _resident_request(
        operation="hook_decide",
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=HOOK_DECISION_FEATURE,
        response_schema=_RESULT_SCHEMA,
        record_success=False,
    )
    if response is None:
        raise NativeHookDecisionError(_UNAVAILABLE)
    if (
        response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        _record_resident(home, success=False, reason="native_hook_decision_unbound")
        raise NativeHookDecisionError(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        _record_resident(home, success=True)
        raise NativeHookDecisionError(
            code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        )
    payload = response.get("payload")
    if status != "ok" or code != "ok" or not isinstance(payload, dict) or payload.get("kind") != query.get("kind"):
        _record_resident(home, success=False, reason="native_hook_decision_bad_status")
        raise NativeHookDecisionError(_UNAVAILABLE)
    try:
        validate(payload)
    except NativeHookDecisionError:
        _record_resident(home, success=False, reason="native_hook_decision_invalid")
        raise
    _record_resident(home, success=True)
    return payload


def native_compose_current(
    inputs: Mapping[str, object],
    classifiers: Mapping[str, Callable[[str | None], bool]],
    *,
    guard_home: Path | None = None,
) -> tuple[dict[str, Any], dict[str, bool]]:
    """Compose the current action; classifiers run only when the resident asks.

    Each classifier is called with the resident-normalized event name.

    Returns the composition and the classifier verdicts gathered along the way
    (the caller hands them back to ``native_finalize``).
    """

    facts: dict[str, bool] = {}

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", "event_name", "needs_facts", "composition"}:
            raise NativeHookDecisionError(_INVALID)
        needs, composition, event_name = payload["needs_facts"], payload["composition"], payload["event_name"]
        if not isinstance(needs, list) or not isinstance(event_name, (str, type(None))):
            raise NativeHookDecisionError(_INVALID)
        if not needs:
            composition = _shape(composition, _COMPOSITION_FIELDS)
            _shape(composition["token"], _TOKEN_FIELDS)
            for key in ("composed_action", "action_with_tool_grant", "action_without_tool_grant"):
                _action(composition[key])
            return
        for name in needs:
            if not isinstance(name, str) or name not in classifiers or name in facts:
                raise NativeHookDecisionError(_INVALID)

    for _ in range(_MAX_FACT_ROUNDS):
        payload = _decide(
            {"kind": "compose_current", "inputs": {**inputs, "facts": dict(facts)}},
            guard_home,
            validate,
        )
        needs, composition, event_name = payload["needs_facts"], payload["composition"], payload["event_name"]
        if not needs:
            return composition, facts
        for name in needs:
            facts[name] = bool(classifiers[name](event_name))
    raise NativeHookDecisionError(_INVALID)


def native_post_claim_reuse(inputs: Mapping[str, object], *, guard_home: Path | None = None) -> tuple[str, str | None]:
    """The action and validation reason for re-evaluating a claimed saved approval."""

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", "current_action", "validation_reason"}:
            raise NativeHookDecisionError(_INVALID)
        reason = payload["validation_reason"]
        if reason is not None and not isinstance(reason, str):
            raise NativeHookDecisionError(_INVALID)
        _action(payload["current_action"])

    payload = _decide({"kind": "post_claim_reuse", "inputs": dict(inputs)}, guard_home, validate)
    return _action(payload["current_action"]), payload["validation_reason"]


def native_finalize(
    inputs: Mapping[str, object],
    settled: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """Settle the final action, dispositions and response directive."""

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", *_FINAL_FIELDS}:
            raise NativeHookDecisionError(_INVALID)
        final = _shape({key: payload[key] for key in _FINAL_FIELDS}, _FINAL_FIELDS)
        _action(final["policy_action"])
        _shape(final["activity"], _ACTIVITY_FIELDS)
        _shape(final["directive"], _DIRECTIVE_FIELDS)
        if not all(isinstance(entry, dict) for entry in final["evidence_tail"]):
            raise NativeHookDecisionError(_INVALID)
        review = final["silent_review"]
        if review is not None:
            _shape(review, {"action": str, "reason": str})

    payload = _decide({"kind": "finalize", "inputs": dict(inputs), "settled": dict(settled)}, guard_home, validate)
    return {key: payload[key] for key in _FINAL_FIELDS}


__all__ = [
    "HOOK_DECISION_FEATURE",
    "NativeHookDecisionError",
    "native_compose_current",
    "native_finalize",
    "native_post_claim_reuse",
]
