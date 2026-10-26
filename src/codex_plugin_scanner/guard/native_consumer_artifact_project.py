"""Consumer artifact projection answered by the native runtime.

The consumer evaluation reads the store and the harness. The resident decides
what that evidence means: the capability snapshot and its delta, the artifact
diff, the history and provenance context, the incident copy, and what the
composed decision means for each artifact (result row, blocking, snapshot,
receipt and change event). There is no Python evaluator:
``native_consumer_project`` raises ``NativeConsumerProjectError`` for anything
but a bound, strictly decoded ``ok`` answer, so a missing resident fails the
evaluation closed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .native_consumer_artifact_compose import record_binding_health
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_hook_artifact_compose import _field_valid

CONSUMER_ARTIFACT_PROJECT_FEATURE = "consumer-artifact-project-v2"
_REQUEST_SCHEMA = "guard-consumer-artifact-project-request.v1"
_RESULT_SCHEMA = "guard-consumer-artifact-project-result.v1"
_RESIDENT_CODE = re.compile(r"^native_consumer_artifact_project_[a-z_]{1,64}$")
_UNAVAILABLE = "native_consumer_artifact_project_unavailable"
_TIMEOUT_SECONDS = 5.0
# Result rows carry the decision projection and scoring evidence, which can
# exceed the shared 256 KiB default.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# Every field is sent explicitly (nulls included) so the digest bound here
# equals the resident's digest of its decoded request.
_FIELDS: dict[str, frozenset[str]] = {
    "artifact_evidence": frozenset(
        {
            "artifact",
            "current_payload",
            "payload_keys",
            "current_hash",
            "previous_snapshot",
            "previous_capabilities",
            "history",
        }
    ),
    "artifact_outcome": frozenset(
        {
            "harness",
            "artifact",
            "evidence",
            "verdict",
            "scanner_action",
            "configured_action",
            "runtime",
            "compose_error",
            "signals",
            "decision_signals",
            "static_risk_summary",
            "runtime_signals_present",
            "user_override",
            "approval_context_hash",
            "effective_workspace",
        }
    ),
    "removed_outcome": frozenset(
        {
            "harness",
            "artifact_id",
            "previous",
            "previous_hash",
            "configured_action",
            "runtime",
            "compose_error",
            "decision_signals",
            "user_override",
            "approval_context_hash",
            "effective_workspace",
        }
    ),
    "incident_context": frozenset(
        {
            "harness",
            "artifact",
            "artifact_id",
            "artifact_name",
            "artifact_type",
            "source_scope",
            "config_path",
            "changed_fields",
            "policy_action",
            "launch_target",
            "risk_summary",
        }
    ),
}

# The exact answer shape of each query kind. Spec letters: a action,
# A action or null, b bool, s string, S string or null, d dict, D dict or
# null, l list. An outcome's result row is checked for the fields every
# consumer reads, and its receipt for the exact ``build_receipt`` fields.
_OUTCOME: dict[str, str] = {
    "result": "d",
    "policy_action": "a",
    "blocking": "b",
    "snapshot_permitted": "b",
    "receipt": "d",
    "event": "D",
}
_ANSWERS: dict[str, dict[str, str]] = {
    "artifact_evidence": {
        "changed": "b",
        "first_seen": "b",
        "diff_summary": "S",
        "changed_fields": "l",
        "previous_hash": "S",
        "current_hash": "s",
        "capabilities_summary": "s",
        "changed_capabilities": "l",
        "provenance_summary": "s",
        "scoring": "d",
        "capability_snapshot": "d",
        "capability_delta": "l",
        "history_context": "d",
        "provenance": "d",
    },
    "artifact_outcome": _OUTCOME,
    "removed_outcome": _OUTCOME,
    "incident_context": {
        "artifact_label": "s",
        "source_label": "s",
        "trigger_summary": "s",
        "why_now": "s",
        "launch_summary": "s",
        "risk_headline": "s",
    },
}
_RECEIPT: dict[str, str] = {
    "artifact_hash": "s",
    "policy_decision": "a",
    "capabilities_summary": "s",
    "changed_capabilities": "l",
    "provenance_summary": "s",
    "artifact_name": "s",
    "source_scope": "S",
    "user_override": "S",
    "diff_summary": "S",
    "approval_source": "s",
    "scanner_evidence": "l",
}
_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_RESULT_FIELDS: dict[str, str] = {
    "artifact_id": "s",
    "policy_action": "a",
    "changed": "b",
    "changed_fields": "l",
    "approval_context_hash": "s",
    "scoring_recommendation": "d",
    "risk_signals": "l",
    "signals": "l",
    "capability_snapshot": "d",
    "capability_delta": "l",
    "provenance": "d",
    "history_context": "d",
    "authoritative_decision": "d",
    "why_now": "s",
}


def _exact(shape: Mapping[str, str], payload: object) -> bool:
    return (
        isinstance(payload, dict)
        and set(payload) == set(shape)
        and all(_field_valid(spec, payload[name]) for name, spec in shape.items())
    )


def _result_valid(row: dict[str, object]) -> bool:
    # A fail-closed row (no native decision) carries its evaluation error in
    # place of an authoritative decision; every other row must carry one.
    fail_closed = (
        "authoritative_decision" not in row
        and row.get("policy_action") == "block"
        and isinstance(row.get("evaluation_error"), dict)
    )
    return all(
        name in row and _field_valid(spec, row[name])
        for name, spec in _RESULT_FIELDS.items()
        if not (fail_closed and name == "authoritative_decision")
    )


def _outcome_consistent(payload: dict[str, object], result: dict[str, object], receipt: dict[str, object]) -> bool:
    # One decision: the row, the receipt and the enforcement flags agree on it,
    # and nothing that blocks may advance the stored snapshot.
    action = payload["policy_action"]
    blocking = action in _BLOCKING_ACTIONS
    return (
        result.get("policy_action") == action
        and receipt["policy_decision"] == action
        and payload["blocking"] is blocking
        and not (blocking and payload["snapshot_permitted"] is True)
    )


def _answer_valid(kind: str, payload: dict[str, object]) -> bool:
    if not _exact(_ANSWERS[kind], payload):
        return False
    if kind not in {"artifact_outcome", "removed_outcome"}:
        return True
    result, receipt = payload["result"], payload["receipt"]
    if not isinstance(result, dict) or not isinstance(receipt, dict) or not _exact(_RECEIPT, receipt):
        return False
    if not _outcome_consistent(payload, result, receipt):
        return False
    if kind == "removed_outcome":
        return result.get("removed") is True and isinstance(payload["event"], dict)
    return _result_valid(result)


class NativeConsumerProjectError(RuntimeError):
    """No authoritative projection answer; ``code`` says why, for diagnostics."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def native_consumer_project(kind: str, fields: Mapping[str, object], *, guard_home: Path | None) -> dict[str, object]:
    """Return the resident's answer to one projection query, or raise."""

    expected = _FIELDS.get(kind)
    if expected is None or set(fields) != expected:
        raise NativeConsumerProjectError("native_consumer_artifact_project_request_invalid")
    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise NativeConsumerProjectError("native_consumer_artifact_project_home_unbound") from None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"consumer-artifact-project-{uuid4().hex}",
        "query": {"kind": kind, **fields},
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise NativeConsumerProjectError("native_consumer_artifact_project_request_invalid") from None
    if not ensure_resident_prerequisite(home):
        raise NativeConsumerProjectError(_UNAVAILABLE)
    response = _resident_request(
        operation="consumer_artifact_project",
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=CONSUMER_ARTIFACT_PROJECT_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
    )
    if response is None:
        raise NativeConsumerProjectError(_UNAVAILABLE)
    # Resident health is recorded only once the reply is bound to this request
    # and decodes, so malformed answers keep counting toward the circuit.
    bound = (
        response.get("schema") == _RESULT_SCHEMA
        and response.get("request_id") == request["request_id"]
        and response.get("request_sha256") == digest
    )
    status, code, payload = response.get("status"), response.get("code"), response.get("payload")
    usable = status == "ok" and code == "ok" and isinstance(payload, dict) and _answer_valid(kind, payload)
    _record_health(home, healthy=bound and (usable or status == "error"))
    if not bound:
        raise NativeConsumerProjectError(_UNAVAILABLE)
    if status == "error":
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        raise NativeConsumerProjectError(reason)
    if not usable or not isinstance(payload, dict):
        raise NativeConsumerProjectError("native_consumer_artifact_project_payload_invalid")
    return payload


def _record_health(home: Path, *, healthy: bool) -> None:
    record_binding_health(home, healthy=healthy, reason="native_consumer_artifact_project_binding")


__all__ = ["CONSUMER_ARTIFACT_PROJECT_FEATURE", "NativeConsumerProjectError", "native_consumer_project"]
