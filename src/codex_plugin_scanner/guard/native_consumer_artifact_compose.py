"""Consumer artifact decision composition answered by the native runtime.

The consumer evaluation gathers evidence (detected artifacts, capability
deltas, store history, provenance, saved-decision lookups, context tokens);
the resident scores the artifact, composes the current policy action,
validates and composes saved/claimed approval reuse and the trusted-request
override, and applies runtime-detector authority. There is no Python
evaluator: ``native_consumer_compose`` raises ``NativeConsumerComposeError``
for anything but a bound, strictly decoded ``ok`` answer, so a missing
resident fails the evaluation closed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_hook_artifact_compose import _field_valid
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

CONSUMER_ARTIFACT_COMPOSE_FEATURE = "consumer-artifact-compose-v1"
_REQUEST_SCHEMA = "guard-consumer-artifact-compose-request.v1"
_RESULT_SCHEMA = "guard-consumer-artifact-compose-result.v1"
_RESIDENT_CODE = re.compile(r"^native_consumer_artifact_compose_[a-z_]{1,64}$")
_UNAVAILABLE = "native_consumer_artifact_compose_unavailable"
_TIMEOUT_SECONDS = 5.0
# Scoring evidence carries artifact text such as prompt signals, which can
# exceed the shared 256 KiB default.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# Every field is sent explicitly (nulls included) so the digest bound here
# equals the resident's digest of its decoded request.
_FIELDS: dict[str, frozenset[str]] = {
    "current_action": frozenset(
        {
            "removed",
            "artifact_type",
            "configured_action",
            "guard_default_action",
            "first_seen",
            "changed",
            "effective_default_action",
            "config_changed_hash_action",
            "config_default_action",
            "skill_directory_identity_reusable",
            "signals",
            "deltas",
            "provenance_source_kind",
            "publisher_trust",
            "prior_approvals",
            "prior_incidents",
        }
    ),
    "runtime_decision": frozenset(
        {
            "current_action",
            "configured_action",
            "scanner_action",
            "raw_scoring_recommendation",
            "skill_directory_identity_reusable",
            "approval_context_hash",
            "saved_decision",
            "ignored_local_integrity",
            "diagnosed_reason",
            "trusted_request_override_hash",
            "claimed_saved_approval_hash",
            "retained_saved_approval_hash",
            "saved_approval_qualification",
            "runtime_detector_composition",
            "runtime_detector_block_reason",
            "runtime_signals",
        }
    ),
}

# The exact answer shape of each query kind. Spec letters: a action,
# A action or null, b bool, s string, d dict, D dict or null, l list.
_ANSWERS: dict[str, dict[str, str]] = {
    "current_action": {"current_action": "a", "scanner_action": "A", "verdict": "D"},
    "runtime_decision": {
        "approval_claim": "D",
        "approval_reuse": "d",
        "approval_source": "s",
        "append_pending_claim": "b",
        "authority_finalized": "b",
        "decision_reason": "s",
        "policy_action": "a",
        "policy_composition": "d",
        "saved_state_present": "b",
        "scanner_evidence": "l",
        "trusted_request_override": "b",
    },
}

_FIELDS["runtime_authoritative"] = frozenset({"runtime", "signals"})
_ANSWERS["runtime_authoritative"] = {**_ANSWERS["runtime_decision"], "authoritative_decision": "d"}


def _answer_valid(kind: str, payload: dict[str, object]) -> bool:
    shape = _ANSWERS[kind]
    return set(payload) == set(shape) and all(_field_valid(spec, payload[name]) for name, spec in shape.items())


class NativeConsumerComposeError(RuntimeError):
    """No authoritative composition answer; ``code`` says why, for diagnostics."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NativeConsumerComposeValidationError(ValueError):
    """The bound healthy owner refused inconsistent composition facts."""


def native_consumer_compose(kind: str, fields: Mapping[str, object], *, guard_home: Path | None) -> dict[str, object]:
    """Return the resident's answer to one composition query, or raise."""

    expected = _FIELDS.get(kind)
    if expected is None or set(fields) != expected:
        raise NativeConsumerComposeError("native_consumer_artifact_compose_request_invalid")
    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise NativeConsumerComposeError("native_consumer_artifact_compose_home_unbound") from None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"consumer-artifact-compose-{uuid4().hex}",
        "query": {"kind": kind, **fields},
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise NativeConsumerComposeError("native_consumer_artifact_compose_request_invalid") from None
    if not ensure_resident_prerequisite(home):
        raise NativeConsumerComposeError(_UNAVAILABLE)
    response = _resident_request(
        operation="consumer_artifact_compose",
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=CONSUMER_ARTIFACT_COMPOSE_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
    )
    if response is None:
        raise NativeConsumerComposeError(_UNAVAILABLE)
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
        raise NativeConsumerComposeError(_UNAVAILABLE)
    if status == "error":
        if (
            code == "native_consumer_artifact_compose_validation_refused"
            and isinstance(payload, dict)
            and payload.get("error_type") == "ValueError"
            and isinstance(payload.get("message"), str)
            and len(payload["message"].encode("utf-8")) <= 4096
        ):
            raise NativeConsumerComposeValidationError(payload["message"])
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        raise NativeConsumerComposeError(reason)
    if not usable or not isinstance(payload, dict):
        raise NativeConsumerComposeError("native_consumer_artifact_compose_payload_invalid")
    return payload


def record_binding_health(home: Path, *, healthy: bool, reason: str) -> None:
    """Record one resident answer-binding outcome against the running native identity."""

    identity = native_runtime_status().identity
    if identity is None:
        return
    if healthy:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason=reason)


def _record_health(home: Path, *, healthy: bool) -> None:
    record_binding_health(home, healthy=healthy, reason="native_consumer_artifact_compose_binding")


__all__ = [
    "CONSUMER_ARTIFACT_COMPOSE_FEATURE",
    "NativeConsumerComposeError",
    "NativeConsumerComposeValidationError",
    "native_consumer_compose",
]
