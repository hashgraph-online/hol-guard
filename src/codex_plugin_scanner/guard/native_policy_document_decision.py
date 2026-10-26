"""Resident bridge for the ``policy_document_decide`` op.

Rust owns which rule decides an event: the probe order, block-beats-allow, the
scope specificity ladder, expiry and the exact-match rule for broad rules over
an exact-only family. ``policy check`` and ``policy test`` ask the resident the
same question the runtime answers from the store, so the two can never drift
apart and report a document as safer than it is.

This module only serializes the compiled rows and the event, binds the reply by
``request_id`` plus ``request_sha256`` and decodes it. Nothing is recomputed in
Python, so an unavailable resident fails closed instead of falling back to a
second opinion.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

POLICY_DOCUMENT_DECISION_FEATURE = "policy-document-decision-v1"
_OPERATION = "policy_document_decide"
_REQUEST_SCHEMA = "guard-policy-document-decision-request.v1"
_RESULT_SCHEMA = "guard-policy-document-decision-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024 - 64 * 1024
# ``guard explain`` builds its document from every remembered decision, and that
# table is unbounded, so the ceiling sits far above any hand-written document.
_MAX_ROWS = 16384
UNAVAILABLE = "native_policy_document_decision_unavailable"
TOO_LARGE = "native_policy_document_decision_too_large"
_REFUSAL_PREFIX = "native_policy_document_decision_"
# Every field is sent, null when absent: the reply digest binds to the
# resident's own serialization of the typed request.
ROW_FIELDS = (
    "rule_id",
    "harness",
    "scope",
    "action",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "publisher",
    "expires_at",
)
EVENT_FIELDS = ("harness", "artifact", "tool", "publisher", "workspace", "at")
_DECISION_KEYS = frozenset(
    {"effect", "ruleId", "ambiguous", "matchLimitExceeded", "tiedRuleIds", "candidates", "lookup"}
)
_CANDIDATE_KEYS = frozenset({"ruleId", "rowIndex", "state", "reason"})
_LOOKUP_KEYS = frozenset({"artifactId", "familyKey", "at"})


class PolicyDocumentDecisionUnavailableError(ValueError):
    """The event was not decided; nothing was recomputed in Python.

    ``code`` separates a runtime that could not answer from a document the
    runtime refused to decide: more rows than one request may carry, a request
    past the frame limit, or a row or event the contract rejects. Both fail
    closed, but only the first is the runtime's fault, so a caller can tell the
    author which one they are looking at instead of blaming an absent runtime.
    """

    def __init__(self, code: str = UNAVAILABLE) -> None:
        super().__init__(code)
        self.code = code

    @property
    def refused(self) -> bool:
        """Whether the document was refused, rather than the runtime being absent."""

        return self.code != UNAVAILABLE


def _wire_row(row: Mapping[str, object]) -> dict[str, object]:
    return {field: row.get(field) for field in ROW_FIELDS}


def _wire_event(event: Mapping[str, object]) -> dict[str, object]:
    return {field: event.get(field) for field in EVENT_FIELDS}


def _decoded(payload: object) -> dict[str, object]:
    """The Explain shape, or a raised error; a half-read reply decides nothing."""

    if not isinstance(payload, dict) or set(payload) != _DECISION_KEYS:
        raise PolicyDocumentDecisionUnavailableError
    candidates = payload["candidates"]
    lookup = payload["lookup"]
    tied = payload["tiedRuleIds"]
    if (
        not isinstance(candidates, list)
        or not isinstance(lookup, dict)
        or set(lookup) != _LOOKUP_KEYS
        or not isinstance(tied, list)
        or not all(isinstance(rule_id, str) for rule_id in tied)
        or not isinstance(payload["ambiguous"], bool)
        or not isinstance(payload["matchLimitExceeded"], bool)
        or not isinstance(payload["effect"], str)
        or not (payload["ruleId"] is None or isinstance(payload["ruleId"], str))
    ):
        raise PolicyDocumentDecisionUnavailableError
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != _CANDIDATE_KEYS:
            raise PolicyDocumentDecisionUnavailableError
    return payload


def _raise_refusal(response: dict[str, object] | None, request: dict[str, object]) -> None:
    """Re-raise the resident's own refusal code when the reply carries one.

    ``_payload`` yields ``None`` for a bound ``error`` reply as well as for an
    absent runtime. A refusal names what it refused, and reporting that as an
    unavailable runtime sends a policy author to fix a runtime that answered.
    """

    if response is None:
        return
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return
    if response.get("request_id") != request["request_id"] or response.get("request_sha256") != digest:
        return
    code = response.get("code")
    if response.get("status") == "error" and isinstance(code, str) and code.startswith(_REFUSAL_PREFIX):
        raise PolicyDocumentDecisionUnavailableError(code)


def native_policy_document_decision(
    rows: Sequence[Mapping[str, object]],
    event: Mapping[str, object],
    *,
    now: str,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Decide ``event`` against ``rows`` in the resident; raise when it cannot."""

    if len(rows) > _MAX_ROWS:
        raise PolicyDocumentDecisionUnavailableError(TOO_LARGE)
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"policy-document-decision-{uuid4().hex}",
        "rows": [_wire_row(row) for row in rows],
        "event": _wire_event(event),
        "now": now,
    }
    try:
        encoded = len(json.dumps(wire).encode("utf-8"))
    except (TypeError, ValueError):
        raise PolicyDocumentDecisionUnavailableError from None
    if encoded > _MAX_REQUEST_BYTES:
        raise PolicyDocumentDecisionUnavailableError(TOO_LARGE)
    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise PolicyDocumentDecisionUnavailableError
    try:
        response = _resident_request(
            operation=_OPERATION,
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=POLICY_DOCUMENT_DECISION_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise PolicyDocumentDecisionUnavailableError from None
    payload = _payload(response, wire, home)
    if payload is None:
        _raise_refusal(response, wire)
    return _decoded(payload)


__all__ = [
    "POLICY_DOCUMENT_DECISION_FEATURE",
    "TOO_LARGE",
    "UNAVAILABLE",
    "PolicyDocumentDecisionUnavailableError",
    "native_policy_document_decision",
]
