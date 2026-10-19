"""Resident bridge for the ``command_policy_decide`` op.

Rust owns whether a command matches a rule and which rule then decides it: the
pattern dialect, the glob translation, the regex engine and the
block-beats-review-beats-warn-beats-allow ladder. Python used to hold a second
copy of all four, which is how ``policy test`` could report a command as
allowed while enforcement blocked it.

This module only serializes the rules the document carries and the command,
binds the reply by ``request_id`` plus ``request_sha256`` and decodes it. No
pattern is matched here, so an unavailable resident fails closed instead of
answering from a second dialect.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

COMMAND_POLICY_DECISION_FEATURE = "command-policy-decision-v1"
_OPERATION = "command_policy_decide"
_REQUEST_SCHEMA = "guard-command-policy-decision-request.v1"
_RESULT_SCHEMA = "guard-command-policy-decision-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024 - 64 * 1024
# A document carrying more command rules than this is past what an author can
# reason about; the byte limit is what a real request runs into first.
_MAX_RULES = 4096
UNAVAILABLE = "native_command_policy_decision_unavailable"
TOO_LARGE = "native_command_policy_decision_too_large"
_REFUSAL_PREFIX = "native_command_policy_decision_"
CONDITION_FIELDS = ("operator", "value", "case_sensitive")
_DECISION_KEYS = frozenset(
    {"effect", "ruleId", "ambiguous", "matchLimitExceeded", "tiedRuleIds", "candidates", "lookup"}
)
_CANDIDATE_KEYS = frozenset({"ruleId", "rowIndex", "state", "reason"})
_LOOKUP_KEYS = frozenset({"artifactId", "familyKey", "at"})


class CommandPolicyDecisionUnavailableError(ValueError):
    """The command was not decided; no pattern was matched in Python.

    ``code`` separates a runtime that could not answer from a document the
    runtime refused to decide: a pattern outside the dialect, an action the
    lattice does not name, or more rules than one request may carry. Both fail
    closed, but only the first is the runtime's fault, so a caller can tell an
    author which one they are looking at.
    """

    def __init__(self, code: str = UNAVAILABLE) -> None:
        super().__init__(code)
        self.code = code

    @property
    def refused(self) -> bool:
        """Whether the document was refused, rather than the runtime being absent."""

        return self.code != UNAVAILABLE


def _wire_condition(condition: Mapping[str, object]) -> dict[str, object]:
    return {field: condition.get(field) for field in CONDITION_FIELDS}


def _wire_rule(rule: Mapping[str, object]) -> dict[str, object]:
    expression = rule.get("expression")
    expression = expression if isinstance(expression, Mapping) else {}
    conditions = expression.get("conditions")
    return {
        "rule_id": rule.get("rule_id"),
        "action": rule.get("action"),
        "expression": {
            "combinator": expression.get("combinator"),
            "conditions": [
                _wire_condition(condition)
                for condition in (conditions if isinstance(conditions, Sequence) else ())
                if isinstance(condition, Mapping)
            ],
        },
    }


def _decoded(payload: object) -> dict[str, object]:
    """The Explain shape, or a raised error; a half-read reply decides nothing."""

    # ``action`` is present only when a rule matched, so the shape is checked
    # against the required keys and that one optional one.
    if not isinstance(payload, dict) or not _DECISION_KEYS <= set(payload) <= _DECISION_KEYS | {"action"}:
        raise CommandPolicyDecisionUnavailableError
    candidates = payload["candidates"]
    lookup = payload["lookup"]
    tied = payload["tiedRuleIds"]
    action = payload.get("action")
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
        or not (action is None or isinstance(action, str))
    ):
        raise CommandPolicyDecisionUnavailableError
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != _CANDIDATE_KEYS:
            raise CommandPolicyDecisionUnavailableError
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
        raise CommandPolicyDecisionUnavailableError(code)


def native_command_policy_decision(
    rules: Sequence[Mapping[str, object]],
    command: str,
    *,
    now: str,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Decide ``command`` against ``rules`` in the resident; raise when it cannot."""

    if len(rules) > _MAX_RULES:
        raise CommandPolicyDecisionUnavailableError(TOO_LARGE)
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"command-policy-decision-{uuid4().hex}",
        "rules": [_wire_rule(rule) for rule in rules],
        "command": command,
        "now": now,
    }
    try:
        encoded = len(json.dumps(wire).encode("utf-8"))
    except (TypeError, ValueError):
        raise CommandPolicyDecisionUnavailableError from None
    if encoded > _MAX_REQUEST_BYTES:
        raise CommandPolicyDecisionUnavailableError(TOO_LARGE)
    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise CommandPolicyDecisionUnavailableError
    try:
        response = _resident_request(
            operation=_OPERATION,
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=COMMAND_POLICY_DECISION_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise CommandPolicyDecisionUnavailableError from None
    payload = _payload(response, wire, home)
    if payload is None:
        _raise_refusal(response, wire)
    return _decoded(payload)


__all__ = [
    "COMMAND_POLICY_DECISION_FEATURE",
    "TOO_LARGE",
    "UNAVAILABLE",
    "CommandPolicyDecisionUnavailableError",
    "native_command_policy_decision",
]
