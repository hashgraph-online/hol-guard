"""The decisions a verified policy bundle activates, answered by the resident.

Rust compiles the candidate, picks the stored bundle that shadows it,
materializes that shadow and compares the two in one ``bundle_candidate``
policy-document query. This module only shapes the request and checks the
reply.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..models import PolicyDecision
from ..native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
from ..native_policy_document import policy_query

_ANSWER_KEYS = frozenset({"decisions", "rejection", "rule_id", "mismatch"})
_MISMATCH_KEYS = frozenset({"canonicalRows", "legacyRows", "reasonCodes", "status"})


@dataclass(frozen=True, slots=True)
class CandidateAnswer:
    """What the resident decided about one policy-bundle candidate."""

    decisions: list[PolicyDecision]
    rejection: str | None
    rule_id: str | None
    mismatch: dict[str, object] | None


_UNAVAILABLE = CandidateAnswer([], NATIVE_UNAVAILABLE_REJECTION, None, None)


def policy_bundle_candidate(
    policy_bundle: Mapping[str, object],
    *,
    is_v2: bool,
    device_id: str,
    device_name: str,
    canonical_enforcement: bool,
    stored_legacy: object,
    existing: object,
) -> CandidateAnswer:
    """Ask the resident for a candidate's decisions; an outage refuses it.

    A refusal keeps the policy the device already has, so an unreachable or
    malformed answer never activates the candidate.
    """

    try:
        answer = policy_query(
            "bundle_candidate",
            {
                "bundle": dict(policy_bundle),
                "is_v2": is_v2,
                "device_id": device_id,
                "device_name": device_name,
                "canonical_enforcement": canonical_enforcement,
                "stored_legacy": stored_legacy,
                "existing": existing,
            },
        )
    except (TypeError, ValueError):
        # NativePolicyDocumentError is a ValueError: the query is unavailable,
        # unbound, or answered by a runtime that predates it.
        return _UNAVAILABLE
    return _read(answer)


def _read(answer: object) -> CandidateAnswer:
    if not isinstance(answer, dict) or set(answer) != _ANSWER_KEYS:
        return _UNAVAILABLE
    rows, rejection, rule_id, mismatch = (answer[key] for key in ("decisions", "rejection", "rule_id", "mismatch"))
    if (
        not isinstance(rows, list)
        or not all(isinstance(row, dict) for row in rows)
        or not isinstance(rejection, (str, type(None)))
        or not isinstance(rule_id, (str, type(None)))
        or not (mismatch is None or (isinstance(mismatch, dict) and set(mismatch) == _MISMATCH_KEYS))
    ):
        return _UNAVAILABLE
    try:
        decisions = [PolicyDecision(**row) for row in rows]
    except TypeError:
        return _UNAVAILABLE
    return CandidateAnswer(decisions, rejection, rule_id, mismatch)
