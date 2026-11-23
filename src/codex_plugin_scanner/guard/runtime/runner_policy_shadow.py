"""The decisions a verified policy bundle activates, answered by the resident.

Rust compiles the candidate, picks the stored bundle that shadows it,
materializes that shadow and compares the two in one ``bundle_candidate``
policy-document query. This module only shapes the request and checks the
reply.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from ..models import PolicyDecision
from ..native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
from ..native_policy_document import policy_query

_ANSWER_KEYS = frozenset({"decisions", "rejection", "rule_id", "mismatch", "total", "next"})
_MISMATCH_KEYS = frozenset({"canonicalRows", "legacyRows", "reasonCodes", "status"})
_DECISION_KEYS = frozenset(
    {
        "harness",
        "scope",
        "action",
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "reason",
        "owner",
        "source",
        "expires_at",
    }
)
_REQUIRED_KEYS = frozenset({"harness", "scope", "action"})
_REQUIRED_TEXT = ("harness",)
_OPTIONAL_TEXT = ("artifact_id", "artifact_hash", "workspace", "publisher", "reason", "owner", "expires_at")
_SCOPES = frozenset({"artifact", "workspace", "publisher", "harness", "global"})
_ACTIONS = frozenset({"allow", "warn", "block", "review", "sandbox-required", "require-reapproval"})
# Every page carries at least one row, so a verdict never needs more pages
# than it has rows; this bounds a resident that keeps naming another page.
_MAX_PAGES = 100_000


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

    The decisions come back in pages, each asked from the offset the previous
    one names. A refusal keeps the policy the device already has, so an
    unreachable, malformed or inconsistent answer never activates the
    candidate.
    """

    request: dict[str, object] = {
        "bundle": dict(policy_bundle),
        "is_v2": is_v2,
        "device_id": device_id,
        "device_name": device_name,
        "canonical_enforcement": canonical_enforcement,
        "stored_legacy": stored_legacy,
        "existing": existing,
    }
    rows: list[PolicyDecision] = []
    first: dict[str, object] | None = None
    offset = 0
    for _ in range(_MAX_PAGES):
        try:
            answer = policy_query("bundle_candidate", {**request, "offset": offset})
        except (TypeError, ValueError):
            # NativePolicyDocumentError is a ValueError: the query is
            # unavailable, unbound, or answered by a runtime that predates it.
            return _UNAVAILABLE
        page = _page(answer)
        if page is None:
            return _UNAVAILABLE
        verdict = {key: page[key] for key in ("rejection", "rule_id", "mismatch", "total")}
        if first is None:
            first = verdict
        elif verdict != first:
            return _UNAVAILABLE
        rows.extend(PolicyDecision(**row) for row in cast(list[dict[str, Any]], page["decisions"]))
        following = page["next"]
        if following is None:
            if len(rows) != first["total"]:
                return _UNAVAILABLE
            return CandidateAnswer(
                rows,
                cast("str | None", first["rejection"]),
                cast("str | None", first["rule_id"]),
                cast("dict[str, object] | None", first["mismatch"]),
            )
        if not isinstance(following, int) or following != len(rows):
            return _UNAVAILABLE
        offset = following
    return _UNAVAILABLE


def _page(answer: object) -> dict[str, object] | None:
    """The answer when every field has the shape and values Python relies on."""

    if not isinstance(answer, dict) or set(answer) != _ANSWER_KEYS:
        return None
    page = cast(dict[str, object], answer)
    rows, total, following = page["decisions"], page["total"], page["next"]
    if (
        not isinstance(rows, list)
        or not all(_decision(row) for row in rows)
        or not _optional_text(page["rejection"])
        or not _optional_text(page["rule_id"])
        or not _mismatch(page["mismatch"])
        or not _count(total)
        or not (following is None or _count(following))
    ):
        return None
    return page


def _decision(row: object) -> bool:
    """A row `PolicyDecision` accepts: optional fields may be absent or null."""

    if not isinstance(row, dict) or not _REQUIRED_KEYS <= set(row) <= _DECISION_KEYS:
        return False
    fields = cast(dict[str, object], row)
    return (
        all(isinstance(fields[key], str) for key in _REQUIRED_TEXT)
        and all(_optional_text(fields.get(key)) for key in _OPTIONAL_TEXT)
        and isinstance(fields.get("source", "local"), str)
        and fields["scope"] in _SCOPES
        and fields["action"] in _ACTIONS
    )


def _mismatch(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict) or set(value) != _MISMATCH_KEYS:
        return False
    fields = cast(dict[str, object], value)
    reasons = fields["reasonCodes"]
    return (
        _count(fields["canonicalRows"])
        and _count(fields["legacyRows"])
        and isinstance(reasons, list)
        and all(isinstance(reason, str) for reason in reasons)
        and fields["status"] == "mismatch"
    )


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _optional_text(value: object) -> bool:
    return value is None or isinstance(value, str)
