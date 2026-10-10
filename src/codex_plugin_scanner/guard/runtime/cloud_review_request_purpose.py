"""Canonical Cloud Review purpose bound to frozen original evidence."""

from __future__ import annotations

from collections.abc import Mapping

WIRE_EVENT_SCHEMA_VERSION = 2
CANONICAL_REQUEST_KINDS = (
    "reviewable_pause",
    "immutable_policy_block",
    "watch_only_observation",
)
_TRUE_MARKERS = frozenset({True, "1"})
_FALSE_MARKERS = frozenset({False, "0"})


def _marker_matches(marker: object, accepted: frozenset[object]) -> bool:
    """Match a stored scalar without raising on a JSON list or object.

    Integer 1 still matches True, and integer 0 still matches False. Any other
    shape is ambiguous and must not become an executable watch-only purpose.
    """

    if isinstance(marker, (bool, str)):
        return marker in accepted
    if isinstance(marker, int):
        return any(marker == item for item in accepted)
    return False


def canonical_request_kind(item: Mapping[str, object]) -> str | None:
    """Return the schema-2 purpose, or None when the frozen marker is absent or ambiguous."""

    if "watch_only_observation" not in item and "watchOnlyObservation" not in item:
        return None
    marker = item["watch_only_observation"] if "watch_only_observation" in item else item["watchOnlyObservation"]
    if _marker_matches(marker, _TRUE_MARKERS):
        return "watch_only_observation"
    if not _marker_matches(marker, _FALSE_MARKERS):
        return None
    policy = str(item.get("policy_action") or item.get("policyAction") or "").lower()
    if policy in {"block", "deny"}:
        return "immutable_policy_block"
    return "reviewable_pause"


def explicit_watch_only(item: Mapping[str, object]) -> bool:
    return canonical_request_kind(item) == "watch_only_observation"
