"""Read immutable policy fields from a recorded local review request."""

from __future__ import annotations

import json


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _read_json_mapping(value: object) -> dict[str, object] | None:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    if value is None:
        return None
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    return {str(key): item for key, item in parsed.items()}


def _policy_version(request_row: dict[str, object]) -> str:
    decision_v2 = _read_json_mapping(request_row.get("decision_v2_json")) or {}
    value = _non_empty_string(decision_v2.get("policyVersion"))
    if value is not None:
        return value
    last_seen_at = _non_empty_string(request_row.get("last_seen_at")) or _non_empty_string(
        request_row.get("created_at")
    )
    return f"request:{last_seen_at or request_row['request_id']}"
