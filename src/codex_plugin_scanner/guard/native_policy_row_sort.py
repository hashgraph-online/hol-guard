"""Stable snapshot-local row ordering shared by source adapters and capture."""

from __future__ import annotations

import json
from collections.abc import Mapping


def native_policy_row_sort_key(row: Mapping[str, object]) -> str:
    """Preserve the canonical source fields that determine snapshot-local IDs."""
    return json.dumps(
        {key: value for key, value in row.items() if key not in {"decision_id", "reason", "owner"}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
