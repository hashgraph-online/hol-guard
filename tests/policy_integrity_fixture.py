"""Test-only forger for policy rows written in the pre-v2 or pending layouts.

Runtime signing and verification belong to the resident ``policy_integrity_rows``
op. Tests that plant legacy or out-of-band rows directly in SQLite still need the
canonical envelope bytes, so this mirrors the frozen v1/v2 layout recorded in
``rust/crates/guard-runtime/testdata/policy_integrity_rows/vectors.json``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

_V2 = 2


def _text(row: Mapping[str, object], name: str) -> str | None:
    value = row.get(name)
    return value if isinstance(value, str) and value else None


def _integer(row: Mapping[str, object], name: str) -> int | None:
    value = row.get(name)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def canonical_policy_payload(row: Mapping[str, object], *, integrity_version: int) -> bytes:
    payload: dict[str, object] = {
        name: _text(row, name)
        for name in (
            "action",
            "artifact_hash",
            "artifact_id",
            "expires_at",
            "harness",
            "publisher",
            "scope",
            "source",
            "updated_at",
            "workspace",
        )
    }
    payload["integrity_version"] = integrity_version
    if integrity_version == _V2:
        payload["decision_id"] = _integer(row, "decision_id")
        payload["integrity_generation"] = _integer(row, "integrity_generation")
        payload["owner"] = _text(row, "owner")
        payload["reason"] = _text(row, "reason")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
