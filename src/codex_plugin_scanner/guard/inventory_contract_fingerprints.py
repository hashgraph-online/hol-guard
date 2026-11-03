"""Stable content identities and bounded inventory fingerprints."""

from __future__ import annotations

import hashlib
import json

from .inventory_contract_constants import _WHITESPACE_RE


def fingerprint_text(value: str) -> str:
    """Hash UTF-8 text using the inventory content-identity algorithm."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fingerprint_mapping(value: object) -> str:
    """Hash a mapping after deterministic JSON serialization."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return fingerprint_text(encoded)


def inventory_item_id(agent_type: str, item_kind: str, display_name: str, semantic_text: str) -> str:
    """Build a stable item identifier from harness, source, and artifact identity."""
    normalized_text = _WHITESPACE_RE.sub(" ", semantic_text.strip())
    digest = fingerprint_mapping(
        {
            "agent_type": agent_type,
            "display_name": display_name.strip().lower(),
            "item_kind": item_kind,
            "semantic_text": normalized_text,
        }
    )
    return f"{agent_type}:{item_kind}:{digest[:24]}"
