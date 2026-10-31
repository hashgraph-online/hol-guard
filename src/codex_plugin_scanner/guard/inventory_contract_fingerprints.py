"""Stable content identities and bounded inventory fingerprints."""

from __future__ import annotations

import hashlib
import json

from .inventory_contract_constants import _WHITESPACE_RE
from .inventory_contract_models import GuardAgentInventoryFinding, GuardAgentInventoryItem, GuardInventorySource
from .native_inventory_snapshot_digest import native_inventory_snapshot_digest


def fingerprint_text(value: str) -> str:
    """Hash UTF-8 text using the inventory content-identity algorithm."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fingerprint_mapping(value: object) -> str:
    """Hash a mapping after deterministic JSON serialization."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return fingerprint_text(encoded)


def _inventory_snapshot_content_hash(
    *,
    agent_type: str,
    items: tuple[GuardAgentInventoryItem, ...],
    findings: tuple[GuardAgentInventoryFinding, ...],
    sources: tuple[GuardInventorySource, ...],
    runtime_version: str | None,
) -> str:
    """Compute snapshot identity from stable evidence rather than observation timestamps.

    The rules that make the identity repeatable - which observation fields are
    dropped, how nested lists are ordered, how rows are sorted and the exact
    serialization the hash is taken over - live in the native runtime. A
    resident that cannot answer leaves the snapshot without an identity rather
    than with one computed here, because two implementations of this grammar
    would disagree about whether an inventory changed.
    """
    return native_inventory_snapshot_digest(
        agent_type=agent_type,
        items=items,
        findings=findings,
        sources=sources,
        runtime_version=runtime_version,
    )


def _stable_snapshot_value(value: object) -> object:
    """Remove volatile fields before calculating a repeatable snapshot fingerprint."""
    if isinstance(value, dict):
        return {
            key: _stable_snapshot_value(item)
            for key, item in sorted(value.items(), key=lambda entry: str(entry[0]))
            if str(key)
            not in {
                "attestation",
                "attestationBindings",
                "capturedAt",
                "duration_ms",
                "durationMs",
                "elapsedMs",
                "evidenceHash",
                "generatedAt",
                "lastSeenAt",
                "observedAt",
                "scanDurationMs",
                "syncedAt",
            }
        }
    if isinstance(value, (list, tuple)):
        return sorted((_stable_snapshot_value(item) for item in value), key=_stable_snapshot_sort_key)
    return value


def _stable_snapshot_sort_key(value: object) -> str:
    """Build a deterministic key for ordering stable snapshot values."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


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
