"""Stable content identities and bounded inventory fingerprints."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .inventory_contract_constants import _IGNORED_TREE_DIR_NAMES, _MAX_FINGERPRINT_FILE_BYTES, _WHITESPACE_RE
from .inventory_contract_models import GuardAgentInventoryFinding, GuardAgentInventoryItem, GuardInventorySource
from .inventory_contract_redaction import redact_local_path


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
    """Compute snapshot identity from stable evidence rather than observation timestamps."""
    return fingerprint_mapping(
        {
            "agent_type": agent_type,
            "runtime_version": runtime_version,
            "items": [
                {
                    "capability_categories": item.capability_categories,
                    "content_hash": item.content_hash,
                    "drift_state": item.drift_state,
                    "item_id": item.item_id,
                    "item_kind": item.item_kind,
                    "metadata": _stable_snapshot_value(item.metadata),
                    "risk_level": item.risk_level,
                    "scanner_sources": item.scanner_sources,
                    "security_score": item.security_score,
                    "source_fingerprint": item.source_fingerprint,
                }
                for item in sorted(items, key=lambda value: (value.item_kind, value.item_id))
            ],
            "findings": [
                {
                    "artifact_id": finding.artifact_id,
                    "check_id": finding.check_id,
                    "confidence": finding.confidence,
                    "evidence": _stable_snapshot_value(finding.evidence),
                    "finding_id": finding.finding_id,
                    "severity": finding.severity,
                    "source": finding.source,
                    "summary": finding.summary,
                    "title": finding.title,
                }
                for finding in sorted(findings, key=lambda value: (value.source, value.finding_id))
            ],
            "sources": [
                {
                    "detail": source.detail,
                    "source_id": source.source_id,
                    "source_type": source.source_type,
                    "status": source.status,
                }
                for source in sorted(sources, key=lambda value: (value.source_type, value.source_id))
            ],
        }
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


def fingerprint_path_tree(root: Path, *, home_dir: Path | None = None) -> str:
    """Fingerprint a bounded set of files without following untrusted path traversal."""
    entries: list[dict[str, str]] = []
    if root.is_file():
        paths = [root]
    else:
        paths = sorted(
            path
            for path in root.rglob("*")
            if path.is_file()
            and path.name != ".env"
            and not any(part in _IGNORED_TREE_DIR_NAMES for part in path.parts)
        )
    for path in paths:
        safe_path = redact_local_path(path, home_dir=home_dir)
        content_hash = _fingerprint_file_bytes(path)
        entries.append({"path": safe_path, "sha256": content_hash})
    return fingerprint_mapping(entries)


def _fingerprint_file_bytes(path: Path) -> str:
    """Read bounded file content for fingerprinting within the permitted inspection roots."""
    digest = hashlib.sha256()
    remaining = _MAX_FINGERPRINT_FILE_BYTES
    with path.open("rb") as file_handle:
        while remaining > 0:
            chunk = file_handle.read(min(65536, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()
