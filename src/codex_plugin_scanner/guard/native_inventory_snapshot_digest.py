"""Resident bridge for the ``inventory_snapshot_digest`` op.

A snapshot's content identity is what decides whether an inventory changed,
and arriving at it is a grammar rather than a hash: observation stamps are
dropped, nested lists are ordered, items, findings and sources are each sorted
by their own key, and the result is serialized exactly one way before it is
digested. That grammar lives in the native runtime. This module ships the rows
the digest reads and hands back the answer; nothing is computed here, so an
unavailable resident cannot produce an identity that a resident would have
spelled differently.

Only the fields the digest actually reads travel. A snapshot's whole JSON is
far larger than the evidence its identity rests on, and a field the grammar
ignores would only make the request bigger.

The snapshot travels whole. Unlike the evidence op there is nothing to batch:
a digest over part of an inventory is not a digest of it, so a snapshot past
the contract's bound fails rather than being hashed here instead.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from .inventory_contract_models import GuardAgentInventoryFinding, GuardAgentInventoryItem, GuardInventorySource
from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

INVENTORY_SNAPSHOT_DIGEST_FEATURE = "inventory-snapshot-digest-v1"
_REQUEST_SCHEMA = "guard-inventory-snapshot-digest-request.v1"
_RESULT_SCHEMA = "guard-inventory-snapshot-digest-result.v1"
# The work is one canonical serialization and one hash over rows already held
# in memory, so the floor is what a cold resident needs to answer at all and
# the per-row share is what the serialization actually scales with. The
# ceiling is the point past which failing closed beats hanging the snapshot
# the caller is still assembling.
_TIMEOUT_FLOOR_SECONDS = 5.0
_TIMEOUT_PER_ROW_SECONDS = 0.002
_TIMEOUT_CEILING_SECONDS = 30.0
# Mirrors ``INVENTORY_SNAPSHOT_DIGEST_MAX_BYTES``, which is itself held under
# the transport's own frame limit so an oversized snapshot is refused for its
# size rather than as a malformed frame.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_HEX_DIGITS = frozenset("0123456789abcdef")


class InventorySnapshotDigestUnavailableError(RuntimeError):
    """The resident could not compute the snapshot's content identity."""

    code = "native_inventory_snapshot_digest_unavailable"


def native_inventory_snapshot_digest(
    *,
    agent_type: str,
    items: Sequence[GuardAgentInventoryItem],
    findings: Sequence[GuardAgentInventoryFinding],
    sources: Sequence[GuardInventorySource],
    runtime_version: str | None,
    guard_home: Path | None = None,
) -> str:
    """Return the snapshot's content hash as 64 hex characters.

    Raises ``InventorySnapshotDigestUnavailableError`` when the resident
    cannot answer, so a caller fails closed rather than publishing a snapshot
    whose identity was computed somewhere else.
    """

    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise InventorySnapshotDigestUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise InventorySnapshotDigestUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"inventory-snapshot-digest-{uuid4().hex}",
        "agent_type": agent_type,
        "runtime_version": runtime_version,
        "items": [_item_wire(item) for item in items],
        "findings": [_finding_wire(finding) for finding in findings],
        "sources": [_source_wire(source) for source in sources],
    }
    try:
        response = _resident_request(
            operation="inventory_snapshot_digest",
            request=wire,
            guard_home=home,
            timeout_seconds=_timeout_seconds(len(items) + len(findings) + len(sources)),
            required_feature=INVENTORY_SNAPSHOT_DIGEST_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise InventorySnapshotDigestUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise InventorySnapshotDigestUnavailableError
    digest = payload.get("digest")
    if not isinstance(digest, str) or len(digest) != 64:
        raise InventorySnapshotDigestUnavailableError
    # The digest becomes the snapshot's identity, and sixty-four characters of
    # anything would satisfy a length check alone. A reply that is bound to
    # this request but is not a hash is a runtime that no longer agrees with
    # this contract, which is the same unavailability as no reply.
    if any(character not in _HEX_DIGITS for character in digest):
        raise InventorySnapshotDigestUnavailableError
    return digest


def _timeout_seconds(row_count: int) -> float:
    """The deadline a snapshot of this many rows is allowed."""

    return min(
        _TIMEOUT_CEILING_SECONDS,
        _TIMEOUT_FLOOR_SECONDS + _TIMEOUT_PER_ROW_SECONDS * row_count,
    )


def _item_wire(item: GuardAgentInventoryItem) -> dict[str, object]:
    """Ship the item fields the digest reads."""

    return {
        "item_id": item.item_id,
        "item_kind": item.item_kind,
        "metadata": item.metadata,
        "capability_categories": list(item.capability_categories),
        "content_hash": item.content_hash,
        "drift_state": item.drift_state,
        "risk_level": item.risk_level,
        "scanner_sources": list(item.scanner_sources),
        "security_score": item.security_score,
        "source_fingerprint": item.source_fingerprint,
    }


def _finding_wire(finding: GuardAgentInventoryFinding) -> dict[str, object]:
    """Ship the finding fields the digest reads.

    ``summary`` travels even when it is ``None``: an absent description and an
    empty one are different snapshots, and the digest shows the difference.
    """

    return {
        "finding_id": finding.finding_id,
        "source": finding.source,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "title": finding.title,
        "artifact_id": finding.artifact_id,
        "check_id": finding.check_id,
        "summary": finding.summary,
        "evidence": finding.evidence,
    }


def _source_wire(source: GuardInventorySource) -> dict[str, object]:
    """Ship the source fields the digest reads."""

    return {
        "source_id": source.source_id,
        "source_type": source.source_type,
        "status": source.status,
        "detail": source.detail,
    }
