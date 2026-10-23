"""Resident bridge for the ``inventory_item_classification`` op.

Six readings decide what an inventory item is: its kind, the capabilities it
declares, its risk level, the hash that identifies its content, and which
evidence keys a skill is allowed to keep. All six are protection decisions
made from metadata Guard scanned, so the resident makes them and this module
only ships the artifact across and applies the answer. Nothing is derived
here: an unavailable resident cannot quietly settle on ``info`` for an item it
never classified, and a snapshot built without the resident carries no items
at all.

The whole artifact set is asked for at once, for the same reason the source
evidence op batches: one request per artifact would put the resident on the
critical path of every item an AIBOM run walks.

The answer carries the metadata changes as key edits rather than a rewritten
mapping, so an item's own insertion order survives the round trip and a
snapshot's exported keys do not churn.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

INVENTORY_ITEM_CLASSIFICATION_FEATURE = "inventory-item-classification-v1"
_REQUEST_SCHEMA = "guard-inventory-item-classification-request.v1"
_RESULT_SCHEMA = "guard-inventory-item-classification-result.v1"
# The deadline covers a whole batch, and a batch is as large as the contract
# allows. The work is pure metadata reading with no filesystem or network in
# it, so the per-entry share is small; the floor is what a cold resident needs
# to answer at all, and the ceiling is the point past which failing closed
# beats hanging the snapshot.
_TIMEOUT_FLOOR_SECONDS = 10.0
_TIMEOUT_PER_ENTRY_SECONDS = 0.02
_TIMEOUT_CEILING_SECONDS = 30.0
# Mirrors ``INVENTORY_ITEM_CLASSIFICATION_MAX_ENTRIES``: the resident refuses a
# request carrying more entries than this.
_MAX_ENTRIES = 512
# Mirrors ``INVENTORY_ITEM_CLASSIFICATION_MAX_BYTES``, which is itself held
# under the transport's own frame limit so an oversized batch is refused for
# its size rather than as a malformed frame.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# What one batch's entries may serialize to. The envelope around them -- the
# schema, the request id, and JSON's own punctuation -- is small and bounded,
# and leaving a share of the limit for it keeps a batch this side accepted
# from arriving as one the resident refuses on size.
_MAX_BATCH_ENTRY_BYTES = _MAX_REQUEST_BYTES - (_MAX_REQUEST_BYTES // 8)
_ANSWER_KEYS = (
    "item_kind",
    "metadata_removals",
    "metadata_updates",
    "content_hash",
    "capability_categories",
    "risk_level",
)


class InventoryItemClassificationUnavailableError(RuntimeError):
    """The resident could not classify the inventory items."""

    code = "native_inventory_item_classification_unavailable"


def native_inventory_item_classification(
    entries: Sequence[Mapping[str, object]],
    *,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """Return one classification mapping per entry, in order.

    Each entry carries ``artifact_id``, ``artifact_type``, ``name``,
    ``metadata`` and the optional ``primary_content_hash`` of Guard's own read
    of the artifact's document. Each answer carries ``item_kind``,
    ``metadata_removals``, ``metadata_updates``, ``content_hash``,
    ``capability_categories`` and ``risk_level``.

    Raises ``InventoryItemClassificationUnavailableError`` when the resident
    cannot answer, so a caller fails closed rather than publishing a snapshot
    whose items were never classified.
    """

    if not entries:
        return []
    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise InventoryItemClassificationUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise InventoryItemClassificationUnavailableError
    answers: list[dict[str, object]] = []
    for batch in _batches(entries):
        answers.extend(_classification_for_batch(batch, home))
    return answers


def _batches(entries: Sequence[Mapping[str, object]]) -> Iterator[list[dict[str, object]]]:
    """Split the artifacts into requests the resident will accept.

    An entry carries the artifact's whole sanitized metadata, which for an MCP
    server is every tool definition it declares, so a few hundred artifacts can
    outgrow the request limit long before they outgrow ``_MAX_ENTRIES``.
    Counting entries alone left those snapshots failing closed on a limit the
    caller could have split under, so the serialized size is counted too.

    One entry larger than a whole batch still travels alone and is refused by
    the resident for its size. Trimming it here would make this module decide
    which metadata an item's classification reads, which is the second
    implementation the op exists to remove.
    """

    batch: list[dict[str, object]] = []
    size = 0
    for entry in entries:
        wire = _entry_wire(entry)
        cost = _wire_bytes(wire)
        if batch and (len(batch) >= _MAX_ENTRIES or size + cost > _MAX_BATCH_ENTRY_BYTES):
            yield batch
            batch, size = [], 0
        batch.append(wire)
        size += cost
    if batch:
        yield batch


def _wire_bytes(wire: Mapping[str, object]) -> int:
    """What one entry costs in a request, as the transport will measure it.

    An entry that cannot be serialized is counted as a whole batch so it
    travels alone, and the request it travels in raises the same unavailability
    the resident would answer with.
    """

    try:
        return len(json.dumps(wire, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return _MAX_BATCH_ENTRY_BYTES


def _classification_for_batch(
    entries: Sequence[dict[str, object]],
    home: Path,
) -> list[dict[str, object]]:
    """Ask the resident about one batch the contract is willing to accept."""

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"inventory-item-classification-{uuid4().hex}",
        "entries": list(entries),
    }
    try:
        response = _resident_request(
            operation="inventory_item_classification",
            request=wire,
            guard_home=home,
            timeout_seconds=_batch_timeout_seconds(len(entries)),
            required_feature=INVENTORY_ITEM_CLASSIFICATION_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise InventoryItemClassificationUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise InventoryItemClassificationUnavailableError
    items = payload.get("items")
    if not isinstance(items, list) or len(items) != len(entries):
        raise InventoryItemClassificationUnavailableError
    if not all(_is_answer(item) for item in items):
        raise InventoryItemClassificationUnavailableError
    return cast("list[dict[str, object]]", items)


def _is_answer(item: object) -> bool:
    """Whether one answer carries every reading the caller will apply.

    A partial answer would leave the caller deriving the rest, which is the
    second implementation this op exists to remove.
    """

    return isinstance(item, dict) and all(key in item for key in _ANSWER_KEYS)


def _batch_timeout_seconds(entry_count: int) -> float:
    """The deadline one batch of this size is allowed."""

    return min(
        _TIMEOUT_CEILING_SECONDS,
        _TIMEOUT_FLOOR_SECONDS + _TIMEOUT_PER_ENTRY_SECONDS * entry_count,
    )


def _entry_wire(entry: Mapping[str, object]) -> dict[str, object]:
    """Ship one artifact's identity and metadata."""

    metadata = entry.get("metadata")
    wire: dict[str, object] = {
        "artifact_id": str(entry.get("artifact_id", "")),
        "artifact_type": str(entry.get("artifact_type", "")),
        "name": str(entry.get("name", "")),
        "metadata": dict(metadata) if isinstance(metadata, Mapping) else {},
    }
    primary_content_hash = entry.get("primary_content_hash")
    if isinstance(primary_content_hash, str) and primary_content_hash:
        wire["primary_content_hash"] = primary_content_hash
    return wire
