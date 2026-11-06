"""Resident bridge for the ``mcp_classify`` op.

Rust describes what an MCP tool's declared schema and the provider's own
annotation claims suggest. Python ships the declarations as data, binds the
reply by ``request_id`` plus ``request_sha256`` and decodes it. Nothing is
described in Python, so an unavailable resident yields no classification at
all rather than a locally invented one.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

MCP_CLASSIFICATION_FEATURE = "mcp-classification-v1"
_OPERATION = "mcp_classify"
_REQUEST_SCHEMA = "guard-mcp-classification-request.v1"
_RESULT_SCHEMA = "guard-mcp-classification-result.v1"
_TIMEOUT_SECONDS = 10.0
# Stays under the resident transport's frame limit, so a page the packer
# accepts is never refused as an oversized frame.
_MAX_REQUEST_BYTES = 6 * 1024 * 1024 - 64 * 1024
_MAX_ITEMS = 1024
UNAVAILABLE = "native_mcp_classification_unavailable"

# What the resident's strict parser accepts, mirrored here only to decide
# whether a declaration can travel. Nothing about the answer is decided here.
_MAX_JSON_STRING_BYTES = 1024 * 1024
_MAX_JSON_COLLECTION_ITEMS = 4096
# The envelope already spends four levels before an item's own fields.
_MAX_ITEM_DEPTH = 32 - 4
_MIN_JSON_INT = -(2**63)
_MAX_JSON_INT = 2**64 - 1


class McpClassificationUnavailableError(ValueError):
    """The resident could not describe the tools; nothing was described here."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE)


def _item(definition: Mapping[str, object]) -> dict[str, object]:
    full_schema = definition.get("full_schema", True)
    return {
        "name": str(definition.get("name") or ""),
        "schema": definition.get("schema"),
        "provider": definition.get("provider"),
        "annotations": definition.get("annotations"),
        "full_schema": bool(full_schema),
    }


def _utf8_length(text: str) -> int | None:
    """Byte length of ``text``, or ``None`` when it has no UTF-8 encoding.

    A provider schema may carry an escaped lone surrogate, which survives
    ``json.loads`` and ``json.dumps`` but cannot be encoded. The resident's
    parser refuses it too, so it travels nowhere.
    """

    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _transportable(value: object, depth: int = 0) -> bool:
    """Whether the resident's parser would accept this declaration.

    A provider-controlled schema can carry a megabyte-long description, a
    lone surrogate, an integer outside the JSON number range or a non-finite
    float. The resident refuses the whole frame over any of them, so a single
    such declaration would cost every other tool in the batch its
    classification. Those are left undescribed instead.
    """

    if depth > _MAX_ITEM_DEPTH:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        length = _utf8_length(value)
        return length is not None and length <= _MAX_JSON_STRING_BYTES
    if isinstance(value, int):
        return _MIN_JSON_INT <= value <= _MAX_JSON_INT
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, Mapping):
        if len(value) > _MAX_JSON_COLLECTION_ITEMS:
            return False
        return all(
            isinstance(key, str) and _transportable(key, depth) and _transportable(item, depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_JSON_COLLECTION_ITEMS:
            return False
        return all(_transportable(item, depth + 1) for item in value)
    return False


def _envelope(items: Sequence[Mapping[str, object]], *, request_id: str) -> dict[str, object]:
    return {
        "operation": _OPERATION,
        "request": {
            "schema": _REQUEST_SCHEMA,
            "request_id": request_id,
            "items": [dict(item) for item in items],
        },
        "deadline_budget_ms": max(1, int(_TIMEOUT_SECONDS * 1000)),
    }


def _wire_bytes(items: Sequence[Mapping[str, object]]) -> int:
    """Byte length of the envelope ``_resident_request`` actually sends."""

    probe = "mcp-classification-" + ("0" * 32)
    return len(json.dumps(_envelope(items, request_id=probe), allow_nan=False).encode("utf-8"))


# json.dumps joins array elements with ", " (comma, space).
_ARRAY_SEPARATOR_BYTES = 2


def _chunks(items: Sequence[Mapping[str, object]], sendable: Sequence[int]) -> list[list[int]]:
    """Pack the sendable declarations under the count and byte caps.

    A declaration too large to travel on its own is left out; the caller hears
    nothing about it rather than receiving a guess for it.
    """

    base = _wire_bytes([])
    chunks: list[list[int]] = []
    current: list[int] = []
    current_bytes = base
    for index in sendable:
        size = _wire_bytes([items[index]]) - base
        if base + size > _MAX_REQUEST_BYTES:
            continue
        added = size if not current else size + _ARRAY_SEPARATOR_BYTES
        if current and (len(current) + 1 > _MAX_ITEMS or current_bytes + added > _MAX_REQUEST_BYTES):
            chunks.append(current)
            current = [index]
            current_bytes = base + size
            continue
        current.append(index)
        current_bytes += added
    if current:
        chunks.append(current)
    return chunks


def native_mcp_classifications(
    definitions: Sequence[Mapping[str, object]],
    *,
    guard_home: Path,
) -> list[dict[str, object] | None]:
    """Describe tool declarations in the resident.

    Raises when the resident cannot answer at all. An individual declaration
    the resident's parser would refuse comes back as ``None``: undescribed,
    never described from here.
    """

    if not definitions:
        return []
    home = Path(guard_home)
    if not ensure_resident_prerequisite(home):
        raise McpClassificationUnavailableError
    prepared = [_item(definition) for definition in definitions]
    sendable = [index for index, item in enumerate(prepared) if _transportable(item)]
    described: list[dict[str, object] | None] = [None] * len(prepared)
    for chunk in _chunks(prepared, sendable):
        wire: dict[str, object] = {
            "schema": _REQUEST_SCHEMA,
            "request_id": f"mcp-classification-{uuid4().hex}",
            "items": [dict(prepared[index]) for index in chunk],
        }
        try:
            response = _resident_request(
                operation=_OPERATION,
                request=wire,
                guard_home=home,
                timeout_seconds=_TIMEOUT_SECONDS,
                required_feature=MCP_CLASSIFICATION_FEATURE,
                response_schema=_RESULT_SCHEMA,
                max_request_bytes=_MAX_REQUEST_BYTES,
                record_success=False,
            )
        except (TypeError, ValueError, OSError, RuntimeError):
            raise McpClassificationUnavailableError from None
        payload = _payload(response, wire, home)
        reply = payload.get("classifications") if payload is not None else None
        if not isinstance(reply, list) or len(reply) != len(chunk):
            raise McpClassificationUnavailableError
        for index, entry in zip(chunk, reply, strict=True):
            if not isinstance(entry, dict):
                raise McpClassificationUnavailableError
            described[index] = entry
    return described
