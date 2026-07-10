"""Default-deny sanitizers for guard-mcp.v1 MCP output.

Every field not in the explicit allowlist is dropped. All values are
length-capped, control-characters removed, Unicode normalized, and
enum-validated before being included in any MCP response.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from .schemas import (
    MAX_FETCH_TEXT_BYTES,
    VALID_DECISIONS,
    VALID_HARNESSES,
    VALID_KINDS,
)

_MAX_FIELD_LENGTH = 1024
_MAX_TITLE_LENGTH = 256
_MAX_SUMMARY_LENGTH = 4096

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _normalize_text(value: Any, max_length: int) -> str:
    if value is None:
        return ""
    text = str(value)
    text = unicodedata.normalize("NFKC", text)
    text = _CONTROL_CHARS.sub("", text)
    return text[:max_length]


def sanitize_search_result(raw: dict[str, object]) -> dict[str, object]:
    allowed: dict[str, object] = {}

    raw_id = _normalize_text(raw.get("id"), 256)
    if raw_id:
        allowed["id"] = raw_id

    allowed["title"] = _normalize_text(raw.get("title"), _MAX_TITLE_LENGTH)
    allowed["kind"] = _validate_enum(raw.get("kind"), VALID_KINDS, "receipt")
    allowed["harness"] = _validate_enum(raw.get("harness"), VALID_HARNESSES, "")
    allowed["decision"] = _validate_enum(raw.get("decision"), VALID_DECISIONS, "unknown")

    changed = raw.get("changedSinceLastApproval")
    if isinstance(changed, bool):
        allowed["changedSinceLastApproval"] = changed

    return allowed


def sanitize_fetch_result(raw: dict[str, object]) -> dict[str, object]:
    allowed: dict[str, object] = {}

    raw_id = _normalize_text(raw.get("id"), 256)
    if raw_id:
        allowed["id"] = raw_id

    allowed["title"] = _normalize_text(raw.get("title"), _MAX_TITLE_LENGTH)
    allowed["kind"] = _validate_enum(raw.get("kind"), VALID_KINDS, "receipt")
    allowed["harness"] = _validate_enum(raw.get("harness"), VALID_HARNESSES, "")
    allowed["decision"] = _validate_enum(raw.get("decision"), VALID_DECISIONS, "unknown")

    changed = raw.get("changedSinceLastApproval")
    if isinstance(changed, bool):
        allowed["changedSinceLastApproval"] = changed

    text = _normalize_text(raw.get("text"), MAX_FETCH_TEXT_BYTES)
    allowed["text"] = text
    allowed["truncated"] = bool(raw.get("truncated", False))

    return allowed


def sanitize_status_result(raw: dict[str, object]) -> dict[str, object]:
    allowed: dict[str, object] = {}

    allowed["cliAvailable"] = bool(raw.get("cliAvailable", True))
    allowed["receiptCount"] = (
        int(raw.get("receiptCount", 0))
        if isinstance(raw.get("receiptCount"), (int, float))
        else 0
    )
    allowed["inventoryCount"] = (
        int(raw.get("inventoryCount", 0))
        if isinstance(raw.get("inventoryCount"), (int, float))
        else 0
    )

    version = _normalize_text(raw.get("cliVersion"), _MAX_FIELD_LENGTH)
    if version:
        allowed["cliVersion"] = version

    return allowed


def _validate_enum(value: Any, valid: frozenset[str], default: str) -> str:
    if value is None:
        return default
    text = str(value)
    if text in valid:
        return text
    return default
