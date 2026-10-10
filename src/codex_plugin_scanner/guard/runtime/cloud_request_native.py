"""Typed projections between Guard Cloud payloads and the native authority owner.

The resident scrubs every Cloud-bound text, projects local approval requests into
Cloud-safe payloads, applies the snapshot byte budget and builds review-event
display fields. Every function here ships a minimal projection and returns the
owner's answer unchanged. A transport, scope or shape failure raises
``NativeRunnerAuthorityError`` (a ``ValueError``), so callers refuse to sync
rather than send unscrubbed text. An inconsistent authoritative decision keeps
its historical ``ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)`` contract.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from typing import Any

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from .decisions import AUTHORITATIVE_DECISION_INCONSISTENT

_DECISION_INCONSISTENT_CODE = "native_runner_authority_decision_inconsistent"
_INVALID_RESULT = "native_runner_authority_result_invalid"
_MEMO_SIZE = 4096
# The owner keeps the head and tail of a long command (at most 65,536 UTF-16 units),
# so an oversized text column keeps this many chars at each end and drops the middle;
# one oversized row then never exceeds the resident request cap. The action envelope
# is JSON, so it gets a larger plain cut.
_ROW_TEXT_KEEP_CHARS = 70_000
_ROW_TEXT_MAX_CHARS = 2 * _ROW_TEXT_KEEP_CHARS
_ROW_ENVELOPE_MAX_CHARS = 400_000
_ROW_ENVELOPE_KEYS = frozenset({"action_envelope_json"})
# A text with no usable scrub (resident outage or refusal) is withheld, never sent raw.
_ERROR_TEXT_MAX_CHARS = 20_000
WITHHELD_ERROR_TEXT = "[withheld: Cloud-safe scrub unavailable]"
# Bound resident refusals that describe the row itself, not an outage.
NATIVE_ROW_REFUSAL_CODES = frozenset(
    {
        "native_runner_authority_request_too_large",
        "native_runner_authority_invalid",
        "native_runner_authority_component_unencodable",
    }
)
# The resident accepts 4 MiB per request: send a snapshot in one call when it fits
# and otherwise build its items in smaller chunks first.
_ONE_SHOT_BYTES = 3_000_000
_CHUNK_BYTES = 2_000_000

# The only request-row columns the resident reads; every other column stays in
# Python so a request stays far below the resident request cap.
_ROW_KEYS = (
    "request_id",
    "status",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_hash",
    "artifact_label",
    "source_label",
    "trigger_summary",
    "why_now",
    "risk_headline",
    "risk_summary",
    "policy_action",
    "recommended_scope",
    "created_at",
    "last_seen_at",
    "resolved_at",
    "queue_group_id",
    "review_kind",
    "risk_category",
    "capability_category",
    "publisher",
    "package_manager",
    "package_name",
    "resolution_action",
    "resolution_scope",
    "raw_command_text",
    "rawCommandText",
    "command_text",
    "commandText",
    "action_envelope_json",
    "action_identity",
)


def _invalid() -> NativeRunnerAuthorityError:
    return NativeRunnerAuthorityError(_INVALID_RESULT)


def _fit_row_value(key: str, value: object) -> object:
    if not isinstance(value, str):
        return value
    if key in _ROW_ENVELOPE_KEYS:
        # A cut JSON document is unparseable, which the owner reports as a malformed envelope.
        return value if len(value) <= _ROW_ENVELOPE_MAX_CHARS else value[:_ROW_ENVELOPE_MAX_CHARS]
    if len(value) <= _ROW_TEXT_MAX_CHARS:
        return value
    return value[:_ROW_TEXT_KEEP_CHARS] + value[-_ROW_TEXT_KEEP_CHARS:]


def project_request_row(row: Mapping[str, object]) -> dict[str, object]:
    """The columns of a local request row the native owner reads."""

    return {key: _fit_row_value(key, row[key]) for key in _ROW_KEYS if key in row}


def _call(kind: str, args: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return native_runner_authority(kind, args)
    except NativeRunnerAuthorityError as error:
        if str(error) == _DECISION_INCONSISTENT_CODE:
            raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT) from error
        raise


def _text_list(payload: Mapping[str, Any], expected: int) -> list[str]:
    texts = payload.get("texts")
    if not isinstance(texts, list) or len(texts) != expected or not all(isinstance(text, str) for text in texts):
        raise _invalid()
    return texts


def cloud_scrub_texts(values: Sequence[str]) -> list[str]:
    """Scrub many texts with one resident round trip."""

    if not values:
        return []
    return _text_list(_call("cloud_scrub_texts", {"texts": list(values)}), len(values))


class _ScrubMemo:
    """Bounded memo of scrubbed texts keyed by digest, so raw text is never retained."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._entries: OrderedDict[bytes, str] = OrderedDict()
        self._lock = threading.Lock()
        # A keyed, process-local MAC: the key never leaves memory, so an entry cannot
        # be matched against a guessed text, and the memo keeps no raw text.
        self._key = secrets.token_bytes(32)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def get(self, value: str) -> str:
        key = hashlib.blake2b(value.encode("utf-8", "surrogatepass"), key=self._key, digest_size=32).digest()
        with self._lock:
            found = self._entries.get(key)
            if found is not None:
                self._entries.move_to_end(key)
                return found
        scrubbed = cloud_scrub_texts([value])[0]
        with self._lock:
            self._entries[key] = scrubbed
            while len(self._entries) > self._size:
                self._entries.popitem(last=False)
        return scrubbed


_SCRUB_MEMO = _ScrubMemo(_MEMO_SIZE)


def cloud_scrub_text(value: str) -> str:
    """The Cloud-safe form of one text; the pure derivation is memoized by digest."""

    return _SCRUB_MEMO.get(value)


def cloud_error_text(value: str) -> str:
    """Cloud-safe error text that never raises and never leaks: unscrubbable text is withheld."""

    try:
        return cloud_scrub_text(value[:_ERROR_TEXT_MAX_CHARS])
    except NativeRunnerAuthorityError:
        return WITHHELD_ERROR_TEXT


def cloud_error_texts(values: Sequence[str]) -> list[str]:
    """Cloud-safe error texts, one batched round trip when it is accepted."""

    cut = [value[:_ERROR_TEXT_MAX_CHARS] for value in values]
    try:
        return cloud_scrub_texts(cut)
    except NativeRunnerAuthorityError:
        return [cloud_error_text(value) for value in cut]


_TOO_LARGE_CODES = frozenset(
    {"native_runner_authority_request_too_large", "native_runner_authority_response_too_large"}
)


def cloud_sync_receipt_payloads(
    receipts: Sequence[Mapping[str, object]],
    *,
    device_id: str,
    device_name: str,
    redaction_level: str,
    now: str,
) -> list[dict[str, object]]:
    """Cloud receipt payloads for stored receipt rows, in one resident round trip.

    A batch that exceeds a resident byte cap is halved until it fits, so only a
    single receipt larger than the cap is refused.
    """

    if not receipts:
        return []
    args = {
        "receipts": [dict(receipt) for receipt in receipts],
        "device_id": device_id,
        "device_name": device_name,
        "redaction_level": redaction_level,
        "now": now,
    }
    try:
        payloads = _call("cloud_sync_receipt_payloads", args).get("payloads")
    except NativeRunnerAuthorityError as error:
        if str(error) not in _TOO_LARGE_CODES or len(receipts) == 1:
            raise
        middle = len(receipts) // 2
        common = {"device_id": device_id, "device_name": device_name, "redaction_level": redaction_level, "now": now}
        return [
            *cloud_sync_receipt_payloads(receipts[:middle], **common),
            *cloud_sync_receipt_payloads(receipts[middle:], **common),
        ]
    if (
        not isinstance(payloads, list)
        or len(payloads) != len(receipts)
        or not all(isinstance(payload, dict) for payload in payloads)
    ):
        raise _invalid()
    return payloads


def cloud_safe_local_request_payload(
    item: Mapping[str, object],
    *,
    redaction_level: str,
) -> dict[str, object]:
    payload = _call(
        "cloud_request_payload",
        {"item": project_request_row(item), "redaction_level": redaction_level},
    ).get("payload")
    if not isinstance(payload, dict):
        raise _invalid()
    return payload


def cloud_review_event_display(item: Mapping[str, object], *, redaction_level: str) -> dict[str, Any]:
    """Display command/summary/provenance plus the safe request payload."""

    answer = _call(
        "cloud_review_event_display",
        {"item": project_request_row(item), "redaction_level": redaction_level},
    )
    if not isinstance(answer.get("payload"), dict) or not isinstance(answer.get("display_command"), str):
        raise _invalid()
    return answer


def _encoded_size(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))


def _built_page(
    common: Mapping[str, object],
    status: str,
    page: Mapping[str, object],
) -> dict[str, object]:
    """Build one page's items in chunks that each fit one resident request."""

    entries = page.get("rows")
    if not isinstance(entries, list):
        raise _invalid()
    items: list[object] = []
    chunk: list[object] = []
    chunk_bytes = 0
    for entry in [*entries, None]:
        entry_bytes = 0 if entry is None else _encoded_size(entry)
        if chunk and (entry is None or chunk_bytes + entry_bytes > _CHUNK_BYTES):
            built = _call("local_request_snapshot_items", {**common, "status": status, "rows": chunk}).get("items")
            if not isinstance(built, list):
                raise _invalid()
            items.extend(built)
            chunk, chunk_bytes = [], 0
        if entry is not None:
            chunk.append(entry)
            chunk_bytes += entry_bytes
    return {"items": items, "complete": page.get("complete")}


def local_request_snapshot(
    *,
    redaction_level: str,
    routing_inputs: Mapping[str, object],
    now: str,
    pending: Mapping[str, object],
    resolved: Mapping[str, object],
) -> dict[str, object]:
    """The bounded snapshot; oversized row sets are built in resident-sized chunks."""

    common: dict[str, object] = {
        "redaction_level": redaction_level,
        "routing_inputs": dict(routing_inputs),
        "now": now,
    }
    args: dict[str, object] = {**common, "pending": dict(pending), "resolved": dict(resolved)}
    if _encoded_size(args) > _ONE_SHOT_BYTES:
        args["pending"] = _built_page(common, "pending", pending)
        args["resolved"] = _built_page(common, "resolved", resolved)
    payload = _call("local_request_snapshot", args)
    if not isinstance(payload.get("requests"), list):
        raise _invalid()
    return payload
