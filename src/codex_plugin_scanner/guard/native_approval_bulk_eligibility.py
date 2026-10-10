"""Resident bridge for the ``approval_bulk_eligibility`` op.

Rust decides whether a pending approval request may be approved once in a bulk
action. This module only narrows stored requests to the fields the decision
reads, binds the reply by ``request_id`` plus ``request_sha256`` and decodes
it. A missing, malformed or mismatched reply raises; nothing is ever
recomputed in Python, so an unavailable resident can never approve a request.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_approval_queue_identity import _json_value
from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

APPROVAL_BULK_ELIGIBILITY_FEATURE = "approval-bulk-eligibility-v1"
_REQUEST_SCHEMA = "guard-approval-bulk-eligibility-request.v1"
_RESULT_SCHEMA = "guard-approval-bulk-eligibility-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_ITEMS = 1024
UNAVAILABLE = "native_approval_bulk_eligibility_unavailable"
_FIELDS = (
    "policy_action",
    "status",
    "artifact_name",
    "artifact_type",
    "risk_headline",
    "risk_summary",
    "trigger_summary",
    "launch_summary",
    "why_now",
    "launch_target",
    "raw_command_text",
    "risk_signals",
    "action_envelope_json",
    "decision_v2_json",
)


class ApprovalBulkEligibilityUnavailableError(ValueError):
    """The resident could not judge the requests; nothing was recomputed."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE)


def _item(request: Mapping[str, object]) -> dict[str, object]:
    # Every field is sent, null when absent: the reply digest binds to the
    # resident's own serialization of the typed request.
    return {field: _json_value(request.get(field)) for field in _FIELDS}


def _wire_bytes(items: Sequence[Mapping[str, object]], *, home_dir: str) -> int:
    """Byte length of the envelope `_resident_request` actually sends."""

    envelope = {
        "operation": "approval_bulk_eligibility",
        "request": {
            "schema": _REQUEST_SCHEMA,
            "request_id": "approval-bulk-eligibility-" + ("0" * 32),
            "home_dir": home_dir,
            "items": [dict(item) for item in items],
        },
        "deadline_budget_ms": max(1, int(_TIMEOUT_SECONDS * 1000)),
    }
    try:
        encoded = json.dumps(envelope).encode("utf-8")
    except (TypeError, ValueError):
        raise ApprovalBulkEligibilityUnavailableError from None
    return len(encoded)


def _eligible_chunks(
    items: Sequence[Mapping[str, object]], *, home_dir: str
) -> tuple[list[bool | None], list[list[int]]]:
    """Pack items under the count and byte caps.

    An item that cannot fit in a call by itself is ineligible. The other items
    are still sent. A resident outage is not invented here.
    """

    verdicts: list[bool | None] = [None] * len(items)
    chunks: list[list[int]] = []
    current: list[int] = []
    for index, item in enumerate(items):
        if _wire_bytes([item], home_dir=home_dir) > _MAX_REQUEST_BYTES:
            verdicts[index] = False
            continue
        if not current:
            current = [index]
            continue
        proposed = [*current, index]
        over_count = len(proposed) > _MAX_ITEMS
        proposed_items = [items[item_index] for item_index in proposed]
        over_bytes = _wire_bytes(proposed_items, home_dir=home_dir) > _MAX_REQUEST_BYTES
        if over_count or over_bytes:
            chunks.append(current)
            current = [index]
        else:
            current = proposed
    if current:
        chunks.append(current)
    return verdicts, chunks


def native_bulk_allow_once_eligibility(
    requests: Sequence[Mapping[str, object]],
    *,
    guard_home: Path,
) -> list[bool]:
    """Judge stored approval requests in the resident; raise when it cannot."""

    if not requests:
        return []
    home = Path(guard_home)
    if not ensure_resident_prerequisite(home):
        raise ApprovalBulkEligibilityUnavailableError
    prepared = [_item(request) for request in requests]
    home_dir = str(Path.home())
    verdicts, chunks = _eligible_chunks(prepared, home_dir=home_dir)
    for chunk in chunks:
        wire: dict[str, object] = {
            "schema": _REQUEST_SCHEMA,
            "request_id": f"approval-bulk-eligibility-{uuid4().hex}",
            "home_dir": home_dir,
            "items": [dict(prepared[index]) for index in chunk],
        }
        try:
            response = _resident_request(
                operation="approval_bulk_eligibility",
                request=wire,
                guard_home=home,
                timeout_seconds=_TIMEOUT_SECONDS,
                required_feature=APPROVAL_BULK_ELIGIBILITY_FEATURE,
                response_schema=_RESULT_SCHEMA,
                max_request_bytes=_MAX_REQUEST_BYTES,
                record_success=False,
            )
        except (TypeError, ValueError, OSError, RuntimeError):
            raise ApprovalBulkEligibilityUnavailableError from None
        payload = _payload(response, wire, home)
        reply = payload.get("items") if payload is not None else None
        if not isinstance(reply, list) or len(reply) != len(chunk):
            raise ApprovalBulkEligibilityUnavailableError
        for index, entry in zip(chunk, reply, strict=True):
            eligible = entry.get("eligible") if isinstance(entry, dict) else None
            if not isinstance(eligible, bool):
                raise ApprovalBulkEligibilityUnavailableError
            verdicts[index] = eligible
    if any(verdict is None for verdict in verdicts):
        raise ApprovalBulkEligibilityUnavailableError
    return [verdict is True for verdict in verdicts]
