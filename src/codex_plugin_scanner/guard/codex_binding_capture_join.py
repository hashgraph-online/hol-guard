"""Validate and join bounded, keyed Codex capture rows."""

# The recording module owns the shared bounded parsers; this companion module
# intentionally reuses those private helpers without exposing them publicly.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import re
import time
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import cast

from .codex_binding_capture import (
    BINDABLE_CODEX_HOOK_EVENTS,
    _bounded_text,
    _canonical_json,
    _json_object,
    _tool_use_id,
)
from .codex_binding_capture_crypto import (
    CAPTURE_SCHEMA,
    FINGERPRINT_SCHEME,
    LEGACY_CAPTURE_SCHEMA,
    MAX_CAPTURE_BYTES,
    MAX_CAPTURE_RECORDS,
    CaptureSession,
    open_receipt,
    verify_row_hmac,
)
from .codex_binding_capture_crypto import receipt_projection as _receipt_projection
from .codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS
from .daemon.hook_request_parsing import runtime_hook_event_name

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


def _valid_hex(value: object, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _validated_record(
    value: Mapping[str, object],
    *,
    run_id: str | None = None,
    capture_session: CaptureSession | None = None,
) -> tuple[tuple[str, str, str, str] | None, str] | None:
    """Return an exact identity or a bounded reason for a structurally valid row."""

    if value.get("schema") != CAPTURE_SCHEMA:
        return None
    row_run_id = value.get("run_id")
    harness = value.get("harness")
    event_name = value.get("event_name")
    route = value.get("route")
    state = value.get("tool_use_id_state")
    if (
        not isinstance(row_run_id, str)
        or _RUN_ID.fullmatch(row_run_id) is None
        or (run_id is not None and row_run_id != run_id)
        or not isinstance(harness, str)
        or _bounded_text(harness, maximum=64) is None
        or harness != "codex"
        or not isinstance(event_name, str)
        or _bounded_text(event_name, maximum=64) is None
        or runtime_hook_event_name({"hook_event_name": event_name}) not in MANAGED_CODEX_HOOK_EVENTS
        or not isinstance(route, str)
        or route not in {"bridge_ingress", "native_worker"}
        or not isinstance(state, str)
        or state not in {"missing", "unsupported", "present"}
        or value.get("fingerprint_scheme") != FINGERPRINT_SCHEME
        or not _valid_hex(value.get("key_id"), _KEY_ID)
        or not _valid_hex(value.get("row_mac"), _HEX64)
    ):
        return None

    canonical_event = runtime_hook_event_name({"hook_event_name": event_name})
    expected = {
        "schema",
        "fingerprint_scheme",
        "key_id",
        "run_id",
        "route",
        "harness",
        "event_name",
        "tool_use_id_state",
        "row_mac",
    }
    if state == "present":
        expected.add("tool_use_id")
    if route == "bridge_ingress":
        expected.update({"raw_payload_hmac_sha256", "forwarded_payload_hmac_sha256"})
    else:
        expected.update({"forwarded_payload_hmac_sha256", "decision_scope", "sealed_receipt"})
    if set(value) != expected:
        return None
    if not _valid_hex(value.get("forwarded_payload_hmac_sha256"), _HEX64):
        return None
    if route == "bridge_ingress" and not _valid_hex(value.get("raw_payload_hmac_sha256"), _HEX64):
        return None
    if route == "native_worker" and value.get("decision_scope") != "native_edge":
        return None

    if capture_session is None:
        return (None, "missing_capture_key")
    if capture_session.run_id != row_run_id or capture_session.key_id != value.get("key_id"):
        return (None, "capture_key_mismatch")
    if capture_session.expires_at <= int(time.time()):
        return (None, "capture_key_expired")
    if not verify_row_hmac(capture_session, value):
        return (None, "row_mac_mismatch")

    if route == "native_worker":
        sealed = value.get("sealed_receipt")
        typed_sealed = cast(Mapping[str, object], sealed) if isinstance(sealed, Mapping) else None
        typed_receipt = open_receipt(capture_session, value, typed_sealed) if typed_sealed is not None else None
        if (
            typed_receipt is None
            or _receipt_projection(typed_receipt) != dict(typed_receipt)
            or typed_receipt.get("harness") != harness
            or typed_receipt.get("event_name") != canonical_event
        ):
            return None

    if state in {"missing", "unsupported"}:
        return (None, state) if "tool_use_id" not in value else None
    identifier = value.get("tool_use_id")
    validated_identifier = _tool_use_id({"tool_use_id": identifier})
    if not isinstance(validated_identifier, str) or validated_identifier != identifier:
        return None
    return (row_run_id, harness, canonical_event, cast(str, identifier)), route


def valid_existing_records(
    raw: bytes,
    *,
    run_id: str,
    capture_session: CaptureSession | None = None,
) -> int | None:
    """Validate an existing output before appending another keyed row."""

    if not raw:
        return 0
    if (
        capture_session is None
        or len(raw) > MAX_CAPTURE_BYTES
        or len(raw) > capture_session.max_bytes
        or not raw.endswith(b"\n")
    ):
        return None
    lines = raw.splitlines()
    record_limit = min(MAX_CAPTURE_RECORDS, capture_session.max_records)
    if not lines or len(lines) > record_limit:
        return None
    for line in lines:
        row = _json_object(line)
        if row is None:
            return None
        validated = _validated_record(row, run_id=run_id, capture_session=capture_session)
        if validated is None or (validated[0] is None and validated[1] not in {"missing", "unsupported"}):
            return None
    return len(lines)


def join_binding_records(
    records: Iterable[object],
    *,
    capture_session: CaptureSession | None = None,
) -> dict[str, object]:
    """Join ingress/native rows using exact identity and keyed continuity."""

    groups: dict[tuple[str, str, str, str], dict[str, list[Mapping[str, object]]]] = defaultdict(
        lambda: {"bridge_ingress": [], "native_worker": []}
    )
    issues: list[dict[str, object]] = []
    aggregate_bytes = 0
    aggregate_limit = (
        min(MAX_CAPTURE_BYTES, capture_session.max_bytes) if capture_session is not None else MAX_CAPTURE_BYTES
    )
    aggregate_exceeded = False
    record_limit = (
        min(MAX_CAPTURE_RECORDS, capture_session.max_records) if capture_session is not None else MAX_CAPTURE_RECORDS
    )
    record_limit_exceeded = False
    count = 0
    for record in records:
        count += 1
        if count > record_limit:
            issues.append({"status": "ambiguous", "reason": "record_limit_exceeded"})
            record_limit_exceeded = True
            break
        if not isinstance(record, Mapping):
            issues.append({"status": "invalid", "reason": "record_not_object"})
            continue
        record = cast(Mapping[str, object], record)
        encoded = _canonical_json(dict(record))
        encoded_size = len(encoded) + 1 if encoded is not None else None
        if encoded_size is None or encoded_size > aggregate_limit or aggregate_bytes + encoded_size > aggregate_limit:
            issues.clear()
            issues.append({"status": "invalid", "reason": "record_size"})
            aggregate_exceeded = True
            break
        aggregate_bytes += encoded_size
        normalized = _validated_record(record, capture_session=capture_session)
        if normalized is None:
            reason = "legacy_capture_schema" if record.get("schema") == LEGACY_CAPTURE_SCHEMA else "record_shape"
            issues.append({"status": "invalid", "reason": reason})
            continue
        key, route = normalized
        if key is None:
            canonical_event = runtime_hook_event_name({"hook_event_name": record.get("event_name")})
            if canonical_event not in BINDABLE_CODEX_HOOK_EVENTS:
                issues.append({"status": "not_applicable", "reason": "native_receipt_unsupported_event"})
            else:
                reason = {
                    "missing": "missing_tool_use_id",
                    "unsupported": "unsupported_tool_use_id",
                }.get(route, route)
                issues.append({"status": "unbound", "reason": reason})
            continue
        groups[key][route].append(record)

    if aggregate_exceeded or record_limit_exceeded:
        groups.clear()
    joins: list[dict[str, object]] = []
    for key, grouped in groups.items():
        if key[2] not in BINDABLE_CODEX_HOOK_EVENTS:
            joins.append({"status": "not_applicable", "reason": "native_receipt_unsupported_event", "identity": key})
            continue
        bridge_rows = grouped["bridge_ingress"]
        native_rows = grouped["native_worker"]
        if len(bridge_rows) > 1 or len(native_rows) > 1:
            joins.append({"status": "ambiguous", "reason": "duplicate_join_rows", "identity": key})
        elif not bridge_rows or not native_rows:
            joins.append({"status": "unbound", "reason": "missing_join_side", "identity": key})
        elif bridge_rows[0].get("forwarded_payload_hmac_sha256") != native_rows[0].get("forwarded_payload_hmac_sha256"):
            joins.append({"status": "invalid", "reason": "payload_fingerprint_mismatch", "identity": key})
        else:
            joins.append({"status": "bound", "scope": "native_edge_binding", "identity": key})

    statuses = [str(item["status"]) for item in joins if item["status"] != "not_applicable"] + [
        str(item["status"]) for item in issues if item["status"] != "not_applicable"
    ]
    if "invalid" in statuses:
        status = "invalid"
    elif "ambiguous" in statuses:
        status = "ambiguous"
    elif not statuses:
        status = "not_applicable" if joins or issues else "unbound"
    elif "unbound" in statuses:
        status = "unbound"
    else:
        status = "bound"
    return {
        "schema": CAPTURE_SCHEMA,
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "scope": "native_edge_binding",
        "status": status,
        "joins": joins,
        "issues": issues,
    }


__all__ = ["join_binding_records", "valid_existing_records"]
