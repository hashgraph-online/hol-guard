"""Validation and cursor helpers for local command-activity routes."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false, reportUnusedCallResult=false

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from datetime import date, datetime, timezone
from typing import Final, Protocol, TypeGuard, cast
from urllib.parse import parse_qsl

from ..runtime.command_activity_api_contract import (
    COMMAND_ACTIVITY_API_SCHEMA_VERSION,
    COMMAND_ACTIVITY_PAGE_DEFAULT,
    CommandActivityAnalyticsQuery,
    CommandActivityFeedbackLabel,
    CommandActivityListQuery,
)
from ..runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    COMMAND_EXTENSION_SCHEMA_VERSION,
    CommandSafetyExtension,
)
from ..store import GuardStore
from ..store_command_activity_api import CommandActivityNotFoundError

_CURSOR_PREFIX: Final = "gca1"
_LIST_QUERY_KEYS: Final = frozenset(
    {
        "limit",
        "cursor",
        "harness",
        "execution_status",
        "proof_level",
        "prompted",
        "approval_reuse_status",
        "extension_id",
        "rule_id",
        "occurred_from",
        "occurred_through",
    }
)
_ANALYTICS_QUERY_KEYS: Final = frozenset({"days", "top_limit", "dimension", "dimension_value"})
_EXTENSION_QUERY_KEYS: Final = frozenset({"limit", "cursor"})
_EVENT_QUERY_KEYS: Final = frozenset({"cursor"})
_COMMAND_ACTIVITY_STREAM_MAX_CLIENTS: Final = 8
_COMMAND_ACTIVITY_STREAM_MAX_SECONDS: Final = 300.0


def parse_command_activity_list_query(query_string: str) -> tuple[CommandActivityListQuery, str | None]:
    query = _single_query_values(query_string, allowed=_LIST_QUERY_KEYS)
    prompted = None
    if "prompted" in query:
        if query["prompted"] not in {"true", "false"}:
            raise ValueError("invalid_prompted")
        prompted = query["prompted"] == "true"
    return (
        CommandActivityListQuery(
            limit=_bounded_int(query.get("limit"), default=COMMAND_ACTIVITY_PAGE_DEFAULT),
            harness=query.get("harness"),
            execution_status=query.get("execution_status"),
            proof_level=query.get("proof_level"),
            prompted=prompted,
            approval_reuse_status=query.get("approval_reuse_status"),
            extension_id=query.get("extension_id"),
            rule_id=query.get("rule_id"),
            occurred_from=_optional_date(query.get("occurred_from"), "invalid_occurred_from"),
            occurred_through=_optional_date(query.get("occurred_through"), "invalid_occurred_through"),
        ),
        query.get("cursor"),
    )


def parse_command_activity_analytics_query(query_string: str) -> CommandActivityAnalyticsQuery:
    query = _single_query_values(query_string, allowed=_ANALYTICS_QUERY_KEYS)
    return CommandActivityAnalyticsQuery(
        days=_bounded_int(query.get("days"), default=90),
        top_limit=_bounded_int(query.get("top_limit"), default=10),
        dimension=query.get("dimension"),
        dimension_value=query.get("dimension_value"),
    )


def parse_command_activity_event_cursor(query_string: str, *, last_event_id: str | None) -> int:
    query = _single_query_values(query_string, allowed=_EVENT_QUERY_KEYS)
    candidate = (
        last_event_id.strip() if isinstance(last_event_id, str) and last_event_id.strip() else query.get("cursor", "0")
    )
    if not candidate.isascii() or not candidate.isdigit():
        raise ValueError("invalid_cursor")
    cursor = int(candidate)
    if cursor > 9_223_372_036_854_775_807:
        raise ValueError("invalid_cursor")
    return cursor


def encode_activity_cursor(
    marker: tuple[str, str],
    *,
    query: CommandActivityListQuery,
    auth_token: str,
) -> str:
    payload: dict[str, object] = {
        "binding": list(query.binding()),
        "occurred_at": marker[0],
        "activity_id": marker[1],
        "version": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
    }
    return _signed_cursor(payload, auth_token=auth_token)


def decode_activity_cursor(
    cursor: str,
    *,
    query: CommandActivityListQuery,
    auth_token: str,
) -> tuple[str, str]:
    payload = _verified_cursor(cursor, auth_token=auth_token)
    if (
        payload.get("version") != COMMAND_ACTIVITY_API_SCHEMA_VERSION
        or payload.get("binding") != list(query.binding())
        or not isinstance(payload.get("occurred_at"), str)
        or not isinstance(payload.get("activity_id"), str)
    ):
        raise ValueError("invalid_cursor")
    return str(payload["occurred_at"]), str(payload["activity_id"])


def command_extensions_page(query_string: str, *, auth_token: str) -> dict[str, object]:
    query = _single_query_values(query_string, allowed=_EXTENSION_QUERY_KEYS)
    limit = _bounded_int(query.get("limit"), default=50)
    if not 1 <= limit <= 100:
        raise ValueError("limit_out_of_range")
    after = None
    cursor = query.get("cursor")
    if cursor is not None:
        payload = _verified_cursor(cursor, auth_token=auth_token)
        if payload.get("kind") != "extensions" or not isinstance(payload.get("after"), str):
            raise ValueError("invalid_cursor")
        after = str(payload["after"])
    extensions = tuple(
        sorted(
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions,
            key=lambda extension: extension.extension_id,
        )
    )
    if after is not None:
        extensions = tuple(extension for extension in extensions if extension.extension_id > after)
    page = extensions[:limit]
    next_cursor = None
    if len(extensions) > limit and page:
        next_cursor = _signed_cursor(
            {"kind": "extensions", "after": page[-1].extension_id},
            auth_token=auth_token,
        )
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "source": "built-in",
        "items": [_extension_payload(extension) for extension in page],
        "next_cursor": next_cursor,
    }


def parse_feedback_payload(payload: dict[str, object]) -> tuple[str, CommandActivityFeedbackLabel]:
    if set(payload) != {"activity_id", "label"}:
        raise ValueError("invalid_feedback_payload")
    activity_id = payload.get("activity_id")
    label = payload.get("label")
    if not isinstance(activity_id, str) or not activity_id or len(activity_id) > 256:
        raise ValueError("invalid_activity_id")
    if not isinstance(label, str):
        raise ValueError("invalid_feedback_label")
    try:
        feedback_label = CommandActivityFeedbackLabel(label)
    except ValueError as error:
        raise ValueError("invalid_feedback_label") from error
    return activity_id, feedback_label


class _Writable(Protocol):
    def write(self, value: bytes) -> object: ...

    def flush(self) -> object: ...


class _ApiServer(Protocol):
    auth_token: str
    store: GuardStore


class _Handler(Protocol):
    server: _ApiServer
    wfile: _Writable

    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None: ...

    def _cors_headers_for_request(self, *, allow_methods: str = "GET, POST, OPTIONS") -> dict[str, str] | None: ...

    def _validated_headers(self, extra_headers: dict[str, str] | None) -> dict[str, str]: ...

    def _touch_runtime_heartbeat(self, path: str) -> None: ...

    def _increment_active_stream_clients(self) -> None: ...

    def _try_increment_active_stream_clients(self, maximum: int) -> bool: ...

    def _decrement_active_stream_clients(self) -> None: ...

    def send_response(self, code: int, message: str | None = None) -> None: ...

    def send_header(self, keyword: str, value: str) -> None: ...

    def end_headers(self) -> None: ...


def handle_command_activity_list(handler: object, query_string: str) -> None:
    target = cast(_Handler, handler)
    try:
        query, encoded_cursor = parse_command_activity_list_query(query_string)
        cursor = (
            decode_activity_cursor(encoded_cursor, query=query, auth_token=target.server.auth_token)
            if encoded_cursor is not None
            else None
        )
        page = target.server.store.list_command_activity_page(query, cursor=cursor)
        marker = page.pop("next_marker", None)
        if isinstance(marker, tuple) and len(marker) == 2 and all(isinstance(item, str) for item in marker):
            typed_marker = (cast(str, marker[0]), cast(str, marker[1]))
            page["next_cursor"] = encode_activity_cursor(
                typed_marker,
                query=query,
                auth_token=target.server.auth_token,
            )
        else:
            page["next_cursor"] = None
    except ValueError as error:
        target._write_json({"error": str(error)}, status=400)
        return
    target._write_json(page)


def handle_command_activity_analytics(handler: object, query_string: str) -> None:
    target = cast(_Handler, handler)
    try:
        query = parse_command_activity_analytics_query(query_string)
        payload = target.server.store.command_activity_analytics(query, as_of=datetime.now(timezone.utc).date())
    except ValueError as error:
        target._write_json({"error": str(error)}, status=400)
        return
    target._write_json(payload)


def handle_command_extensions(handler: object, query_string: str) -> None:
    target = cast(_Handler, handler)
    try:
        payload = command_extensions_page(query_string, auth_token=target.server.auth_token)
    except ValueError as error:
        target._write_json({"error": str(error)}, status=400)
        return
    target._write_json(payload)


def handle_command_activity_feedback(handler: object, payload: dict[str, object]) -> None:
    target = cast(_Handler, handler)
    try:
        activity_id, label = parse_feedback_payload(payload)
        response = target.server.store.record_command_activity_feedback(
            activity_id=activity_id,
            label=label,
            recorded_at=datetime.now(timezone.utc),
        )
    except CommandActivityNotFoundError:
        target._write_json({"error": "activity_not_found"}, status=404)
        return
    except ValueError as error:
        target._write_json({"error": str(error)}, status=400)
        return
    target._write_json(response)


def stream_command_activity_events(handler: object, cursor: int) -> None:
    target = cast(_Handler, handler)
    if not target._try_increment_active_stream_clients(_COMMAND_ACTIVITY_STREAM_MAX_CLIENTS):
        target._write_json({"error": "too_many_streams"}, status=429)
        return
    try:
        target.send_response(200)
        target.send_header("Content-Type", "text/event-stream")
        target.send_header("Cache-Control", "no-cache")
        target.send_header("Connection", "keep-alive")
        cors_headers = target._cors_headers_for_request(allow_methods="GET, OPTIONS")
        for key, value in target._validated_headers(cors_headers).items():
            target.send_header(key, value)
        target.end_headers()
        next_cursor = max(0, cursor)
        deadline = time.monotonic() + _COMMAND_ACTIVITY_STREAM_MAX_SECONDS
        while time.monotonic() < deadline:
            target._touch_runtime_heartbeat("/v1/command-activity/events")
            page = target.server.store.list_command_activity_invalidations(next_cursor, limit=100)
            reset_required = page.get("reset_required")
            reset_cursor = page.get("reset_cursor")
            if reset_required is True and isinstance(reset_cursor, int):
                next_cursor = reset_cursor
                reset_body = json.dumps(
                    {"event": "command_activity_reset", "reset_required": True},
                    separators=(",", ":"),
                )
                try:
                    target.wfile.write(
                        f"id: {reset_cursor}\nevent: command_activity_reset\ndata: {reset_body}\n\n".encode()
                    )
                    target.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
            items = page.get("items")
            if not isinstance(items, list):
                items = []
            for item in items:
                if not _is_string_object_dict(item):
                    continue
                sequence = item.get("sequence")
                activity_id = item.get("activity_id")
                if not isinstance(sequence, int) or not isinstance(activity_id, str):
                    continue
                next_cursor = sequence
                body = json.dumps(
                    {"event": "command_activity_invalidated", "activity_id": activity_id},
                    separators=(",", ":"),
                )
                try:
                    target.wfile.write(f"id: {sequence}\ndata: {body}\n\n".encode())
                    target.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
            time.sleep(0.5)
    finally:
        target._decrement_active_stream_clients()


def _extension_payload(extension: CommandSafetyExtension) -> dict[str, object]:
    return {
        "extension_id": extension.extension_id,
        "version": extension.version,
        "name": extension.name,
        "description": extension.description,
        "enabled": True,
        "required": extension.required,
        "source": extension.source,
        "dependencies": list(extension.dependencies),
        "conflicts": list(extension.conflicts),
        "delegated_protection": extension.delegated_protection,
        "action_classes": list(extension.action_classes),
        "risk_classes": list(extension.risk_classes),
        "rule_count": len(extension.rules),
        "rules": [
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "risk_classes": list(rule.risk_classes),
                "action_classes": list(rule.action_classes),
                "default_mode": rule.default_mode,
                "safe_variant_ids": [variant.variant_id for variant in rule.safe_variants],
                "compatibility_fallback": rule.compatibility_fallback,
            }
            for rule in extension.rules
        ],
    }


def _single_query_values(query_string: str, *, allowed: frozenset[str]) -> dict[str, str]:
    if len(query_string) > 8_192:
        raise ValueError("query_too_long")
    values: dict[str, str] = {}
    for key, value in parse_qsl(query_string, keep_blank_values=True, strict_parsing=False):
        if key not in allowed:
            raise ValueError("unknown_query_parameter")
        if key in values or not value:
            raise ValueError("invalid_query_parameter")
        values[key] = value
    return values


def _bounded_int(value: str | None, *, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise ValueError("invalid_integer") from error


def _optional_date(value: str | None, error_code: str) -> date | None:
    if value is None:
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(error_code) from error
    if parsed.isoformat() != value:
        raise ValueError(error_code)
    return parsed


def _signed_cursor(payload: Mapping[str, object], *, auth_token: str) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    signature = hmac.new(auth_token.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{_CURSOR_PREFIX}.{encoded}.{encoded_signature}"


def _verified_cursor(cursor: str, *, auth_token: str) -> dict[str, object]:
    if len(cursor) > 2_048:
        raise ValueError("invalid_cursor")
    try:
        prefix, encoded, signature = cursor.split(".")
        if prefix != _CURSOR_PREFIX or not encoded or not signature:
            raise ValueError
        expected = hmac.new(auth_token.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(supplied, expected):
            raise ValueError
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        decoded: object = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid_cursor") from error
    if not _is_string_object_dict(decoded):
        raise ValueError("invalid_cursor")
    return decoded


def _is_string_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


__all__ = (
    "command_extensions_page",
    "decode_activity_cursor",
    "encode_activity_cursor",
    "handle_command_activity_analytics",
    "handle_command_activity_feedback",
    "handle_command_activity_list",
    "handle_command_extensions",
    "parse_command_activity_analytics_query",
    "parse_command_activity_event_cursor",
    "parse_command_activity_list_query",
    "parse_feedback_payload",
    "stream_command_activity_events",
)
