"""Typed client for the native install-time protect op; no Python parser.

Rust owns parsing the wrapped install or registration command and matching
the store's cached advisories against its targets. Python ships the command
and the store path, binds the answer to the request by ``request_id`` and
canonical ``request_sha256``, and decodes the parsed request and verdict.
Every outcome other than a well-formed, request-bound reply raises
``NativeProtectRequestError``; callers must fail closed and never substitute
a Python evaluation. A command whose URL cannot be parsed raises
``ValueError`` with the parser's message, as the install path always has.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite

_OPERATION = "protect_request"
_FEATURE = "protect-request-v1"
_REQUEST_SCHEMA = "guard-protect-request-request.v1"
_RESULT_SCHEMA = "guard-protect-request-result.v1"
_MAX_REQUEST_BYTES = 256 * 1024 + 4096
_TIMEOUT_SECONDS = 5.0
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "detail", "request", "verdict"})
_REQUEST_KEYS = ("command", "install_kind", "executor", "package_manager", "harness", "targets")
_TARGET_KEYS = (
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "ecosystem",
    "package_name",
    "package_url",
    "raw_spec",
    "version",
    "source_url",
    "harness",
)
_REQUIRED_TARGET_KEYS = frozenset(_TARGET_KEYS[:4])
_ADVISORY_KEYS = frozenset({"cache_key", "updated_at", "payload_json"})
_ACTIONS = frozenset({"allow", "review", "block"})
_INVALID = "native_protect_request_invalid_result"
_MERGE_OPERATION = "protect_advisory_merge"
_MERGE_FEATURE = "protect-advisory-merge-v1"
_MERGE_REQUEST_SCHEMA = "guard-protect-advisory-merge-request.v1"
_MERGE_RESULT_SCHEMA = "guard-protect-advisory-merge-result.v1"
_MERGE_MAX_REQUEST_BYTES = 2 * 1024 * 1024 + 4096
_MERGE_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "merged"})
_MERGE_INVALID = "native_protect_advisory_merge_invalid_result"


class NativeProtectRequestError(RuntimeError):
    """The native owner could not supply a complete, request-bound protect answer."""


def native_protect_request(
    command: Sequence[str],
    *,
    guard_home: Path | None,
    store_path: Path | None,
    cwd: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the parsed ``(request, verdict)`` dicts for one wrapped command.

    ``verdict["matched_advisories"]`` holds the matched cache rows rebuilt as
    ``{"cache_key", "updated_at", **payload}``, the shape the store lists.
    """

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id(_OPERATION),
        "guard_home": "",
        "store_path": str(store_path) if store_path is not None else None,
        "command": [str(item) for item in command],
    }
    if cwd is not None:
        # A custom command that launches a relative script is read from here;
        # the resident reads a script only against an absolute directory.
        # `parse_protect_command` and a verdict asked for without a working
        # directory have none, so the field is left out rather than sent as
        # null: their request, and the digest the reply is bound to, stay the
        # bytes a caller that never knew about `cwd` would send.
        request["cwd"] = str(Path(cwd).absolute())
    decoded = _bound_reply(
        request,
        guard_home=guard_home,
        operation=_OPERATION,
        feature=_FEATURE,
        result_schema=_RESULT_SCHEMA,
        result_keys=_RESULT_KEYS,
        max_request_bytes=_MAX_REQUEST_BYTES,
        prefix="native_protect_request",
    )
    code = decoded.get("code")
    if decoded.get("status") == "error":
        detail = decoded.get("detail")
        if code == "native_protect_request_invalid_url" and isinstance(detail, str):
            raise ValueError(detail)
        raise NativeProtectRequestError(code if isinstance(code, str) else _INVALID)
    if decoded.get("status") != "ok" or code != "ok":
        raise NativeProtectRequestError(_INVALID)
    return _parsed_request(decoded.get("request")), _verdict(decoded.get("verdict"))


def _optional_str(value: object) -> bool:
    return value is None or isinstance(value, str)


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _parsed_request(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(_REQUEST_KEYS):
        raise NativeProtectRequestError(_INVALID)
    targets = value["targets"]
    if (
        not _strings(value["command"])
        or not isinstance(value["install_kind"], str)
        or not isinstance(value["executor"], str)
        or not _optional_str(value["package_manager"])
        or not _optional_str(value["harness"])
        or not isinstance(targets, list)
        or not targets
    ):
        raise NativeProtectRequestError(_INVALID)
    parsed = {key: value[key] for key in _REQUEST_KEYS}
    parsed["targets"] = [_target(target) for target in targets]
    return parsed


def _target(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != set(_TARGET_KEYS)
        or not all(isinstance(value[key], str) for key in _REQUIRED_TARGET_KEYS)
        or not all(_optional_str(value[key]) for key in _TARGET_KEYS)
    ):
        raise NativeProtectRequestError(_INVALID)
    return {key: value[key] for key in _TARGET_KEYS}


def _verdict(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"action", "reason", "risk_signals", "matched_advisories"}:
        raise NativeProtectRequestError(_INVALID)
    rows = value["matched_advisories"]
    if (
        value["action"] not in _ACTIONS
        or not isinstance(value["reason"], str)
        or not _strings(value["risk_signals"])
        or not isinstance(rows, list)
    ):
        raise NativeProtectRequestError(_INVALID)
    return {
        "action": value["action"],
        "reason": value["reason"],
        "risk_signals": tuple(value["risk_signals"]),
        "matched_advisories": tuple(_advisory(row) for row in rows),
    }


def _advisory(value: object) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value) != _ADVISORY_KEYS
        or not all(isinstance(value[key], str) for key in _ADVISORY_KEYS)
    ):
        raise NativeProtectRequestError(_INVALID)
    try:
        payload = json.loads(value["payload_json"])
    except ValueError as error:
        raise NativeProtectRequestError(_INVALID) from error
    if not isinstance(payload, dict):
        raise NativeProtectRequestError(_INVALID)
    return {"cache_key": value["cache_key"], "updated_at": value["updated_at"], **payload}


def native_protect_advisory_merge(
    payload: dict[str, object],
    *,
    cached: dict[str, object],
    requested_dry_run: bool,
    exit_code: int,
    guard_home: Path | None,
) -> tuple[dict[str, Any], int, tuple[str, str] | None, tuple[str, dict[str, Any]] | None] | None:
    """Return the native cached-advisory merge, or ``None`` when nothing changes."""

    request: dict[str, object] = {
        "schema": _MERGE_REQUEST_SCHEMA,
        "request_id": native_execution._request_id(_MERGE_OPERATION),
        "payload": payload,
        "cached": cached,
        "requested_dry_run": requested_dry_run,
        "exit_code": exit_code,
    }
    decoded = _bound_reply(
        request,
        guard_home=guard_home,
        operation=_MERGE_OPERATION,
        feature=_MERGE_FEATURE,
        result_schema=_MERGE_RESULT_SCHEMA,
        result_keys=_MERGE_RESULT_KEYS,
        max_request_bytes=_MERGE_MAX_REQUEST_BYTES,
        prefix="native_protect_advisory_merge",
    )
    code = decoded.get("code")
    if decoded.get("status") == "error":
        raise NativeProtectRequestError(code if isinstance(code, str) else _MERGE_INVALID)
    if decoded.get("status") != "ok" or code != "ok":
        raise NativeProtectRequestError(_MERGE_INVALID)
    merged = decoded.get("merged")
    if merged is None:
        return None
    if not isinstance(merged, dict) or set(merged) != {"payload", "exit_code", "receipt_policy_update", "event"}:
        raise NativeProtectRequestError(_MERGE_INVALID)
    updated, merged_exit_code = merged["payload"], merged["exit_code"]
    if not isinstance(updated, dict) or type(merged_exit_code) is not int:
        raise NativeProtectRequestError(_MERGE_INVALID)
    return updated, merged_exit_code, _receipt_update(merged["receipt_policy_update"]), _event(merged["event"])


def _receipt_update(value: object) -> tuple[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"receipt_id", "action"}:
        raise NativeProtectRequestError(_MERGE_INVALID)
    if not all(isinstance(item, str) for item in value.values()):
        raise NativeProtectRequestError(_MERGE_INVALID)
    return value["receipt_id"], value["action"]


def _event(value: object) -> tuple[str, dict[str, Any]] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"name", "fields"} or not isinstance(value["name"], str):
        raise NativeProtectRequestError(_MERGE_INVALID)
    fields = value["fields"]
    if not isinstance(fields, list) or not all(
        isinstance(field, list) and len(field) == 2 and isinstance(field[0], str) for field in fields
    ):
        raise NativeProtectRequestError(_MERGE_INVALID)
    return value["name"], {field[0]: field[1] for field in fields}


def _bound_reply(
    request: dict[str, object],
    *,
    guard_home: Path | None,
    operation: str,
    feature: str,
    result_schema: str,
    result_keys: frozenset[str],
    max_request_bytes: int,
    prefix: str,
) -> dict[str, Any]:
    """Send ``request`` and return the reply bound to it by id and digest."""

    try:
        home = _resolve_digest_home(guard_home)
        if "guard_home" in request:
            request["guard_home"] = str(home)
        if not ensure_resident_prerequisite(home):
            raise NativeProtectRequestError(f"{prefix}_unavailable")
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        decoded = native_execution._resident_request(
            operation=operation,
            request=request,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=feature,
            response_schema=result_schema,
            max_request_bytes=max_request_bytes,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeProtectRequestError(f"{prefix}_unavailable") from error
    if decoded is None:
        raise NativeProtectRequestError(f"{prefix}_unavailable")
    if not set(decoded) <= result_keys:
        raise NativeProtectRequestError(f"{prefix}_invalid_result")
    if decoded.get("request_id") != request["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeProtectRequestError(f"{prefix}_request_mismatch")
    return decoded
