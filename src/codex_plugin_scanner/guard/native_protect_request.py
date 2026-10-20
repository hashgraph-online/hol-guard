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
    try:
        home = _resolve_digest_home(guard_home)
        request["guard_home"] = str(home)
        if not ensure_resident_prerequisite(home):
            raise NativeProtectRequestError("native_protect_request_unavailable")
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        decoded = native_execution._resident_request(
            operation=_OPERATION,
            request=request,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeProtectRequestError("native_protect_request_unavailable") from error
    if decoded is None:
        raise NativeProtectRequestError("native_protect_request_unavailable")
    if not set(decoded) <= _RESULT_KEYS:
        raise NativeProtectRequestError(_INVALID)
    if decoded.get("request_id") != request["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeProtectRequestError("native_protect_request_request_mismatch")
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
