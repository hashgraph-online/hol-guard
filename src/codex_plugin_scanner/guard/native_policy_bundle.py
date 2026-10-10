"""Resident bridge for the ``policy_bundle_authority`` op.

Rust owns every verdict about signed Guard Cloud policy bundles: schema and
signature validation, canonical hashing, trust-root assembly, delivery and
acknowledgement correlation, and decision materialization. This module only
encodes a JSON-safe request, forwards it through the existing resident client,
verifies the request binding of the answer and returns the decoded result.
Any transport failure, malformed answer, or missing capability raises a typed
``PolicyBundleNativeError``; there is no Python fallback.
"""

from __future__ import annotations

import json
import math
import os
import time
from typing import cast

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)

MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_BYTES = 3 * 1024 * 1024
CHUNK_CHARS = 100_000
UNAVAILABLE = "native_policy_bundle_authority_unavailable"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_FEATURE = "policy-bundle-authority-v1"
_REQUEST_SCHEMA = "guard-policy-bundle-authority-request.v1"
_RESULT_SCHEMA = "guard-policy-bundle-authority-result.v1"
_DEFAULT_TIMEOUT_SECONDS = 8.0

_request_counter = 0


class PolicyBundleNativeError(ValueError):
    """A typed, fail-closed failure of the policy bundle authority bridge."""

    def __init__(self, code: str, result: dict[str, object] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.result = result or {}


def _reject_non_json(value: object) -> None:
    """Refuse values the JSON transport would silently reshape."""

    stack: list[object] = [value]
    while stack:
        current = stack.pop()
        if current is None or isinstance(current, (bool, int, str)):
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise PolicyBundleNativeError("non_finite_number")
            continue
        if isinstance(current, list):
            stack.extend(current)
            continue
        if isinstance(current, dict):
            if not all(isinstance(key, str) for key in current):
                raise PolicyBundleNativeError("invalid_json_value")
            stack.extend(current.values())
            continue
        raise PolicyBundleNativeError("invalid_json_value")


def _encode(value: object) -> str:
    _reject_non_json(value)
    try:
        text = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        text.encode("utf-8")
    except RecursionError as error:
        raise PolicyBundleNativeError("limit_depth") from error
    except (TypeError, ValueError) as error:
        raise PolicyBundleNativeError("invalid_json_value") from error
    return text


def policy_bundle_chunks(document: object) -> list[str]:
    """Encode one JSON document as bounded text chunks for the resident."""

    text = _encode(document)
    if len(text) > MAX_DOCUMENT_BYTES:
        raise PolicyBundleNativeError("limit_bytes")
    chunks = [text[start : start + CHUNK_CHARS] for start in range(0, len(text), CHUNK_CHARS)]
    return chunks or [""]


def _next_request_id() -> str:
    global _request_counter
    _request_counter += 1
    return f"pba-{os.getpid()}-{_request_counter}"


def native_policy_bundle(
    kind: str,
    request_input: dict[str, object],
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Ask the resident for one policy-bundle verdict document."""

    effective_deadline = time.monotonic() + timeout_seconds
    status = native_runtime_status(deadline_monotonic=effective_deadline)
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or _FEATURE not in status.capabilities.features
    ):
        raise PolicyBundleNativeError(UNAVAILABLE)
    guard_home = _resolve_digest_home(None)
    if native_runtime_health_snapshot(status.identity.sha256, guard_home).circuit_open:
        raise PolicyBundleNativeError(UNAVAILABLE)
    if not ensure_resident_prerequisite(guard_home):
        raise PolicyBundleNativeError(UNAVAILABLE)
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _next_request_id(),
        "kind": kind,
        "input": request_input,
    }
    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        raise PolicyBundleNativeError(UNAVAILABLE)
    try:
        _reject_non_json(request_input)
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        resident = json.dumps(
            {
                "operation": "policy_bundle_authority",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except PolicyBundleNativeError:
        raise
    except (TypeError, ValueError, RecursionError) as error:
        raise PolicyBundleNativeError("native_policy_bundle_authority_invalid") from error
    if len(resident) > MAX_REQUEST_BYTES:
        raise PolicyBundleNativeError("limit_bytes")
    if time.monotonic() >= effective_deadline:
        raise PolicyBundleNativeError(UNAVAILABLE)
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=effective_deadline,
    )
    if output is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=UNAVAILABLE)
        raise PolicyBundleNativeError(UNAVAILABLE)
    try:
        decoded: object = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_policy_bundle_authority_decode_failed"
        )
        raise PolicyBundleNativeError("native_policy_bundle_authority_decode_failed") from error
    if _native_error(decoded) == "native_overloaded":
        native_record_overload(status.identity.sha256, guard_home)
        raise PolicyBundleNativeError("native_overloaded")
    envelope = cast("dict[str, object]", decoded) if isinstance(decoded, dict) else None
    if (
        envelope is None
        or envelope.get("schema") != _RESULT_SCHEMA
        or envelope.get("request_id") != request["request_id"]
        or envelope.get("request_sha256") != request_sha256
    ):
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_policy_bundle_authority_schema_mismatch"
        )
        raise PolicyBundleNativeError("native_policy_bundle_authority_schema_mismatch")
    native_record_resident_success(status.identity.sha256, guard_home)
    result = envelope.get("result")
    if envelope.get("status") != "ok" or envelope.get("code") != "ok" or not isinstance(result, dict):
        code = envelope.get("code")
        raise PolicyBundleNativeError(code if isinstance(code, str) else "native_policy_bundle_authority_invalid")
    return cast("dict[str, object]", result)


def policy_bundle_verdict(kind: str, request_input: dict[str, object]) -> dict[str, object]:
    """Return the verdict document, raising its code when Rust rejected it."""

    result = native_policy_bundle(kind, request_input)
    error = result.get("error")
    if isinstance(error, str):
        raise PolicyBundleNativeError(error, result)
    return result
