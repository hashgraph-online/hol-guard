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

import hashlib
import itertools
import json
import math
import os
import time
from collections.abc import Iterator
from typing import Any, cast

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
# Stable rejection code callers report when the resident could not answer. It is
# distinct from every policy verdict so an outage is never read as a bad bundle.
NATIVE_UNAVAILABLE_REJECTION = "native_policy_bundle_unavailable"
MAX_INPUT_DEPTH = 256
MAX_INPUT_NODES = 4_000_000
MAX_PAGES = 4_096
_INVALID_REQUEST = "native_policy_bundle_authority_invalid"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_FEATURE = "policy-bundle-authority-v1"
_REQUEST_SCHEMA = "guard-policy-bundle-authority-request.v1"
_RESULT_SCHEMA = "guard-policy-bundle-authority-result.v1"
_DEFAULT_TIMEOUT_SECONDS = 8.0

# ``next()`` on ``itertools.count`` is a single atomic C call, so concurrent
# daemon threads never observe the same request id.
_request_counter = itertools.count(1)


class PolicyBundleNativeError(ValueError):
    """A typed, fail-closed failure of the policy bundle authority bridge."""

    def __init__(self, code: str, result: dict[str, object] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.result = result or {}


class PolicyBundleNativeUnavailableError(PolicyBundleNativeError):
    """The resident could not give a verdict (timeout, overload, open circuit, bad answer).

    This is an outage, not a policy verdict: callers must fail closed and report
    ``NATIVE_UNAVAILABLE_REJECTION`` instead of inventing a rejection reason.
    """


_LEAVE = object()


def _reject_non_json(value: object) -> None:
    """Refuse values the JSON transport would silently reshape.

    Cycles are detected by the identity of the containers on the current path
    and nesting is bounded, so a self-referential input is rejected instead of
    looping. Repeated, acyclic sharing stays valid.
    """

    stack: list[tuple[object, int]] = [(value, 0)]
    active: set[int] = set()
    visited = 0
    while stack:
        current, depth = stack.pop()
        if current is _LEAVE:
            active.discard(depth)
            continue
        visited += 1
        if visited > MAX_INPUT_NODES:
            raise PolicyBundleNativeError("limit_bytes")
        if current is None or isinstance(current, (bool, int, str)):
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise PolicyBundleNativeError("non_finite_number")
            continue
        if not isinstance(current, (list, dict)):
            raise PolicyBundleNativeError("invalid_json_value")
        identity = id(current)
        if identity in active:
            raise PolicyBundleNativeError("invalid_json_value")
        if depth > MAX_INPUT_DEPTH:
            raise PolicyBundleNativeError("limit_depth")
        if isinstance(current, dict) and not all(isinstance(key, str) for key in current):
            raise PolicyBundleNativeError("invalid_json_value")
        active.add(identity)
        stack.append((_LEAVE, identity))
        children = current if isinstance(current, list) else current.values()
        stack.extend((child, depth + 1) for child in children)


def native_rejection_code(error: PolicyBundleNativeError) -> str:
    """The stable rejection code for a native failure: an outage never reads as a verdict."""

    return NATIVE_UNAVAILABLE_REJECTION if isinstance(error, PolicyBundleNativeUnavailableError) else error.code


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
    return f"pba-{os.getpid()}-{next(_request_counter)}"


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
        raise PolicyBundleNativeUnavailableError(UNAVAILABLE)
    guard_home = _resolve_digest_home(None)
    if native_runtime_health_snapshot(status.identity.sha256, guard_home).circuit_open:
        raise PolicyBundleNativeUnavailableError(UNAVAILABLE)
    if not ensure_resident_prerequisite(guard_home):
        raise PolicyBundleNativeUnavailableError(UNAVAILABLE)
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _next_request_id(),
        "kind": kind,
        "input": request_input,
    }
    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        raise PolicyBundleNativeUnavailableError(UNAVAILABLE)
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
        raise PolicyBundleNativeUnavailableError(UNAVAILABLE)
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=effective_deadline,
    )
    if output is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=UNAVAILABLE)
        raise PolicyBundleNativeUnavailableError(UNAVAILABLE)
    try:
        decoded: object = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_policy_bundle_authority_decode_failed"
        )
        raise PolicyBundleNativeUnavailableError("native_policy_bundle_authority_decode_failed") from error
    if _native_error(decoded) == "native_overloaded":
        native_record_overload(status.identity.sha256, guard_home)
        raise PolicyBundleNativeUnavailableError("native_overloaded")
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
        raise PolicyBundleNativeUnavailableError("native_policy_bundle_authority_schema_mismatch")
    native_record_resident_success(status.identity.sha256, guard_home)
    result = envelope.get("result")
    if envelope.get("status") != "ok" or envelope.get("code") != "ok" or not isinstance(result, dict):
        code = envelope.get("code")
        if code == _INVALID_REQUEST:
            raise PolicyBundleNativeError(_INVALID_REQUEST)
        # Any other non-ok answer (unknown kind, a codeless or foreign error) is
        # the resident failing to serve the op, not a verdict about the bundle.
        raise PolicyBundleNativeUnavailableError(code if isinstance(code, str) else UNAVAILABLE)
    return cast("dict[str, object]", result)


def policy_bundle_verdict(kind: str, request_input: dict[str, object]) -> dict[str, object]:
    """Return the verdict document, raising its code when Rust rejected it."""

    result = native_policy_bundle(kind, request_input)
    error = result.get("error")
    if isinstance(error, str):
        raise PolicyBundleNativeError(error, result)
    return result


_SCHEMA_MISMATCH = "native_policy_bundle_authority_schema_mismatch"


def _pages(kind: str, request_input: dict[str, object]) -> Iterator[dict[str, object]]:
    """Yield every page of a paged verdict, following the resident's ``next`` offsets."""

    offset = 0
    for _ in range(MAX_PAGES):
        page = policy_bundle_verdict(kind, {**request_input, "offset": offset})
        yield page
        following = page.get("next")
        if following is None:
            return
        if not isinstance(following, int) or isinstance(following, bool) or following <= offset:
            raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)
        offset = following
    raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)


def policy_bundle_paged_rows(kind: str, request_input: dict[str, object]) -> list[dict[str, Any]]:
    """Collect a verdict whose rows exceed one resident response, page by page.

    Rust returns bounded pages with the total row count; the count is checked so
    a truncated or inconsistent answer is never used.
    """

    rows: list[dict[str, Any]] = []
    total: object = None
    for page in _pages(kind, request_input):
        items = page.get("decisions")
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)
        if total is not None and page.get("total") != total:
            raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)
        total = page.get("total")
        rows.extend(cast("list[dict[str, Any]]", items))
    if total != len(rows):
        raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)
    return rows


def policy_bundle_paged_text(kind: str, request_input: dict[str, object]) -> str:
    """Collect a text verdict that can exceed one resident response, page by page.

    The reassembled text must match the byte count and SHA-256 Rust reported for
    the whole document.
    """

    parts: list[str] = []
    total: object = None
    digest: object = None
    for page in _pages(kind, request_input):
        part = page.get("value")
        if not isinstance(part, str):
            raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)
        if total is not None and (page.get("total") != total or page.get("sha256") != digest):
            raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)
        total, digest = page.get("total"), page.get("sha256")
        parts.append(part)
    encoded = "".join(parts).encode("utf-8")
    if total != len(encoded) or digest != hashlib.sha256(encoded).hexdigest():
        raise PolicyBundleNativeUnavailableError(_SCHEMA_MISMATCH)
    return encoded.decode("utf-8")
