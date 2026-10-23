"""Typed client for the native retry-lineage capture; no Python grammar.

A hook's retry lineage is local diagnostic metadata: the provider session,
thread, tool call, turn or invocation it belongs to, so a later retry can be
correlated with the first attempt. It is never a capability or bearer token.
The resident decides which payload aliases count, whether they agree, and what
the digests are; this module only moves the inputs and reads the record back.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeIdentity

_FEATURE = "retry-lineage-capture-v1"
_REQUEST_SCHEMA = "guard-retry-lineage-capture-request.v1"
_RESULT_SCHEMA = "guard-retry-lineage-capture-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "lineage"})
# The resident refuses a canonical request over 4 MiB, so a larger one is
# refused here instead of costing resident health.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# The ASCII-escaped wire is the canonical request plus framing.
_MAX_WIRE_BYTES = 6 * 1024 * 1024 - 64 * 1024
# Lineage rides on a hook that is already asking; it must not hold that hook
# up. A healthy resident answers in milliseconds.
_TIMEOUT_SECONDS = 0.75
# One past the longest identifier the resident accepts, so a longer string
# keeps being refused without its whole body crossing the wire.
_MAX_SCALAR_CHARS = 257


def capture_retry_lineage(
    payload: Mapping[str, object],
    *,
    harness: str,
    workspace: str | None = None,
    action_envelope: Mapping[str, object] | None = None,
    guard_home: Path | None = None,
) -> dict[str, object] | None:
    """Return the resident's lineage record for this hook, or ``None``.

    ``None`` means the payload names no usable provider identifier, or the
    resident could not answer. Either way the hook proceeds without lineage:
    the record only correlates retries, so losing it never changes a decision,
    and there is no Python capture to fall back to.
    """

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("retry_lineage_capture"),
        "harness": harness,
        "payload": _payload_row(payload),
        "workspace": workspace,
        "action_envelope": dict(action_envelope) if action_envelope is not None else None,
    }
    try:
        # A lone surrogate (an envelope value, or a workspace path decoded
        # with surrogateescape) survives the ASCII-escaped transport but not
        # the resident's decoder; refuse it here instead of as a resident failure.
        json.dumps(wire, ensure_ascii=False).encode("utf-8")
        # The same canonical bytes the resident bounds.
        canonical = json.dumps(wire, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        if len(canonical) > _MAX_REQUEST_BYTES:
            return None
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            return None
        # The resident answers with the prefixed token, so bind against the same form.
        request_sha256 = "sha256:" + _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation="retry_lineage_capture",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
            # Success is recorded below, once the reply is known to be usable.
            record_success=False,
            status=status,
        )
    except (OSError, TypeError, ValueError):
        return None
    if decoded is None:
        return None
    valid, lineage = _validated_lineage(decoded, wire, request_sha256)
    _record(home, status.identity, success=valid)
    return lineage


def _payload_row(payload: Mapping[str, object]) -> dict[str, object]:
    """Project the payload to the top-level members the resident can read.

    Only a string member can name an identifier, so every other value is sent
    as ``false``: the resident refuses it exactly as it would the original,
    and nested tool input never counts against the request budget. A string
    longer than any identifier, or one UTF-8 cannot carry, is refused the same
    way. A key that is not a transportable string can never be an alias.
    """

    row: dict[str, object] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not _transportable(key):
            continue
        if value is None:
            row[key] = None
        elif isinstance(value, str) and len(value) <= _MAX_SCALAR_CHARS and _transportable(value):
            row[key] = value
        else:
            row[key] = False
    return row


def _transportable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _validated_lineage(
    decoded: dict[str, Any], wire: dict[str, object], request_sha256: str
) -> tuple[bool, dict[str, object] | None]:
    """Whether the reply is a bound, well-formed answer, and the record it carries."""

    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok":
        return False, None
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        return False, None
    lineage = decoded.get("lineage")
    if lineage is None:
        return True, None
    if not isinstance(lineage, dict):
        return False, None
    return True, cast("dict[str, object]", lineage)


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_retry_lineage_capture_result")


__all__ = ["capture_retry_lineage"]
