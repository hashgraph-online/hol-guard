"""Typed client for the native protection-health report; no Python verdict."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .native_runtime_values import NativeRuntimeIdentity

_FEATURE = "protection-health-facts-v1"
_OPERATION = "protection_health_facts"
_REQUEST_SCHEMA = "guard-protection-health-facts-request.v1"
_RESULT_SCHEMA = "guard-protection-health-report-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "payload"})
_PAYLOAD_KEYS = frozenset(
    {
        "schema_version",
        "state",
        "label",
        "detail",
        "evidence_gap",
        "checks",
        "reason_codes",
        "apps",
    }
)
_REPORT_STATES = frozenset({"protected", "partial", "degraded"})
_CHECK_STATUSES = frozenset({"pass", "unknown", "fail"})
_CHECK_KEYS = frozenset({"check_id", "status", "reason_code"})
_APP_KEYS = frozenset({"harness", "state", "label", "detail", "evidence_gap", "checks", "reason_codes"})
# A handful of facts and the managed installs' identities; the op's own bound
# is 256 KiB and the wire envelope carries the same material plus framing.
_MAX_WIRE_BYTES = 512 * 1024


class NativeProtectionHealthError(RuntimeError):
    """The native owner could not supply a complete, request-bound report."""


def protection_health_report(
    facts: Mapping[str, object],
    *,
    guard_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, object]:
    """Return the resident's protection-health report for these facts.

    What each fact proves, which statuses add up to ``protected``, which
    failures are a platform with no such check, and the words an operator reads
    are the resident's. Every outcome other than a well-formed, request-bound
    ``ok`` reply raises ``NativeProtectionHealthError``, so an unreachable
    runtime is never read as a machine that turned out to be protected.
    """

    wire: dict[str, object] = {
        **facts,
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id(_OPERATION),
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeProtectionHealthError("native_protection_health_report_unavailable")
        # The resident answers with the prefixed token, so bind against the same form.
        request_sha256 = "sha256:" + _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation=_OPERATION,
            request=wire,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
            # Success is recorded below, once the reply is known to be usable.
            record_success=False,
            status=status,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeProtectionHealthError("native_protection_health_report_unavailable") from error
    if decoded is None:
        raise NativeProtectionHealthError("native_protection_health_report_unavailable")
    try:
        report = _validated_report(decoded, wire, request_sha256)
    except NativeProtectionHealthError:
        _record(home, status.identity, success=False)
        raise
    _record(home, status.identity, success=True)
    return report


def _is_word(value: Any, words: frozenset[str]) -> bool:
    """Whether ``value`` is one of ``words``.

    A reply is JSON the resident sent, so a field the grammar expects to be a
    word can arrive as a list or an object. Testing set membership on one of
    those raises ``TypeError``, which would escape this adapter instead of
    being refused as the malformed reply it is.
    """

    return isinstance(value, str) and value in words


def _well_formed_checks(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(row, dict)
        and set(row) == _CHECK_KEYS
        and isinstance(row["check_id"], str)
        and _is_word(row["status"], _CHECK_STATUSES)
        and isinstance(row["reason_code"], str)
        for row in value
    )


def _well_formed_reason_codes(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(code, str) for code in value)


def _well_formed_verdict(row: Mapping[str, Any]) -> bool:
    """Whether a report or harness row states its verdict in the resident's own words.

    Nothing here decides what the state should have been: that is the
    resident's, and this call has no signals left to recompute it from. It only
    refuses a reply that is not a report at all, so a payload whose ``state``
    is a number or an unknown word can never be rendered as protection.
    """

    return (
        _is_word(row["state"], _REPORT_STATES)
        and isinstance(row["label"], str)
        and isinstance(row["detail"], str)
        and isinstance(row["evidence_gap"], bool)
        and _well_formed_checks(row["checks"])
        and _well_formed_reason_codes(row["reason_codes"])
    )


def _well_formed_apps(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(row, dict)
        and set(row) == _APP_KEYS
        and isinstance(row["harness"], str)
        and _well_formed_verdict(row)
        for row in value
    )


def _validated_report(decoded: dict[str, Any], wire: dict[str, object], request_sha256: str) -> dict[str, object]:
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok":
        raise NativeProtectionHealthError("native_protection_health_report_invalid_result")
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeProtectionHealthError("native_protection_health_report_request_mismatch")
    payload: Any = decoded.get("payload")
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise NativeProtectionHealthError("native_protection_health_report_invalid_result")
    if (
        not isinstance(payload["schema_version"], str)
        or not _well_formed_verdict(payload)
        or not _well_formed_apps(payload["apps"])
    ):
        raise NativeProtectionHealthError("native_protection_health_report_invalid_result")
    return payload


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_protection_health_report_result")
