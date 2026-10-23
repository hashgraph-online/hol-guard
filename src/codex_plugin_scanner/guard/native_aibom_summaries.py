"""Typed client for the native AIBOM report summaries; no Python counting."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .inventory_contract import GuardAgentInventorySnapshot
    from .native_runtime_values import NativeRuntimeIdentity

_FEATURE = "aibom-report-summaries-v1"
_REQUEST_SCHEMA = "guard-aibom-report-summaries-request.v1"
_RESULT_SCHEMA = "guard-aibom-report-summaries-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "payload"})
_PAYLOAD_KEYS = ("layer_summary", "trust", "drift")
# The resident accepts a canonical request up to 4 MiB; the wire envelope
# carries the same material plus framing, so leave room for both -- and no more
# than the transport will frame. Twice the op's bound is past that ceiling, so
# a request between the two was refused as a broken runtime rather than as one
# that asked for too much.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_WIRE_BYTES = 6 * 1024 * 1024 - 64 * 1024


class NativeAibomSummariesError(RuntimeError):
    """The native owner could not supply complete, request-bound summaries."""


def report_summaries(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
    *,
    generated_at: str,
    guard_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Return the resident's ``(layer_summary, trust, drift)`` for one report.

    The counts decide what an operator is told about drift, trust coverage and
    high-risk artifacts, so there is one place that produces them. Every
    outcome other than a well-formed, request-bound ``ok`` reply raises
    ``NativeAibomSummariesError``; no caller recomputes a summary locally.
    """

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("aibom_report_summaries"),
        "generated_at": generated_at,
        "snapshots": [_snapshot_row(snapshot) for snapshot in snapshots],
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeAibomSummariesError("native_aibom_report_summaries_unavailable")
        # The resident answers with the prefixed token, so bind against the same form.
        request_sha256 = "sha256:" + _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation="aibom_report_summaries",
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
        raise NativeAibomSummariesError("native_aibom_report_summaries_unavailable") from error
    if decoded is None:
        raise NativeAibomSummariesError("native_aibom_report_summaries_unavailable")
    try:
        summaries = _validated_summaries(decoded, wire, request_sha256)
    except NativeAibomSummariesError:
        _record(home, status.identity, success=False)
        raise
    _record(home, status.identity, success=True)
    return summaries


def _snapshot_row(snapshot: GuardAgentInventorySnapshot) -> dict[str, object]:
    """Project one snapshot to the fields the summaries read.

    The findings and the sources reach the grammar only through how many there
    are, so the row carries the counts rather than the records.
    """

    return {
        "items": [_item_row(item) for item in snapshot.items],
        "finding_count": len(snapshot.findings),
        "source_count": len(snapshot.sources),
        "drift_states": [str(drift.state) for drift in snapshot.drift],
    }


def _item_row(item: Any) -> dict[str, object]:
    metadata = item.metadata if isinstance(item.metadata, dict) else {}
    return {
        "item_kind": str(item.item_kind),
        "risk_level": str(item.risk_level),
        "drift_state": str(item.drift_state),
        # Always present: a key the request omits digests differently on each
        # side of the call, and the reply would never bind to this request.
        "trust_resolution": _trust_shape(metadata.get("trustResolution")),
        "source_links": _links_shape(metadata.get("sourceLinks")),
        "source_of_truth": {} if isinstance(metadata.get("sourceOfTruth"), dict) else None,
    }


# Stored metadata is arbitrary and can be large. The grammar reads a source of
# truth for being an object, the source links for how many there are, and the
# trust resolution for being an object and for its score. The rows below keep
# exactly that shape, so the answer is the same and nested scan detail never
# counts against the request budget. Whether a value counts stays the
# resident's call.


def _trust_shape(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    score = value.get("trustScore")
    # A number is small however it is spelled; anything else reads as no score.
    return {"trustScore": score} if isinstance(score, int | float) else {}


def _links_shape(value: object) -> list[None] | None:
    return [None] * len(value) if isinstance(value, list) else None


def _validated_summaries(
    decoded: dict[str, Any], wire: dict[str, object], request_sha256: str
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok":
        raise NativeAibomSummariesError("native_aibom_report_summaries_invalid_result")
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeAibomSummariesError("native_aibom_report_summaries_request_mismatch")
    payload: Any = decoded.get("payload")
    if not isinstance(payload, dict) or set(payload) != set(_PAYLOAD_KEYS):
        raise NativeAibomSummariesError("native_aibom_report_summaries_invalid_result")
    summaries = tuple(payload[key] for key in _PAYLOAD_KEYS)
    if not all(isinstance(summary, dict) for summary in summaries):
        raise NativeAibomSummariesError("native_aibom_report_summaries_invalid_result")
    return summaries  # type: ignore[return-value]


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_aibom_report_summaries_result")
