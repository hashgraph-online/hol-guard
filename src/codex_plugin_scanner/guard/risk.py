"""Artifact risk signals for local Guard artifacts, derived by the resident.

The resident ``artifact_risk`` op answers the typed signals, their V2
projection and the summary in one reply. Any missing, failed or malformed
answer raises; it never yields fewer signals.
"""

from __future__ import annotations

import base64
import json
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, TypeVar, get_args
from uuid import uuid4

from .models import GuardArtifact
from .native_content_sensitivity import PACK_THRESHOLD_BYTES, NativeContentSensitivityError, pack_json_body
from .native_context import _canonical_request_sha256, _resolve_existing_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .runtime.signals import (
    RiskConfidenceLabel,
    RiskRedactionLevel,
    RiskSeverityLabel,
    RiskSignalCategory,
    RiskSignalV2,
)
from .types import EvidenceSource, GuardSignal, SignalFamily

_Record = TypeVar("_Record")

ARTIFACT_RISK_FEATURE: Final = "artifact-risk-v1"
NO_RISK_SIGNAL_SUMMARY: Final = "No obvious secret-access or network signal was detected in the launch definition."
_REQUEST_SCHEMA: Final = "guard-artifact-risk-request.v1"
_RESULT_SCHEMA: Final = "guard-artifact-risk-result.v1"
_TIMEOUT_SECONDS: Final = 10.0
_LARGE_TIMEOUT_SECONDS: Final = 30.0
_MAX_REQUEST_BYTES: Final = 6 * 1024 * 1024
_MAX_UNPACKED_REPLY_BYTES: Final = 64 * 1024 * 1024
_RESULT_KEYS: Final = frozenset({"schema", "request_id", "request_sha256", "status", "code", "payload"})
_PAYLOAD_KEYS: Final = frozenset({"signals", "signals_v2", "summary"})
# The metadata keys the derivation reads. Lists carry their ``str`` items;
# other values that are not ``None``, ``bool`` or ``str`` carry ``str()`` and
# truthiness.
_LIST_KEYS: Final = frozenset({"env_keys", "prompt_signals", "runtime_request_signals"})
_SCALAR_KEYS: Final = frozenset(
    {
        "analysis_truncated",
        "config_parse_complete",
        "config_reason",
        "inspection_complete",
        "inspection_reason",
        "prompt_summary",
        "request_summary",
        "runtime_request_reason",
        "runtime_request_summary",
    }
)


class NativeArtifactRiskError(NativeContentSensitivityError):
    """The resident did not answer the artifact's risk signals; fail closed."""


@dataclass(frozen=True, slots=True)
class ArtifactRiskProfile:
    """Every risk signal for one artifact, from one resident reply."""

    signals: tuple[GuardSignal, ...]
    signals_v2: tuple[RiskSignalV2, ...]
    summary: str


def _text(value: object) -> bool:
    return isinstance(value, str)


def _optional_text(value: object) -> bool:
    return value is None or isinstance(value, str)


def _one_of(alias: object) -> Callable[[object], bool]:
    allowed = frozenset(get_args(alias))
    return lambda value: isinstance(value, str) and value in allowed


_SIGNAL_FIELDS: Final[Mapping[str, Callable[[object], bool]]] = {
    "signal_id": _text,
    "family": _one_of(SignalFamily),
    "severity": lambda value: type(value) is int,
    "confidence": lambda value: type(value) is float,
    "evidence_source": _one_of(EvidenceSource),
    "matched_text": _optional_text,
    "explanation": _text,
    "remediation": _optional_text,
    "rule_version": _text,
}
_SIGNAL_V2_FIELDS: Final[Mapping[str, Callable[[object], bool]]] = {
    "signal_id": _text,
    "category": _one_of(RiskSignalCategory),
    "severity": _one_of(RiskSeverityLabel),
    "confidence": _one_of(RiskConfidenceLabel),
    "detector": _text,
    "title": _text,
    "plain_reason": _text,
    "technical_detail": _optional_text,
    "evidence_ref": _optional_text,
    "redaction_level": _one_of(RiskRedactionLevel),
    "false_positive_hint": _optional_text,
    "advisory_id": _optional_text,
}


def artifact_risk_profile(artifact: GuardArtifact) -> ArtifactRiskProfile:
    """Ask the resident for every risk signal of ``artifact`` in one round trip."""

    wire = _wire_artifact(artifact)
    try:
        wire_bytes = json.dumps(wire, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise NativeArtifactRiskError("native_artifact_risk_request_invalid") from exc
    large = len(wire_bytes) > PACK_THRESHOLD_BYTES
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"artifact-risk-{uuid4().hex}",
        "artifact": pack_json_body(wire_bytes) if large else wire,
    }
    digest = "sha256:" + _canonical_request_sha256(request)
    guard_home = _resolve_existing_digest_home(None)
    if not ensure_resident_prerequisite(guard_home):
        raise NativeArtifactRiskError("native_artifact_risk_unavailable")
    response = _resident_request(
        operation="artifact_risk",
        request=request,
        guard_home=guard_home,
        timeout_seconds=_LARGE_TIMEOUT_SECONDS if large else _TIMEOUT_SECONDS,
        required_feature=ARTIFACT_RISK_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
    )
    if response is None:
        raise NativeArtifactRiskError("native_artifact_risk_unavailable")
    from .native_consumer_artifact_compose import record_binding_health

    # Health is recorded only once the reply is bound and decodes, so a
    # resident sending unusable answers keeps counting toward the circuit.
    try:
        if (
            set(response) != _RESULT_KEYS
            or response["request_id"] != request["request_id"]
            or response["request_sha256"] != digest
            or response["status"] != "ok"
            or response["code"] != "ok"
        ):
            raise NativeArtifactRiskError("native_artifact_risk_unavailable")
        profile = _profile(_unpack(response["payload"]))
    except NativeArtifactRiskError:
        record_binding_health(guard_home, healthy=False, reason="native_artifact_risk_reply_invalid")
        raise
    record_binding_health(guard_home, healthy=True, reason="native_artifact_risk_reply_invalid")
    return profile


def artifact_risk_signals_typed(artifact: GuardArtifact) -> tuple[GuardSignal, ...]:
    """Return structured risk signals for a Guard artifact."""

    return artifact_risk_profile(artifact).signals


def artifact_risk_signals(artifact: GuardArtifact) -> tuple[str, ...]:
    """Backward-compatible string signals derived from structured signals."""

    return tuple(signal.explanation for signal in artifact_risk_profile(artifact).signals)


def artifact_risk_signals_v2(artifact: GuardArtifact) -> tuple[RiskSignalV2, ...]:
    """Return product-facing V2 risk signals derived from legacy Guard signals."""

    return artifact_risk_profile(artifact).signals_v2


def artifact_risk_summary(artifact: GuardArtifact) -> str:
    """Human-readable summary of the highest-impact artifact signals."""

    return artifact_risk_profile(artifact).summary


def _wire_artifact(artifact: GuardArtifact) -> dict[str, object]:
    metadata = artifact.metadata
    return {
        "name": artifact.name,
        "command": artifact.command,
        "url": artifact.url,
        "args": list(artifact.args),
        "metadata": {
            key: _wire_value(key, metadata[key]) for key in sorted(_LIST_KEYS | _SCALAR_KEYS) if key in metadata
        },
    }


def _wire_value(key: str, value: object) -> object:
    if key in _LIST_KEYS:
        return [item if isinstance(item, str) else None for item in value] if isinstance(value, list) else None
    if value is None or isinstance(value, bool | str):
        return value
    return {"python_str": str(value), "truthy": bool(value)}


def _record(item: object, fields: Mapping[str, Callable[[object], bool]], factory: Callable[..., _Record]) -> _Record:
    if (
        not isinstance(item, dict)
        or set(item) != set(fields)
        or not all(check(item[key]) for key, check in fields.items())
    ):
        raise NativeArtifactRiskError("native_artifact_risk_reply_invalid")
    return factory(**item)


def _unpack(payload: object) -> object:
    """Decode a reply the resident gzip-packed because it was large."""

    if not isinstance(payload, dict) or set(payload) != {"packed_json_gzip_v1"}:
        return payload
    packed = payload["packed_json_gzip_v1"]
    try:
        if not isinstance(packed, str):
            raise ValueError("packed reply is not text")
        decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
        body = decoder.decompress(base64.b64decode(packed, validate=True), _MAX_UNPACKED_REPLY_BYTES + 1)
        if len(body) > _MAX_UNPACKED_REPLY_BYTES:
            raise ValueError("packed reply too large")
        if not decoder.eof or decoder.unused_data:
            raise ValueError("packed reply is not one complete gzip member")
        return json.loads(body)
    except (ValueError, zlib.error) as exc:
        raise NativeArtifactRiskError("native_artifact_risk_reply_invalid") from exc


def _profile(payload: object) -> ArtifactRiskProfile:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise NativeArtifactRiskError("native_artifact_risk_reply_invalid")
    raw_signals, raw_signals_v2, summary = payload["signals"], payload["signals_v2"], payload["summary"]
    if (
        not isinstance(raw_signals, list)
        or not isinstance(raw_signals_v2, list)
        or len(raw_signals) != len(raw_signals_v2)
        or not isinstance(summary, str)
        or not summary
    ):
        raise NativeArtifactRiskError("native_artifact_risk_reply_invalid")
    signals = tuple(_record(item, _SIGNAL_FIELDS, GuardSignal) for item in raw_signals)
    signals_v2 = tuple(_record(item, _SIGNAL_V2_FIELDS, RiskSignalV2) for item in raw_signals_v2)
    if any(signal.signal_id != projected.signal_id for signal, projected in zip(signals, signals_v2, strict=True)):
        raise NativeArtifactRiskError("native_artifact_risk_reply_invalid")
    return ArtifactRiskProfile(signals=signals, signals_v2=signals_v2, summary=summary)
