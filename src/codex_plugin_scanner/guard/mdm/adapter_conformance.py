"""Vendor-neutral conformance checks for MDM/EDR observer adapters."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_ASSERTION_BYTES = 16_384
MAX_CLOCK_SKEW_SECONDS = 60
MAX_ASSERTION_LIFETIME_SECONDS = 900
ALLOWED_REMEDIATION_ACTIONS = frozenset({"install", "repair", "policy-refresh", "service-register", "version-converge"})
ALLOWED_OBSERVER_REASONS = frozenset(
    {
        "observer_current_present",
        "observer_current_absent",
        "observer_current_partial",
        "observer_offline",
        "observer_stale",
        "observer_mapping_ambiguous",
        "observer_credential_invalid",
    }
)
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")


class AdapterConformanceError(ValueError):
    """Stable rejection reason raised by the conformance harness."""


@dataclass(frozen=True, slots=True)
class ObserverConformanceResult:
    assertion_id: str | None
    digest: str | None
    outcome: Literal["accepted", "duplicate", "outage", "quarantined"]
    reason: str | None


@dataclass(frozen=True, slots=True)
class RemediationConformanceResult:
    digest: str
    job_id: str
    outcome: Literal["accepted", "duplicate"]


def _error(reason: str) -> AdapterConformanceError:
    return AdapterConformanceError(reason)


def _object(value: object, reason: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _error(reason)
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], reason: str) -> None:
    if set(value) != expected:
        raise _error(reason)


def _safe_id(value: object, reason: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise _error(reason)
    return value


def _timestamp(value: object, reason: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _error(reason)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise _error(reason) from exc
    return parsed.astimezone(timezone.utc)


def _strict_json(payload: bytes, *, maximum: int, reason: str) -> dict[str, object]:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise _error(reason)
    try:
        text = payload.decode("utf-8")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error(reason) from exc
    if json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() != payload:
        raise _error(reason)
    return _object(value, reason)


def _verify_signature(envelope: Mapping[str, object], public_key: Ed25519PublicKey, *, reason: str) -> None:
    signature = _object(envelope.get("signature"), reason)
    _exact_keys(signature, {"algorithm", "keyId", "value"}, reason)
    _safe_id(signature.get("keyId"), reason)
    encoded = signature.get("value")
    if signature.get("algorithm") != "ed25519" or not isinstance(encoded, str):
        raise _error(reason)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _error(reason) from exc
    if len(raw) != 64:
        raise _error(reason)
    unsigned = dict(envelope)
    unsigned.pop("signature")
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    try:
        public_key.verify(raw, canonical)
    except InvalidSignature as exc:
        raise _error("adapter_signature_invalid") from exc


@dataclass(slots=True)
class ObserverAdapterConformanceHarness:
    """Validate adapter assertions without embedding vendor-specific logic."""

    accepted: dict[tuple[str, str], str] = field(default_factory=dict)

    def evaluate(
        self,
        payload: bytes | None,
        *,
        mapping_candidates: int,
        now: datetime,
        public_key: Ed25519PublicKey,
        transport_error: str | None = None,
    ) -> ObserverConformanceResult:
        if payload is None:
            if not transport_error or len(transport_error) > 128:
                raise _error("adapter_outage_invalid")
            return ObserverConformanceResult(None, None, "outage", "observer_unavailable")
        if transport_error is not None:
            raise _error("adapter_outage_invalid")
        if now.tzinfo is None:
            raise _error("adapter_clock_invalid")
        if not isinstance(mapping_candidates, int) or isinstance(mapping_candidates, bool) or mapping_candidates < 0:
            raise _error("adapter_mapping_invalid")
        envelope = _strict_json(payload, maximum=MAX_ASSERTION_BYTES, reason="adapter_assertion_invalid")
        _exact_keys(
            envelope,
            {
                "schemaVersion",
                "assertionId",
                "workspaceId",
                "observerId",
                "adapterId",
                "externalDeviceId",
                "observedAt",
                "expiresAt",
                "detection",
                "remediation",
                "signature",
            },
            "adapter_assertion_invalid",
        )
        if envelope.get("schemaVersion") != "observer-assertion.v1":
            raise _error("adapter_assertion_invalid")
        assertion_id = _safe_id(envelope.get("assertionId"), "adapter_assertion_invalid")
        observer_id = _safe_id(envelope.get("observerId"), "adapter_assertion_invalid")
        for key in ("workspaceId", "adapterId", "externalDeviceId"):
            _safe_id(envelope.get(key), "adapter_assertion_invalid")
        observed_at = _timestamp(envelope.get("observedAt"), "adapter_assertion_invalid")
        expires_at = _timestamp(envelope.get("expiresAt"), "adapter_assertion_invalid")
        current = now.astimezone(timezone.utc)
        if observed_at > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
            raise _error("adapter_clock_skew")
        if expires_at <= current or expires_at <= observed_at:
            raise _error("adapter_assertion_expired")
        if expires_at > observed_at + timedelta(seconds=MAX_ASSERTION_LIFETIME_SECONDS):
            raise _error("adapter_assertion_lifetime")
        detection = _object(envelope.get("detection"), "adapter_assertion_invalid")
        _exact_keys(
            detection,
            {"state", "endpointOnline", "version", "packageIdentity", "reasonCodes"},
            "adapter_assertion_invalid",
        )
        state = detection.get("state")
        endpoint_online = detection.get("endpointOnline")
        version = detection.get("version")
        package_identity = detection.get("packageIdentity")
        reasons = detection.get("reasonCodes")
        if state not in {"present", "absent", "partial", "unknown", "unsupported"}:
            raise _error("adapter_assertion_invalid")
        if endpoint_online is not None and not isinstance(endpoint_online, bool):
            raise _error("adapter_assertion_invalid")
        if version is not None and (not isinstance(version, str) or len(version) > 128):
            raise _error("adapter_assertion_invalid")
        if package_identity is not None and (not isinstance(package_identity, str) or len(package_identity) > 256):
            raise _error("adapter_assertion_invalid")
        if (
            not isinstance(reasons, list)
            or len(reasons) > 32
            or not all(isinstance(item, str) and item in ALLOWED_OBSERVER_REASONS for item in reasons)
            or len(set(reasons)) != len(reasons)
        ):
            raise _error("adapter_assertion_invalid")
        if state == "partial" and not reasons:
            raise _error("adapter_partial_without_reason")
        remediation = _object(envelope.get("remediation"), "adapter_assertion_invalid")
        _exact_keys(remediation, {"state", "jobId"}, "adapter_assertion_invalid")
        remediation_state = remediation.get("state")
        remediation_job_id = remediation.get("jobId")
        if remediation_state not in {
            "none",
            "queued",
            "accepted",
            "running",
            "succeeded",
            "failed",
            "paused",
            "unknown",
        }:
            raise _error("adapter_assertion_invalid")
        if remediation_state == "none":
            if remediation_job_id is not None:
                raise _error("adapter_assertion_invalid")
        else:
            _safe_id(remediation_job_id, "adapter_assertion_invalid")
        _verify_signature(envelope, public_key, reason="adapter_assertion_invalid")
        digest = hashlib.sha256(payload).hexdigest()
        replay_key = (observer_id, assertion_id)
        previous = self.accepted.get(replay_key)
        if previous is not None:
            if previous != digest:
                raise _error("adapter_assertion_replay_conflict")
            return ObserverConformanceResult(assertion_id, digest, "duplicate", None)
        self.accepted[replay_key] = digest
        if mapping_candidates != 1:
            return ObserverConformanceResult(assertion_id, digest, "quarantined", "mapping_not_unique")
        return ObserverConformanceResult(assertion_id, digest, "accepted", None)


@dataclass(slots=True)
class RemediationAdapterConformanceHarness:
    """Validate signed, bounded, replay-safe remediation jobs."""

    accepted: dict[tuple[str, str], str] = field(default_factory=dict)

    def evaluate(self, payload: bytes, *, now: datetime, public_key: Ed25519PublicKey) -> RemediationConformanceResult:
        if now.tzinfo is None:
            raise _error("adapter_clock_invalid")
        envelope = _strict_json(payload, maximum=MAX_ASSERTION_BYTES, reason="adapter_remediation_invalid")
        _exact_keys(
            envelope,
            {
                "schemaVersion",
                "jobId",
                "workspaceId",
                "deviceId",
                "installationGeneration",
                "action",
                "targetVersion",
                "idempotencyKey",
                "issuedAt",
                "validForSeconds",
                "attemptLimit",
                "signature",
            },
            "adapter_remediation_invalid",
        )
        if envelope.get("schemaVersion") != "remediation-job.v1":
            raise _error("adapter_remediation_invalid")
        job_id = _safe_id(envelope.get("jobId"), "adapter_remediation_invalid")
        workspace_id = _safe_id(envelope.get("workspaceId"), "adapter_remediation_invalid")
        _safe_id(envelope.get("deviceId"), "adapter_remediation_invalid")
        idempotency_key = _safe_id(envelope.get("idempotencyKey"), "adapter_remediation_invalid")
        generation = envelope.get("installationGeneration")
        action = envelope.get("action")
        duration = envelope.get("validForSeconds")
        attempt_limit = envelope.get("attemptLimit")
        if not isinstance(generation, str) or _HEX_32.fullmatch(generation) is None:
            raise _error("adapter_remediation_invalid")
        if action not in ALLOWED_REMEDIATION_ACTIONS:
            raise _error("adapter_remediation_action_denied")
        if not isinstance(duration, int) or isinstance(duration, bool) or not 60 <= duration <= 3600:
            raise _error("adapter_remediation_invalid")
        if not isinstance(attempt_limit, int) or isinstance(attempt_limit, bool) or not 1 <= attempt_limit <= 5:
            raise _error("adapter_remediation_invalid")
        issued_at = _timestamp(envelope.get("issuedAt"), "adapter_remediation_invalid")
        current = now.astimezone(timezone.utc)
        if issued_at > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
            raise _error("adapter_clock_skew")
        if issued_at + timedelta(seconds=duration) <= current:
            raise _error("adapter_remediation_expired")
        target = envelope.get("targetVersion")
        if action in {"install", "version-converge"} and (not isinstance(target, str) or not 1 <= len(target) <= 128):
            raise _error("adapter_remediation_invalid")
        if target is not None and (not isinstance(target, str) or len(target) > 128):
            raise _error("adapter_remediation_invalid")
        _verify_signature(envelope, public_key, reason="adapter_remediation_invalid")
        digest = hashlib.sha256(payload).hexdigest()
        replay_key = (workspace_id, idempotency_key)
        previous = self.accepted.get(replay_key)
        if previous is not None:
            if previous != digest:
                raise _error("adapter_remediation_replay_conflict")
            return RemediationConformanceResult(digest, job_id, "duplicate")
        self.accepted[replay_key] = digest
        return RemediationConformanceResult(digest, job_id, "accepted")
