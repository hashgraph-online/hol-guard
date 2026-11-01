"""Fail-closed health and proof gating for enforced containment."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final, cast

from .containment_contract import (
    CONTAINMENT_POLICY_VERSION,
    CONTAINMENT_SCHEMA_VERSION,
    ContainmentBackend,
)
from .effect_contract import EFFECT_CONTRACT_SCHEMA_VERSION
from .effect_decision import EFFECT_DECISION_SCHEMA_VERSION
from .protection_health import ProtectionCheckStatus, ProtectionSignal

CONTAINMENT_HEALTH_SCHEMA_VERSION: Final = "guard.containment-health.v1"
CONTAINMENT_POLICY_CONTRACT_DIGEST: Final = hashlib.sha256(
    b"guard.containment-policy.v1\x00deny-network\x00deny-external-writes\x00deny-live-workspace-reads"
).hexdigest()
_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_UNSUPPORTED_BACKEND_DIGEST: Final = hashlib.sha256(b"unavailable:unsupported").hexdigest()
_PROBE_MAX_AGE: Final = timedelta(minutes=5)
_FUTURE_TOLERANCE: Final = timedelta(seconds=5)


@dataclass(frozen=True, slots=True)
class ContainmentHealthEvidence:
    """Privacy-safe compatibility and self-probe evidence from the active daemon."""

    backend: ContainmentBackend
    backend_digest: str
    policy_contract_digest: str
    daemon_fingerprint: str
    runtime_fingerprint: str
    probe_at: str
    probe_enforced: bool
    containment_schema_version: str = CONTAINMENT_SCHEMA_VERSION
    policy_version: str = CONTAINMENT_POLICY_VERSION
    effect_contract_schema_version: str = EFFECT_CONTRACT_SCHEMA_VERSION
    effect_decision_schema_version: str = EFFECT_DECISION_SCHEMA_VERSION
    schema_version: str = CONTAINMENT_HEALTH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CONTAINMENT_HEALTH_SCHEMA_VERSION:
            raise ValueError("unsupported containment health schema version")
        if not isinstance(cast(object, self.backend), ContainmentBackend):
            raise ValueError("backend must be an exact ContainmentBackend")
        digests = (
            ("backend_digest", self.backend_digest),
            ("policy_contract_digest", self.policy_contract_digest),
            ("daemon_fingerprint", self.daemon_fingerprint),
            ("runtime_fingerprint", self.runtime_fingerprint),
        )
        for name, value in digests:
            if _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if type(self.probe_enforced) is not bool:
            raise ValueError("probe_enforced must be a boolean")
        _ = _parse_time(self.probe_at)

    @classmethod
    def from_mapping(cls, value: object) -> ContainmentHealthEvidence:
        if not isinstance(value, Mapping):
            raise ValueError("containment health evidence must be a mapping")
        expected_keys = {
            "backend",
            "backend_digest",
            "policy_contract_digest",
            "daemon_fingerprint",
            "runtime_fingerprint",
            "probe_at",
            "probe_enforced",
            "containment_schema_version",
            "policy_version",
            "effect_contract_schema_version",
            "effect_decision_schema_version",
            "schema_version",
        }
        raw_mapping = cast(Mapping[object, object], value)
        if set(raw_mapping) != expected_keys:
            raise ValueError("containment health evidence fields are incomplete or unknown")
        try:
            backend = ContainmentBackend(raw_mapping["backend"])
        except (TypeError, ValueError) as exc:
            raise ValueError("unsupported containment backend") from exc
        string_fields = {
            key: _require_string(raw_mapping[key], key)
            for key in expected_keys.difference({"backend", "probe_enforced"})
        }
        return cls(
            backend=backend,
            probe_enforced=_require_bool(raw_mapping["probe_enforced"], "probe_enforced"),
            **string_fields,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": self.backend.value,
            "backend_digest": self.backend_digest,
            "policy_contract_digest": self.policy_contract_digest,
            "daemon_fingerprint": self.daemon_fingerprint,
            "runtime_fingerprint": self.runtime_fingerprint,
            "probe_at": self.probe_at,
            "probe_enforced": self.probe_enforced,
            "containment_schema_version": self.containment_schema_version,
            "policy_version": self.policy_version,
            "effect_contract_schema_version": self.effect_contract_schema_version,
            "effect_decision_schema_version": self.effect_decision_schema_version,
            "schema_version": self.schema_version,
        }

    def compatibility_errors(self, *, now: datetime, runtime_fingerprint: str | None = None) -> tuple[str, ...]:
        errors: list[str] = []
        if self.backend is ContainmentBackend.UNSUPPORTED:
            errors.append("unsupported_platform")
        if self.containment_schema_version != CONTAINMENT_SCHEMA_VERSION:
            errors.append("containment_schema_mismatch")
        if self.policy_version != CONTAINMENT_POLICY_VERSION:
            errors.append("policy_version_mismatch")
        if self.effect_contract_schema_version != EFFECT_CONTRACT_SCHEMA_VERSION:
            errors.append("effect_contract_mismatch")
        if self.effect_decision_schema_version != EFFECT_DECISION_SCHEMA_VERSION:
            errors.append("decision_plane_mismatch")
        if self.policy_contract_digest != CONTAINMENT_POLICY_CONTRACT_DIGEST:
            errors.append("policy_digest_mismatch")
        if self.daemon_fingerprint != self.runtime_fingerprint:
            errors.append("daemon_runtime_drift")
        if runtime_fingerprint is not None and self.daemon_fingerprint != runtime_fingerprint:
            errors.append("daemon_runtime_drift")
        if not self.probe_enforced:
            errors.append("containment_probe_failed")
        probe_time = _parse_time(self.probe_at)
        normalized_now = _normalized_now(now)
        age = normalized_now - probe_time
        if age < -_FUTURE_TOLERANCE:
            errors.append("containment_probe_future")
        elif age > _PROBE_MAX_AGE:
            errors.append("containment_probe_stale")
        return tuple(sorted(errors))

    def binding_digest(self) -> str:
        encoded = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


def probe_containment_health(
    *,
    daemon_fingerprint: str,
    guard_home: Path,
) -> ContainmentHealthEvidence:
    """Report containment health from the resident's own execution-owned probe.

    The resident selects the backend, runs the enforcement self-probe and builds
    the evidence, so this never recalculates any of it. A resident that cannot
    answer is reported as unavailable by raising, not by guessing a verdict here.
    """

    from ..native_execution import containment_health_probe_native

    if _SHA256.fullmatch(daemon_fingerprint) is None:
        raise ValueError("daemon fingerprint must be a lowercase SHA-256 digest")
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        return ContainmentHealthEvidence(
            backend=ContainmentBackend.UNSUPPORTED,
            backend_digest=_UNSUPPORTED_BACKEND_DIGEST,
            policy_contract_digest=CONTAINMENT_POLICY_CONTRACT_DIGEST,
            daemon_fingerprint=daemon_fingerprint,
            runtime_fingerprint=daemon_fingerprint,
            probe_at=datetime.now(timezone.utc).isoformat(),
            probe_enforced=False,
        )
    payload = containment_health_probe_native(
        daemon_fingerprint=daemon_fingerprint,
        guard_home=guard_home,
    )
    if payload is None:
        raise RuntimeError("native_containment_health_probe_unavailable")
    return ContainmentHealthEvidence.from_mapping(payload)


def containment_health_signals(
    value: object,
    *,
    now: datetime,
) -> dict[str, ProtectionSignal]:
    """Map runtime evidence into existing protection-health check IDs."""

    try:
        evidence = ContainmentHealthEvidence.from_mapping(value)
    except (TypeError, ValueError):
        return _failed_signals("containment_health_invalid")
    if evidence.backend is ContainmentBackend.UNSUPPORTED:
        return _failed_signals("unsupported_platform")
    errors = evidence.compatibility_errors(now=now)
    if not errors:
        return {
            "policy_engine": ProtectionSignal(ProtectionCheckStatus.PASS, "policy_engine_compatible"),
            "decision_plane_compatibility": ProtectionSignal(
                ProtectionCheckStatus.PASS,
                "decision_plane_compatible",
            ),
            "containment_compatibility": ProtectionSignal(
                ProtectionCheckStatus.PASS,
                "containment_compatible",
            ),
            "sandbox": ProtectionSignal(ProtectionCheckStatus.PASS, "containment_backend_enforced"),
        }
    reason = errors[0]
    policy_error = reason in {
        "policy_version_mismatch",
        "policy_digest_mismatch",
        "effect_contract_mismatch",
        "decision_plane_mismatch",
        "containment_schema_mismatch",
    }
    return _failed_signals("policy_version_mismatch" if policy_error else reason)


def _failed_signals(reason: str) -> dict[str, ProtectionSignal]:
    return {
        "policy_engine": ProtectionSignal(ProtectionCheckStatus.FAIL, reason),
        "decision_plane_compatibility": ProtectionSignal(ProtectionCheckStatus.FAIL, reason),
        "containment_compatibility": ProtectionSignal(ProtectionCheckStatus.FAIL, reason),
        "sandbox": ProtectionSignal(ProtectionCheckStatus.FAIL, reason),
    }


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("probe_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("probe_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def _normalized_now(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("now must include a timezone")
    return value.astimezone(timezone.utc)


def _require_string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _require_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


__all__ = (
    "CONTAINMENT_HEALTH_SCHEMA_VERSION",
    "CONTAINMENT_POLICY_CONTRACT_DIGEST",
    "ContainmentHealthEvidence",
    "containment_health_signals",
    "probe_containment_health",
)
