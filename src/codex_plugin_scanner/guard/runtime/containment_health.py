"""Fail-closed health and proof gating for enforced containment."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
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
_CONTAINMENT_CHECK_IDS: Final = frozenset(
    {"policy_engine", "decision_plane_compatibility", "containment_compatibility", "sandbox"}
)


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
    guard_home: Path | None = None,
) -> dict[str, ProtectionSignal]:
    """The four containment-owned checks the resident proves from this evidence.

    The resident decides them exactly as it does inside the full report, so a
    repair confirmation can never disagree with the health the operator sees.
    A resident that cannot answer raises ``NativeProtectionHealthError``,
    except for valid evidence from a platform with no backend: that fails all
    four checks as ``unsupported_platform`` before any other check, so it is
    answered here and stays a platform limit rather than an unreachable runtime.
    """

    if _unsupported_backend(value):
        unsupported = ProtectionSignal(ProtectionCheckStatus.FAIL, "unsupported_platform")
        return dict.fromkeys(sorted(_CONTAINMENT_CHECK_IDS), unsupported)

    from ..native_protection_health import protection_health_report

    report = protection_health_report(
        {
            "now": now.isoformat(),
            "managed_installs": [],
            "hook_verification": None,
            "daemon": {"registration_status": None, "last_heartbeat_at": None, "containment_health": value},
            "remembered_rules": None,
            "runtime_protection": None,
            "decision_stream": None,
        },
        guard_home=guard_home,
    )
    checks = cast(list[dict[str, str]], report["checks"])
    return {
        row["check_id"]: ProtectionSignal(ProtectionCheckStatus(row["status"]), row["reason_code"])
        for row in checks
        if row["check_id"] in _CONTAINMENT_CHECK_IDS
    }


def _unsupported_backend(value: object) -> bool:
    try:
        evidence = ContainmentHealthEvidence.from_mapping(value)
    except (TypeError, ValueError):
        return False
    return evidence.backend is ContainmentBackend.UNSUPPORTED


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("probe_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("probe_at must include a timezone")
    return parsed.astimezone(timezone.utc)


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
