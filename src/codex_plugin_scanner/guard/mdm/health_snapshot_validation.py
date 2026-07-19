"""Strict binding validation for machine health snapshots carried by lease outboxes."""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from typing import Protocol, get_args

from .contracts import (
    AssuranceLevel,
    InstallOwner,
    IntegrityReasonCode,
    IntegrityState,
    KeyProtectionLevel,
    RemediationClass,
    SupervisorState,
)

_MAX_SNAPSHOT_BYTES = 256 * 1024
_MAX_UINT64 = (1 << 64) - 1
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_SNAPSHOT_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_SNAPSHOT_KEYS = {
    "schemaVersion",
    "generatedAt",
    "scope",
    "healthy",
    "assuranceLevel",
    "installOwner",
    "platform",
    "architecture",
    "identifiers",
    "product",
    "components",
    "harnessCoverage",
    "continuity",
    "reasonCodes",
    "remediationClass",
}
_IDENTIFIER_KEYS = {"workspaceId", "deviceId", "machineInstallationId", "installationGeneration"}
_PRODUCT_KEYS = {"version", "buildId", "sourceCommit", "packageIdentity", "manifestHash", "policyHash"}
_COMPONENT_KEYS = {
    "manifest",
    "nativePackage",
    "managedPolicy",
    "ownershipAndAcl",
    "supervisor",
    "deviceKey",
    "harnessCoverage",
    "installationIdentity",
    "leaseContinuity",
    "daemon",
    "commandShadowing",
    "update",
}
_HARNESS_KEYS = {"required", "protected", "degraded", "missing"}
_CONTINUITY_KEYS = {"monotonicUptimeSeconds", "sequence", "previousLeaseDigest", "bootSessionId"}
_BASIC_COMPONENT_KEYS = {"state", "healthy", "reasonCode"}
_INTEGRITY_STATES = frozenset(get_args(IntegrityState))
_SUPERVISOR_STATES = frozenset(get_args(SupervisorState))
_KEY_LEVELS = frozenset(get_args(KeyProtectionLevel))
_REASON_CODES = frozenset(get_args(IntegrityReasonCode))


class SnapshotLeaseClaims(Protocol):
    @property
    def workspace_id(self) -> str: ...
    @property
    def device_id(self) -> str: ...
    @property
    def machine_installation_id(self) -> str: ...
    @property
    def installation_generation(self) -> str: ...
    @property
    def sequence(self) -> int: ...
    @property
    def snapshot_schema_version(self) -> str: ...
    @property
    def previous_lease_digest(self) -> str | None: ...


def _reject_json_constant(_value: str) -> None:
    raise ValueError("health_lease_json_invalid")


def _strict_json(payload: bytes) -> dict[str, object]:
    if not payload or len(payload) > _MAX_SNAPSHOT_BYTES:
        raise ValueError("health_lease_outbox_invalid")
    try:
        raw = json.loads(payload.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("health_lease_outbox_invalid") from exc
    if not isinstance(raw, dict):
        raise ValueError("health_lease_outbox_invalid")
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if canonical != payload:
        raise ValueError("health_lease_outbox_invalid")
    return raw


def _exact_keys(raw: dict[str, object], expected: set[str]) -> None:
    if set(raw) != expected:
        raise ValueError("health_lease_outbox_invalid")


def _match(value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError("health_lease_outbox_invalid")
    return value


def _bounded_string(value: object, *, maximum: int, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or len(value.encode()) > maximum:
        raise ValueError("health_lease_outbox_invalid")
    return value


def _optional_uint64(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_UINT64:
        raise ValueError("health_lease_outbox_invalid")
    return value


def validate_health_snapshot_binding(snapshot: bytes, claims: SnapshotLeaseClaims) -> None:
    raw = _strict_json(snapshot)
    _exact_keys(raw, _SNAPSHOT_KEYS)
    if raw.get("schemaVersion") != claims.snapshot_schema_version:
        raise ValueError("health_lease_outbox_invalid")
    identifiers = raw.get("identifiers")
    product = raw.get("product")
    components = raw.get("components")
    harness = raw.get("harnessCoverage")
    continuity = raw.get("continuity")
    if not all(isinstance(value, dict) for value in (identifiers, product, components, harness, continuity)):
        raise ValueError("health_lease_outbox_invalid")
    assert isinstance(identifiers, dict)
    assert isinstance(product, dict)
    assert isinstance(components, dict)
    assert isinstance(harness, dict)
    assert isinstance(continuity, dict)
    for value, keys in (
        (identifiers, _IDENTIFIER_KEYS),
        (product, _PRODUCT_KEYS),
        (components, _COMPONENT_KEYS),
        (harness, _HARNESS_KEYS),
        (continuity, _CONTINUITY_KEYS),
    ):
        _exact_keys(value, keys)
    for name, component in components.items():
        if not isinstance(component, dict):
            raise ValueError("health_lease_outbox_invalid")
        expected = _BASIC_COMPONENT_KEYS | ({"level"} if name == "deviceKey" else set())
        _exact_keys(component, expected)
        allowed_states = _SUPERVISOR_STATES if name == "supervisor" else _INTEGRITY_STATES
        state = component.get("state")
        reason_code = component.get("reasonCode")
        level = component.get("level")
        if (
            not isinstance(state, str)
            or state not in allowed_states
            or not isinstance(component.get("healthy"), bool)
            or not isinstance(reason_code, str)
            or reason_code not in _REASON_CODES
            or (name == "deviceKey" and (not isinstance(level, str) or level not in _KEY_LEVELS))
        ):
            raise ValueError("health_lease_outbox_invalid")
    generated_at = raw.get("generatedAt")
    if not isinstance(generated_at, str) or _SNAPSHOT_TIMESTAMP.fullmatch(generated_at) is None:
        raise ValueError("health_lease_outbox_invalid")
    try:
        generated = datetime.fromisoformat(f"{generated_at[:-1]}+00:00")
    except ValueError as exc:
        raise ValueError("health_lease_outbox_invalid") from exc
    reason_codes = raw.get("reasonCodes")
    if (
        generated.tzinfo is None
        or len(generated_at.encode("utf-8")) > 64
        or raw.get("scope") != "machine"
        or not isinstance(raw.get("healthy"), bool)
        or raw.get("assuranceLevel") not in get_args(AssuranceLevel)
        or raw.get("installOwner") not in get_args(InstallOwner)
        or raw.get("remediationClass") not in get_args(RemediationClass)
        or not isinstance(reason_codes, list)
        or len(reason_codes) > 64
        or any(not isinstance(reason, str) or reason not in _REASON_CODES for reason in reason_codes)
        or reason_codes != sorted(set(reason_codes))
    ):
        raise ValueError("health_lease_outbox_invalid")
    _bounded_string(raw.get("platform"), maximum=64)
    _bounded_string(raw.get("architecture"), maximum=64)
    _bounded_string(product.get("version"), maximum=128)
    _bounded_string(product.get("buildId"), maximum=256, nullable=True)
    _bounded_string(product.get("sourceCommit"), maximum=256, nullable=True)
    _bounded_string(product.get("packageIdentity"), maximum=256)
    for name in ("manifestHash", "policyHash"):
        value = product.get(name)
        if value is not None:
            _match(value, _HEX_64)
    for value in harness.values():
        _optional_uint64(value)
    uptime = continuity.get("monotonicUptimeSeconds")
    if uptime is not None and (
        not isinstance(uptime, (int, float)) or isinstance(uptime, bool) or not math.isfinite(uptime) or uptime < 0
    ):
        raise ValueError("health_lease_outbox_invalid")
    _optional_uint64(continuity.get("sequence"))
    previous = continuity.get("previousLeaseDigest")
    if previous is not None:
        _match(previous, _HEX_64)
    _bounded_string(continuity.get("bootSessionId"), maximum=256, nullable=True)
    expected_identifiers = {
        "workspaceId": claims.workspace_id,
        "deviceId": claims.device_id,
        "machineInstallationId": claims.machine_installation_id,
        "installationGeneration": claims.installation_generation,
    }
    if any(identifiers.get(key) != value for key, value in expected_identifiers.items()):
        raise ValueError("health_lease_outbox_invalid")
    if (
        continuity.get("sequence") != claims.sequence - 1
        or continuity.get("previousLeaseDigest") != claims.previous_lease_digest
    ):
        raise ValueError("health_lease_outbox_invalid")


__all__ = ["validate_health_snapshot_binding"]
