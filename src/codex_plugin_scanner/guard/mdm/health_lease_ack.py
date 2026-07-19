"""Strict Cloud acknowledgement contract for machine health leases."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, cast

from .health_lease_contract import MAX_UINT64, canonical_json_bytes

HEALTH_LEASE_ACK_SCHEMA: Final = "hol-guard-health-lease-ack.v1"
MAX_ACK_BYTES: Final = 4096

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_ACK_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
_ACK_KEYS = {
    "schemaVersion",
    "status",
    "workspaceId",
    "deviceId",
    "machineInstallationId",
    "installationGeneration",
    "sequence",
    "leaseDigest",
    "receivedAt",
}


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("health_lease_ack_invalid")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("health_lease_ack_invalid")


def _match(value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError("health_lease_ack_invalid")
    return value


@dataclass(frozen=True, slots=True)
class HealthLeaseAck:
    status: str
    workspace_id: str
    device_id: str
    machine_installation_id: str
    installation_generation: str
    sequence: int
    lease_digest: str
    received_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": HEALTH_LEASE_ACK_SCHEMA,
            "status": self.status,
            "workspaceId": self.workspace_id,
            "deviceId": self.device_id,
            "machineInstallationId": self.machine_installation_id,
            "installationGeneration": self.installation_generation,
            "sequence": self.sequence,
            "leaseDigest": self.lease_digest,
            "receivedAt": self.received_at,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @property
    def received_datetime(self) -> datetime:
        return datetime.strptime(self.received_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)

    @classmethod
    def parse(cls, payload: bytes) -> HealthLeaseAck:
        if not payload or len(payload) > MAX_ACK_BYTES:
            raise ValueError("health_lease_ack_invalid")
        try:
            decoded = json.loads(
                payload.decode("utf-8"),
                parse_constant=_reject_json_constant,
                object_pairs_hook=_unique_json_object,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("health_lease_ack_invalid") from exc
        if not isinstance(decoded, dict):
            raise ValueError("health_lease_ack_invalid")
        raw = cast(dict[str, object], decoded)
        if set(raw) != _ACK_KEYS or raw.get("schemaVersion") != HEALTH_LEASE_ACK_SCHEMA:
            raise ValueError("health_lease_ack_invalid")
        status = raw.get("status")
        if not isinstance(status, str) or status not in {"accepted", "replayed"}:
            raise ValueError("health_lease_ack_invalid")
        sequence = raw.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or not 1 <= sequence <= MAX_UINT64:
            raise ValueError("health_lease_ack_invalid")
        received_at = raw.get("receivedAt")
        if not isinstance(received_at, str) or _ACK_TIMESTAMP.fullmatch(received_at) is None:
            raise ValueError("health_lease_ack_invalid")
        try:
            parsed_received_at = datetime.strptime(received_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError("health_lease_ack_invalid") from exc
        canonical_received_at = parsed_received_at.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if canonical_received_at != received_at:
            raise ValueError("health_lease_ack_invalid")
        return cls(
            status,
            _match(raw.get("workspaceId"), _SAFE_ID),
            _match(raw.get("deviceId"), _SAFE_ID),
            _match(raw.get("machineInstallationId"), _HEX_32),
            _match(raw.get("installationGeneration"), _HEX_32),
            sequence,
            _match(raw.get("leaseDigest"), _HEX_64),
            canonical_received_at,
        )


__all__ = ["HEALTH_LEASE_ACK_SCHEMA", "MAX_ACK_BYTES", "HealthLeaseAck"]
