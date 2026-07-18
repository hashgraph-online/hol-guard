from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.mdm.health_lease_ack import MAX_ACK_BYTES, HealthLeaseAck
from codex_plugin_scanner.guard.mdm.health_lease_contract import canonical_json_bytes


def _ack(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": "hol-guard-health-lease-ack.v1",
        "status": "accepted",
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": "1" * 32,
        "installationGeneration": "2" * 32,
        "sequence": 1,
        "leaseDigest": "4" * 64,
        "receivedAt": "2026-07-18T14:00:01.000Z",
    }
    payload.update(updates)
    return payload


def test_ack_accepts_portal_field_order_and_canonicalizes_durable_marker() -> None:
    portal_order = json.dumps(_ack(), separators=(",", ":")).encode()

    ack = HealthLeaseAck.parse(portal_order)

    assert ack.status == "accepted"
    assert HealthLeaseAck.parse(ack.canonical_bytes()) == ack


@pytest.mark.parametrize(
    "updates",
    [
        {"status": "rejected"},
        {"workspaceId": "../escape"},
        {"sequence": True},
        {"sequence": 0},
        {"leaseDigest": "F" * 64},
        {"receivedAt": "2026-07-18T14:00:01Z"},
        {"receivedAt": "2026-07-18T14:00:01.000+00:00"},
    ],
)
def test_ack_rejects_malformed_fields(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="health_lease_ack_invalid"):
        HealthLeaseAck.parse(canonical_json_bytes(_ack(**updates)))


def test_ack_rejects_unknown_duplicate_and_oversized_input() -> None:
    duplicate = (
        b'{"schemaVersion":"hol-guard-health-lease-ack.v1","status":"accepted","status":"replayed",'
        b'"workspaceId":"workspace-a","deviceId":"device-a","machineInstallationId":"'
        + b"1" * 32
        + b'","installationGeneration":"'
        + b"2" * 32
        + b'","sequence":1,"leaseDigest":"'
        + b"4" * 64
        + b'","receivedAt":"2026-07-18T14:00:01.000Z"}'
    )
    payloads = (
        canonical_json_bytes(_ack(unexpected=True)),
        duplicate,
        b"{" + b" " * MAX_ACK_BYTES + b"}",
    )

    for payload in payloads:
        with pytest.raises(ValueError, match="health_lease_ack_invalid"):
            HealthLeaseAck.parse(payload)
