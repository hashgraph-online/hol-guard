from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.mdm.health_lease_contract import HealthLeaseBinding
from codex_plugin_scanner.guard.mdm.health_transport import (
    GuardCloudMachineHealthTransport,
    parse_pending_challenge,
)


def _payload(**updates: object) -> bytes:
    value: dict[str, object] = {
        "schemaVersion": "guard-protection-attestation-challenge.v1",
        "challengeId": "challenge-a",
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": "1" * 32,
        "installationGeneration": "2" * 32,
        "issuedAt": "2026-07-18T17:59:30Z",
        "nonce": "n" * 43,
        "validForSeconds": 120,
    }
    value.update(updates)
    return json.dumps(value, separators=(",", ":")).encode()


def test_pending_challenge_is_bound_to_exact_machine_identity() -> None:
    challenge = parse_pending_challenge(
        _payload(),
        binding=HealthLeaseBinding("workspace-a", "device-a"),
        machine_installation_id="1" * 32,
        installation_generation="2" * 32,
    )

    assert challenge.challenge_id == "challenge-a"
    assert challenge.nonce == "n" * 43


@pytest.mark.parametrize(
    "payload",
    [
        _payload(command="repair"),
        _payload(workspaceId="workspace-b"),
        _payload(deviceId="device-b"),
        _payload(machineInstallationId="3" * 32),
        _payload(installationGeneration="4" * 32),
        b"[]",
        b"x" * 4097,
    ],
)
def test_pending_challenge_rejects_commands_cross_identity_and_unbounded_payloads(payload: bytes) -> None:
    with pytest.raises(ValueError, match="health_lease_challenge_invalid"):
        parse_pending_challenge(
            payload,
            binding=HealthLeaseBinding("workspace-a", "device-a"),
            machine_installation_id="1" * 32,
            installation_generation="2" * 32,
        )


def test_cloud_transport_accepts_empty_204_without_creating_a_command_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = object.__new__(GuardCloudMachineHealthTransport)
    monkeypatch.setattr(transport, "_request", lambda *_args, **_kwargs: (204, b""))

    result = transport.poll_challenge(
        binding=HealthLeaseBinding("workspace-a", "device-a"),
        machine_installation_id="1" * 32,
        installation_generation="2" * 32,
    )

    assert result is None


def test_cloud_transport_rejects_body_on_no_content_challenge_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = object.__new__(GuardCloudMachineHealthTransport)
    monkeypatch.setattr(transport, "_request", lambda *_args, **_kwargs: (204, b"{}"))

    with pytest.raises(ValueError, match="health_lease_challenge_invalid"):
        transport.poll_challenge(
            binding=HealthLeaseBinding("workspace-a", "device-a"),
            machine_installation_id="1" * 32,
            installation_generation="2" * 32,
        )
