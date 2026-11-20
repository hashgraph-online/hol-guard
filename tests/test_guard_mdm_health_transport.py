from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm.health_lease_contract import HealthLeaseBinding
from codex_plugin_scanner.guard.mdm.health_transport import (
    GuardCloudMachineHealthTransport,
    parse_pending_challenge,
)
from codex_plugin_scanner.guard.runtime.cloud_bundle_sync import CloudResponseOversizedError


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


def test_cloud_transport_sends_through_the_native_raw_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.runtime import cloud_bundle_sync, runner

    sent: list[tuple[str, bytes | None, Path]] = []

    def raw_request(
        _auth_context, guard_home, *, url, body, timeout_seconds, retry_timeout_seconds, max_response_bytes
    ):
        assert max_response_bytes == 4096
        sent.append((url, body, guard_home))
        return 204, b""

    transport = object.__new__(GuardCloudMachineHealthTransport)
    transport._guard_home = tmp_path
    transport._store = object()
    monkeypatch.setattr(
        runner,
        "_resolve_guard_sync_auth_context",
        lambda _store: {"sync_url": "https://hol.test/api/guard/receipts/sync"},
    )
    monkeypatch.setattr(cloud_bundle_sync, "cloud_raw_request", raw_request)

    assert transport._request("GET", "/api/guard/runtime/machine-health/challenges/pending") == (204, b"")
    assert sent == [("https://hol.test/api/guard/runtime/machine-health/challenges/pending", None, tmp_path)]


def test_cloud_transport_reports_a_refusal_with_its_error_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.runtime import cloud_bundle_sync, runner

    def refused(*_args, url, **_kwargs):
        raise urllib.error.HTTPError(url, 409, "Conflict", Message(), io.BytesIO(b'{"code":"lease_conflict"}'))

    transport = object.__new__(GuardCloudMachineHealthTransport)
    transport._guard_home = tmp_path
    transport._store = object()
    monkeypatch.setattr(
        runner,
        "_resolve_guard_sync_auth_context",
        lambda _store: {"sync_url": "https://hol.test/api/guard/receipts/sync"},
    )
    monkeypatch.setattr(cloud_bundle_sync, "cloud_raw_request", refused)

    with pytest.raises(OSError, match="health_lease_delivery_http_409:lease_conflict"):
        transport._request("POST", "/api/guard/runtime/machine-health/leases", b"{}")


@pytest.mark.parametrize(
    ("failure", "reason"),
    (
        (CloudResponseOversizedError("too long"), "health_lease_delivery_response_oversized"),
        (RuntimeError("native runtime missing"), "health_lease_delivery_unavailable"),
    ),
)
def test_cloud_transport_names_native_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: RuntimeError,
    reason: str,
) -> None:
    from codex_plugin_scanner.guard.runtime import cloud_bundle_sync, runner

    def failed(*_args, **_kwargs):
        raise failure

    transport = object.__new__(GuardCloudMachineHealthTransport)
    transport._guard_home = tmp_path
    transport._store = object()
    monkeypatch.setattr(
        runner,
        "_resolve_guard_sync_auth_context",
        lambda _store: {"sync_url": "https://hol.test/api/guard/receipts/sync"},
    )
    monkeypatch.setattr(cloud_bundle_sync, "cloud_raw_request", failed)

    with pytest.raises(OSError, match=f"^{reason}$"):
        transport._request("GET", "/api/guard/runtime/machine-health/challenges/pending")
