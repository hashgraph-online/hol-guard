from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm
from codex_plugin_scanner.guard.mdm.contracts import (
    MDM_POLICY_SCHEMA_VERSION,
    InstallOwner,
    MachinePaths,
    ManagedPolicy,
    ManagedPolicyState,
    ManagedUpdatePolicy,
)
from codex_plugin_scanner.guard.mdm.health_lease_ack import HealthLeaseAck
from codex_plugin_scanner.guard.mdm.health_lease_contract import (
    HealthLeaseBinding,
    HealthLeaseOutbox,
)
from codex_plugin_scanner.guard.mdm.health_reporter import run_machine_health_cadence
from codex_plugin_scanner.guard.mdm.protection_lease_contract import ProtectionLeaseChallenge


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(root / "runtime", root / "state", root / "policy", root / "logs", root / "manifest")


def _policy(
    *,
    owner: str = "mdm",
    locked: bool = True,
    workspace_id: str = "workspace-a",
    device_id: str = "device-a",
) -> ManagedPolicyState:
    locks = frozenset({"selfProtection.workspaceId", "selfProtection.deviceId"}) if locked else frozenset()
    return ManagedPolicyState(
        "active",
        "native",
        ManagedPolicy(
            schema_version=MDM_POLICY_SCHEMA_VERSION,
            settings={"selfProtection": {"workspaceId": workspace_id, "deviceId": device_id}},
            locked_settings=locks,
            update=ManagedUpdatePolicy(owner=cast(InstallOwner, owner)),
        ),
        reason_code="managed_policy_active",
    )


def _outbox() -> HealthLeaseOutbox:
    claims = SimpleNamespace(
        workspace_id="workspace-a",
        device_id="device-a",
        machine_installation_id="1" * 32,
        installation_generation="2" * 32,
        signing_key_id="A" * 43,
        sequence=7,
        issued_at="2026-07-18T18:00:00Z",
        lease_expires_at="2026-07-18T18:15:00Z",
    )
    lease = SimpleNamespace(claims=claims, digest="3" * 64)
    snapshot = json.dumps(
        {"healthy": True, "components": {"deviceKey": {"state": "healthy"}}},
        separators=(",", ":"),
    ).encode()
    return cast(HealthLeaseOutbox, SimpleNamespace(lease=lease, snapshot_bytes=snapshot))


def test_machine_cadence_uses_only_locked_machine_policy_binding(tmp_path: Path) -> None:
    calls: list[tuple[MachinePaths, HealthLeaseBinding, str]] = []

    def issue(paths: MachinePaths, binding: HealthLeaseBinding, *, system_name: str) -> HealthLeaseOutbox:
        calls.append((paths, binding, system_name))
        return _outbox()

    paths = _paths(tmp_path)
    result = run_machine_health_cadence(
        paths=paths,
        system_name="Darwin",
        policy_loader=lambda **_kwargs: _policy(),
        lease_issuer=issue,
    )

    assert calls == [(paths, HealthLeaseBinding("workspace-a", "device-a"), "Darwin")]
    assert result["state"] == "lease-ready"
    assert result["reasonCodes"] == ["health_lease_ready"]
    assert result["localEnforcementHealthy"] is True
    assert result["workspaceId"] == "workspace-a"
    assert result["deviceId"] == "device-a"
    assert result["sequence"] == 7
    assert result["leaseDigest"] == "3" * 64
    metrics = cast(dict[str, object], result["metrics"])
    assert metrics == {
        "snapshotDurationMs": 0,
        "leaseAgeSeconds": metrics["leaseAgeSeconds"],
        "deliveryLatencyMs": None,
        "rejectionReason": None,
        "queueDepth": 1,
        "keyStorageHealth": "healthy",
    }
    assert "signature" not in result
    assert "snapshot" not in result


def test_machine_cadence_delivers_then_answers_only_purpose_bound_challenge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _outbox()
    second = _outbox()
    second.lease.claims.sequence = 8
    delivered: list[HealthLeaseOutbox] = []
    issued_challenges: list[ProtectionLeaseChallenge | None] = []
    acknowledgements: list[HealthLeaseAck] = []
    challenge = ProtectionLeaseChallenge("challenge-a", "2026-07-18T17:59:30Z", "n" * 43, 120)

    class Transport:
        def register_key(self, _payload: bytes) -> None:
            return None

        def deliver_lease(self, outbox: HealthLeaseOutbox) -> HealthLeaseAck:
            delivered.append(outbox)
            claims = outbox.lease.claims
            return HealthLeaseAck(
                "accepted",
                claims.workspace_id,
                claims.device_id,
                claims.machine_installation_id,
                claims.installation_generation,
                claims.sequence,
                outbox.lease.digest,
                "2026-07-18T18:00:01.000Z",
            )

        def poll_challenge(self, **_kwargs: object) -> ProtectionLeaseChallenge:
            return challenge

    def issue(
        *_args: object,
        challenge: ProtectionLeaseChallenge | None = None,
        **_kwargs: object,
    ) -> HealthLeaseOutbox:
        issued_challenges.append(challenge)
        return first if challenge is None else second

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.health_reporter.build_machine_health_key_registration",
        lambda *_args, **_kwargs: b"registration",
    )

    result = run_machine_health_cadence(
        paths=_paths(tmp_path),
        system_name="Darwin",
        policy_loader=lambda **_kwargs: _policy(),
        lease_issuer=issue,
        lease_acknowledger=lambda _paths, _binding, ack, **_kwargs: acknowledgements.append(HealthLeaseAck.parse(ack)),
        transport=Transport(),
    )

    assert issued_challenges == [None, challenge]
    assert delivered == [first, second]
    assert len(acknowledgements) == 2
    assert result["state"] == "lease-delivered"
    assert result["challengeResponded"] is True
    assert cast(dict[str, object], result["metrics"])["queueDepth"] == 0


def test_machine_cadence_registers_the_recovered_lease_signing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recovered = _outbox()
    recovered.lease.claims.signing_key_id = "p" * 43
    registered_key_ids: list[str | None] = []

    class Transport:
        def register_key(self, _payload: bytes) -> None:
            return None

        def deliver_lease(self, outbox: HealthLeaseOutbox) -> HealthLeaseAck:
            claims = outbox.lease.claims
            return HealthLeaseAck(
                "accepted",
                claims.workspace_id,
                claims.device_id,
                claims.machine_installation_id,
                claims.installation_generation,
                claims.sequence,
                outbox.lease.digest,
                "2026-07-18T18:00:01.000Z",
            )

        def poll_challenge(self, **_kwargs: object) -> None:
            return None

    def registration(*_args: object, key_id: str | None = None, **_kwargs: object) -> bytes:
        registered_key_ids.append(key_id)
        return b"registration"

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.health_reporter.build_machine_health_key_registration",
        registration,
    )

    run_machine_health_cadence(
        paths=_paths(tmp_path),
        system_name="Darwin",
        policy_loader=lambda **_kwargs: _policy(),
        lease_issuer=lambda *_args, **_kwargs: recovered,
        lease_acknowledger=lambda _paths, _binding, ack, **_kwargs: ack,
        transport=Transport(),
    )

    assert registered_key_ids == ["p" * 43]


def test_delivery_failure_is_exposed_without_weakening_local_enforcement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class OfflineTransport:
        def register_key(self, _payload: bytes) -> None:
            return None

        def deliver_lease(self, _outbox: HealthLeaseOutbox) -> HealthLeaseAck:
            raise TimeoutError("cloud delivery timed out")

        def poll_challenge(self, **_kwargs: object) -> None:
            pytest.fail("challenge polling must not run after failed delivery")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.health_reporter.build_machine_health_key_registration",
        lambda *_args, **_kwargs: b"registration",
    )

    result = run_machine_health_cadence(
        paths=_paths(tmp_path),
        system_name="Darwin",
        policy_loader=lambda **_kwargs: _policy(),
        lease_issuer=lambda *_args, **_kwargs: _outbox(),
        transport=OfflineTransport(),
    )

    assert result["healthy"] is True
    assert result["localEnforcementHealthy"] is True
    assert result["state"] == "delivery-failed"
    assert result["reasonCodes"] == ["health_lease_delivery_failed"]
    assert cast(dict[str, object], result["metrics"])["rejectionReason"] == "cloud delivery timed out"


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        (ManagedPolicyState("absent", "native", reason_code="managed_policy_absent"), "managed_policy_absent"),
        (_policy(locked=False), "health_reporter_binding_unlocked"),
        (_policy(owner="user"), "health_reporter_machine_management_required"),
        (_policy(workspace_id="   "), "health_reporter_binding_invalid"),
    ],
)
def test_machine_cadence_fails_closed_without_managed_locked_binding(
    tmp_path: Path, state: ManagedPolicyState, reason: str
) -> None:
    with pytest.raises((OSError, PermissionError, ValueError), match=reason):
        run_machine_health_cadence(
            paths=_paths(tmp_path),
            system_name="Darwin",
            policy_loader=lambda **_kwargs: state,
            lease_issuer=lambda *_args, **_kwargs: pytest.fail("lease issuer must not run"),
        )


def test_health_report_cli_is_machine_only_and_emits_bounded_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    expected = {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "health-report",
        "healthy": True,
        "reasonCodes": ["health_lease_ready"],
    }
    monkeypatch.setattr(commands_dispatch_mdm, "run_machine_health_cadence", lambda: expected)

    assert cli.main(["mdm", "health-report", "--scope", "machine", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == expected
