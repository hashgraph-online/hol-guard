from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.mdm import user_health
from codex_plugin_scanner.guard.mdm.contracts import LocalIntegritySnapshot
from codex_plugin_scanner.guard.mdm.health_lease_ack import HealthLeaseAck
from codex_plugin_scanner.guard.mdm.health_lease_contract import HealthLeaseOutbox
from tests.guard_mdm_health_lease_support import snapshot

NOW = user_health.datetime(2026, 7, 19, 14, 0, tzinfo=user_health.timezone.utc)


class Transport:
    def __init__(self) -> None:
        self.registrations: list[bytes] = []
        self.outboxes: list[HealthLeaseOutbox] = []

    def register_key(self, payload: bytes) -> None:
        self.registrations.append(payload)

    def poll_challenge(self, **_kwargs: object) -> None:
        return None

    def deliver_lease(self, outbox: HealthLeaseOutbox) -> HealthLeaseAck:
        self.outboxes.append(outbox)
        claims = outbox.lease.claims
        return HealthLeaseAck(
            "accepted",
            claims.workspace_id,
            claims.device_id,
            claims.machine_installation_id,
            claims.installation_generation,
            claims.sequence,
            outbox.lease.digest,
            "2026-07-19T14:00:01.000Z",
        )


class FailingTransport(Transport):
    def deliver_lease(self, outbox: HealthLeaseOutbox) -> HealthLeaseAck:
        self.outboxes.append(outbox)
        raise ConnectionError("offline")


class ConcurrentTransport(Transport):
    def __init__(self) -> None:
        super().__init__()
        self.barrier = threading.Barrier(2)

    def deliver_lease(self, outbox: HealthLeaseOutbox) -> HealthLeaseAck:
        self.outboxes.append(outbox)
        self.barrier.wait(timeout=5)
        claims = outbox.lease.claims
        return HealthLeaseAck(
            "accepted",
            claims.workspace_id,
            claims.device_id,
            claims.machine_installation_id,
            claims.installation_generation,
            claims.sequence,
            outbox.lease.digest,
            "2026-07-19T14:00:01.000Z",
        )


@pytest.fixture
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / ".hol-guard"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(user_health, "GuardStore", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        user_health,
        "guard_review_oauth_metadata",
        lambda _store: SimpleNamespace(workspace_id="workspace-a", device_id="device-a"),
    )
    monkeypatch.setattr(
        user_health,
        "machine_integrity_snapshot",
        lambda: cast(LocalIntegritySnapshot, snapshot()),
    )
    return home


def test_user_health_requires_explicit_opt_in_and_reports_lower_assurance(guard_home: Path) -> None:
    assert user_health.user_health_status(guard_home) == {
        "schemaVersion": "hol-guard-user-health-status.v1",
        "configured": False,
        "enabled": False,
        "assuranceLevel": "user-managed",
        "sequence": 0,
        "pending": False,
    }
    with pytest.raises(PermissionError, match="user_health_opt_in_required"):
        user_health.run_user_health_cadence(guard_home, now=NOW, transport=Transport())

    configured = user_health.configure_user_health_leases(guard_home, enabled=True, now=NOW)
    assert configured["enabled"] is True
    assert configured["assuranceLevel"] == "user-managed"


def test_user_health_registers_and_delivers_signed_monotonic_leases(guard_home: Path) -> None:
    user_health.configure_user_health_leases(guard_home, enabled=True, now=NOW)
    transport = Transport()
    first = user_health.run_user_health_cadence(guard_home, now=NOW, transport=transport)
    second = user_health.run_user_health_cadence(
        guard_home,
        now=NOW.replace(minute=15),
        transport=transport,
    )

    assert first["sequence"] == 1
    assert second["sequence"] == 2
    assert first["assuranceLevel"] == "user-managed"
    assert len(transport.registrations) == 1
    registration = json.loads(transport.registrations[0])
    assert registration["deviceId"] == "device-a"
    assert registration["workspaceId"] == "workspace-a"
    first_snapshot = json.loads(transport.outboxes[0].snapshot_bytes)
    assert first_snapshot["assuranceLevel"] == "user-managed"
    assert first_snapshot["installOwner"] == "user"
    assert transport.outboxes[1].lease.claims.previous_lease_digest == transport.outboxes[0].lease.digest


def test_user_health_serializes_concurrent_cadence_runs(guard_home: Path) -> None:
    user_health.configure_user_health_leases(guard_home, enabled=True, now=NOW)
    transport = ConcurrentTransport()

    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(
            executor.map(
                lambda minute: user_health.run_user_health_cadence(
                    guard_home,
                    now=NOW.replace(minute=minute),
                    transport=transport,
                ),
                (0, 1),
            )
        )

    assert {report["sequence"] for report in reports} == {1}
    assert len({outbox.lease.digest for outbox in transport.outboxes}) == 1
    assert user_health.user_health_status(guard_home)["sequence"] == 1


def test_user_health_disable_preserves_continuity_but_stops_delivery(guard_home: Path) -> None:
    user_health.configure_user_health_leases(guard_home, enabled=True, now=NOW)
    user_health.run_user_health_cadence(guard_home, now=NOW, transport=Transport())
    status = user_health.configure_user_health_leases(guard_home, enabled=False, now=NOW)

    assert status["sequence"] == 1
    assert status["enabled"] is False
    with pytest.raises(PermissionError, match="user_health_opt_in_required"):
        user_health.run_user_health_cadence(guard_home, now=NOW, transport=Transport())


def test_user_health_retries_exact_pending_lease_after_transport_failure(guard_home: Path) -> None:
    user_health.configure_user_health_leases(guard_home, enabled=True, now=NOW)
    failed = FailingTransport()
    with pytest.raises(ConnectionError, match="offline"):
        user_health.run_user_health_cadence(guard_home, now=NOW, transport=failed)
    assert user_health.user_health_status(guard_home)["pending"] is True
    assert user_health.user_health_report_due(guard_home, now=NOW) is True

    recovered = Transport()
    result = user_health.run_user_health_cadence(
        guard_home,
        now=NOW.replace(minute=1),
        transport=recovered,
    )
    assert result["leaseDigest"] == failed.outboxes[0].lease.digest
    assert recovered.outboxes[0].canonical_bytes() == failed.outboxes[0].canonical_bytes()
    assert user_health.user_health_status(guard_home)["pending"] is False


def test_user_health_refreshes_expired_unaccepted_lease(guard_home: Path) -> None:
    user_health.configure_user_health_leases(guard_home, enabled=True, now=NOW)
    failed = FailingTransport()
    with pytest.raises(ConnectionError, match="offline"):
        user_health.run_user_health_cadence(guard_home, now=NOW, transport=failed)

    recovered = Transport()
    result = user_health.run_user_health_cadence(
        guard_home,
        now=NOW.replace(minute=16),
        transport=recovered,
    )

    assert result["sequence"] == 1
    assert recovered.outboxes[0].lease.digest != failed.outboxes[0].lease.digest
    assert recovered.outboxes[0].lease.claims.previous_lease_digest is None


def test_user_health_due_gate_is_bounded_and_cadenced(guard_home: Path) -> None:
    user_health.configure_user_health_leases(guard_home, enabled=True, now=NOW)
    assert user_health.user_health_report_due(guard_home, now=NOW.replace(minute=4)) is False
    assert user_health.user_health_report_due(guard_home, now=NOW.replace(minute=5)) is True
    with pytest.raises(ValueError, match="user_health_cadence_invalid"):
        user_health.user_health_report_due(guard_home, cadence_seconds=1)


def test_user_health_rejects_group_readable_or_symlinked_state(guard_home: Path) -> None:
    user_health.configure_user_health_leases(guard_home, enabled=True, now=NOW)
    state_path = guard_home / "user-health-state.json"
    state_path.chmod(0o644)
    with pytest.raises(PermissionError, match="user_health_state_acl_invalid"):
        user_health.user_health_status(guard_home)


def test_user_health_cli_exposes_explicit_status_surface(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["guard", "health-leases", "status", "--home", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schemaVersion"] == "hol-guard-user-health-status.v1"
    assert payload["enabled"] is False
    assert payload["assuranceLevel"] == "user-managed"
