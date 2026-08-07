from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm import health_lease
from codex_plugin_scanner.guard.mdm.health_lease_ack import HealthLeaseAck
from codex_plugin_scanner.guard.mdm.health_lease_contract import (
    HealthLeaseBinding,
    HealthLeaseOutbox,
    canonical_json_bytes,
)
from tests.guard_mdm_health_lease_support import NOW, prepare, signer, snapshot
from tests.guard_mdm_health_lease_support import paths as machine_paths


def _ack(outbox: HealthLeaseOutbox, **updates: object) -> bytes:
    claims = outbox.lease.claims
    payload: dict[str, object] = {
        "schemaVersion": "hol-guard-health-lease-ack.v1",
        "status": "accepted",
        "workspaceId": claims.workspace_id,
        "deviceId": claims.device_id,
        "machineInstallationId": claims.machine_installation_id,
        "installationGeneration": claims.installation_generation,
        "sequence": claims.sequence,
        "leaseDigest": outbox.lease.digest,
        "receivedAt": "2026-07-18T14:00:01.000Z",
    }
    payload.update(updates)
    return canonical_json_bytes(payload)


def test_windows_atomic_create_omits_unsupported_follow_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = machine_paths(tmp_path)
    paths.state_root.mkdir(parents=True)
    linked: list[tuple[Path, Path]] = []

    def link(source: Path, target: Path) -> None:
        linked.append((source, target))

    monkeypatch.setattr(health_lease.os, "name", "nt")
    monkeypatch.setattr(health_lease.os, "link", link)

    target = paths.state_root / "pending.json"
    health_lease._atomic_create(paths, target, b"payload", conflict_reason="conflict")

    assert len(linked) == 1
    assert linked[0][1] == target


def test_authenticated_ack_retires_one_item_and_advances_exact_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, private, _key_generation = prepare(tmp_path, monkeypatch)
    first = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=NOW,
        system_name="Darwin",
        snapshot_factory=snapshot,
        signer=signer(private),
    )

    ack = health_lease.acknowledge_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        _ack(first),
        system_name="Darwin",
    )

    assert isinstance(ack, HealthLeaseAck)
    assert health_lease.load_pending_health_lease(paths) is None
    assert (paths.state_root / "health-lease-ack.json").read_bytes() == ack.canonical_bytes()

    second = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=NOW + timedelta(minutes=1),
        system_name="Darwin",
        snapshot_factory=lambda: snapshot(1, first.lease.digest),
        signer=signer(private),
    )
    assert second.lease.claims.sequence == 2
    assert second.lease.claims.previous_lease_digest == first.lease.digest
    assert second.lease.claims.previous_lease_key_id is None
    assert second.lease.claims.signing_key_id == first.lease.claims.signing_key_id


def test_replayed_ack_is_idempotent_after_retirement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths, private, _key_generation = prepare(tmp_path, monkeypatch)
    pending = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=NOW,
        system_name="Darwin",
        snapshot_factory=snapshot,
        signer=signer(private),
    )
    payload = _ack(pending, status="replayed")

    first = health_lease.acknowledge_pending_health_lease(
        paths, HealthLeaseBinding("workspace-a", "device-a"), payload, system_name="Darwin"
    )
    second = health_lease.acknowledge_pending_health_lease(
        paths, HealthLeaseBinding("workspace-a", "device-a"), payload, system_name="Darwin"
    )

    assert first == second
    assert health_lease.load_pending_health_lease(paths) is None
    with pytest.raises(OSError, match="health_lease_outbox_absent"):
        health_lease.acknowledge_pending_health_lease(
            paths, HealthLeaseBinding("workspace-b", "device-a"), payload, system_name="Darwin"
        )


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"workspaceId": "workspace-b"}, "health_lease_ack_conflict"),
        ({"deviceId": "device-b"}, "health_lease_ack_conflict"),
        ({"sequence": 2}, "health_lease_ack_conflict"),
        ({"leaseDigest": "f" * 64}, "health_lease_ack_conflict"),
        ({"receivedAt": "2026-07-18T14:15:00.000Z"}, "health_lease_ack_stale"),
    ],
)
def test_invalid_ack_cannot_retire_pending_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    updates: dict[str, object],
    reason: str,
) -> None:
    paths, private, _key_generation = prepare(tmp_path, monkeypatch)
    pending = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=NOW,
        system_name="Darwin",
        snapshot_factory=snapshot,
        signer=signer(private),
    )
    before = (paths.state_root / "health-lease-outbox.json").read_bytes()

    with pytest.raises(OSError, match=reason):
        health_lease.acknowledge_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-a", "device-a"),
            _ack(pending, **updates),
            system_name="Darwin",
        )

    assert (paths.state_root / "health-lease-outbox.json").read_bytes() == before
    assert not (paths.state_root / "health-lease-ack.json").exists()


def test_ack_durable_crash_recovers_without_backfill(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths, private, _key_generation = prepare(tmp_path, monkeypatch)
    first = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=NOW,
        system_name="Darwin",
        snapshot_factory=snapshot,
        signer=signer(private),
    )

    def crash(stage: str) -> None:
        assert stage == "ack-durable"
        raise RuntimeError("simulated-crash")

    with pytest.raises(RuntimeError, match="simulated-crash"):
        health_lease.acknowledge_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-a", "device-a"),
            _ack(first),
            system_name="Darwin",
            crash_hook=crash,
        )
    assert health_lease.load_pending_health_lease(paths) == first

    second = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=NOW + timedelta(minutes=16),
        system_name="Darwin",
        snapshot_factory=lambda: snapshot(1, first.lease.digest),
        signer=signer(private),
    )

    assert second.lease.claims.sequence == 2
    assert second.lease.claims.issued_at == "2026-07-18T14:16:00Z"
    assert second.lease.claims.previous_lease_digest == first.lease.digest


def test_symlink_ack_marker_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths, private, _key_generation = prepare(tmp_path, monkeypatch)
    health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=NOW,
        system_name="Darwin",
        snapshot_factory=snapshot,
        signer=signer(private),
    )
    target = tmp_path / "attacker-ack"
    target.write_text("{}", encoding="utf-8")
    (paths.state_root / "health-lease-ack.json").symlink_to(target)

    with pytest.raises(PermissionError, match="health_lease_ack_acl_invalid"):
        health_lease.issue_or_load_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-a", "device-a"),
            now=NOW + timedelta(seconds=1),
            system_name="Darwin",
        )
