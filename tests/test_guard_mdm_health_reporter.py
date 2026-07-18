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
from codex_plugin_scanner.guard.mdm.health_lease_contract import HealthLeaseBinding, HealthLeaseOutbox
from codex_plugin_scanner.guard.mdm.health_reporter import run_machine_health_cadence


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(root / "runtime", root / "state", root / "policy", root / "logs", root / "manifest")


def _policy(*, owner: str = "mdm", locked: bool = True) -> ManagedPolicyState:
    locks = frozenset({"selfProtection.workspaceId", "selfProtection.deviceId"}) if locked else frozenset()
    return ManagedPolicyState(
        "active",
        "native",
        ManagedPolicy(
            schema_version=MDM_POLICY_SCHEMA_VERSION,
            settings={"selfProtection": {"workspaceId": "workspace-a", "deviceId": "device-a"}},
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
        sequence=7,
        issued_at="2026-07-18T18:00:00Z",
        lease_expires_at="2026-07-18T18:15:00Z",
    )
    lease = SimpleNamespace(claims=claims, digest="3" * 64)
    return cast(HealthLeaseOutbox, SimpleNamespace(lease=lease))


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
    assert result == {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "health-report",
        "healthy": True,
        "state": "lease-ready",
        "reasonCodes": ["health_lease_ready"],
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": "1" * 32,
        "installationGeneration": "2" * 32,
        "sequence": 7,
        "issuedAt": "2026-07-18T18:00:00Z",
        "leaseExpiresAt": "2026-07-18T18:15:00Z",
        "leaseDigest": "3" * 64,
    }
    assert "signature" not in result
    assert "snapshot" not in result


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        (ManagedPolicyState("absent", "native", reason_code="managed_policy_absent"), "managed_policy_absent"),
        (_policy(locked=False), "health_reporter_binding_unlocked"),
        (_policy(owner="user"), "health_reporter_machine_management_required"),
    ],
)
def test_machine_cadence_fails_closed_without_managed_locked_binding(
    tmp_path: Path, state: ManagedPolicyState, reason: str
) -> None:
    with pytest.raises((OSError, PermissionError), match=reason):
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
