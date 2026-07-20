from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import get_args

import pytest

from codex_plugin_scanner.guard.mdm import integrity
from codex_plugin_scanner.guard.mdm.acl import OwnershipAclVerification
from codex_plugin_scanner.guard.mdm.contracts import (
    IntegrityReasonCode,
    KeyProtectionStatus,
    MachinePaths,
    ManagedPolicyState,
    SupervisorStatus,
)
from codex_plugin_scanner.guard.mdm.manifest import ManifestVerification


@pytest.fixture(autouse=True)
def _isolate_machine_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        integrity,
        "load_managed_policy",
        lambda **_kwargs: ManagedPolicyState("absent", "native", reason_code="managed_policy_absent"),
    )
    monkeypatch.setattr(
        integrity,
        "verify_protected_ownership_and_acl",
        lambda _paths: OwnershipAclVerification("unsupported", "ownership_acl_verification_unavailable", ()),
    )
    monkeypatch.setattr(
        integrity,
        "verify_machine_supervisor",
        lambda _paths: SupervisorStatus("unsupported", "supervisor_verification_unavailable"),
    )
    monkeypatch.setattr(
        integrity,
        "verify_machine_device_key",
        lambda _paths: KeyProtectionStatus("unsupported", "unavailable", "device_key_verification_unavailable"),
    )


def _paths(root: Path) -> MachinePaths:
    runtime = root / "runtime"
    return MachinePaths(runtime, root / "state", root / "policy.json", root / "logs", runtime / "release-manifest.json")


def test_snapshot_schema_reason_codes_match_runtime_contract() -> None:
    schema_path = Path(__file__).parents[1] / "docs" / "guard" / "schemas" / "local-integrity-snapshot-v1.schema.json"
    schema = json.loads(schema_path.read_text())
    assert set(schema["$defs"]["reasonCode"]["enum"]) == set(get_args(IntegrityReasonCode))


def test_managed_policy_source_tamper_reason_is_preserved() -> None:
    component = integrity._component("tampered", "managed_policy_source_tampered")

    assert component.state == "tampered"
    assert component.reason_code == "managed_policy_source_tampered"


@pytest.mark.parametrize(
    ("supervisor", "expected"),
    [
        (SupervisorStatus("running", "supervisor_running"), ("healthy", "daemon_running")),
        (SupervisorStatus("absent", "supervisor_absent"), ("absent", "daemon_absent")),
        (SupervisorStatus("stopped", "supervisor_stopped"), ("degraded", "daemon_stopped")),
        (SupervisorStatus("disabled", "supervisor_disabled"), ("tampered", "daemon_disabled")),
        (
            SupervisorStatus("unknown", "supervisor_registration_invalid"),
            ("tampered", "daemon_registration_invalid"),
        ),
        (
            SupervisorStatus("unknown", "supervisor_executable_mismatch"),
            ("tampered", "daemon_registration_invalid"),
        ),
        (
            SupervisorStatus("unknown", "supervisor_schedule_invalid"),
            ("tampered", "daemon_registration_invalid"),
        ),
        (SupervisorStatus("unknown", "supervisor_probe_failed"), ("unknown", "daemon_probe_failed")),
    ],
)
def test_daemon_component_has_stable_supervisor_reason_codes(
    supervisor: SupervisorStatus, expected: tuple[str, str]
) -> None:
    component = integrity._daemon_component(supervisor)
    assert (component.state, component.reason_code) == expected


def test_snapshot_projects_disabled_supervisor_as_daemon_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(
        integrity,
        "verify_machine_supervisor",
        lambda _paths: SupervisorStatus("disabled", "supervisor_disabled"),
    )

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["components"]["daemon"] == {
        "state": "tampered",
        "healthy": False,
        "reasonCode": "daemon_disabled",
    }


def test_snapshot_detects_shadowed_command_without_exposing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    paths.runtime_root.mkdir(parents=True)
    shadow = tmp_path / "user-bin" / "hol-guard"
    shadow.parent.mkdir()
    shadow.write_text("shadow")
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(shutil, "which", lambda _command: str(shadow))

    snapshot = integrity.machine_integrity_snapshot()
    serialized = json.dumps(snapshot)

    assert snapshot["components"]["commandShadowing"] == {
        "state": "tampered",
        "healthy": False,
        "reasonCode": "command_shadowing_detected",
    }
    assert str(shadow) not in serialized


def test_snapshot_detects_shadow_when_runtime_root_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shadow = tmp_path / "user-bin" / "hol-guard"
    shadow.parent.mkdir()
    shadow.write_text("shadow")
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda _command: str(shadow))

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["components"]["commandShadowing"] == {
        "state": "tampered",
        "healthy": False,
        "reasonCode": "command_shadowing_detected",
    }


def test_snapshot_reports_no_shadow_when_entrypoint_is_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda _command: None)

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["components"]["commandShadowing"] == {
        "state": "healthy",
        "healthy": True,
        "reasonCode": "command_shadowing_absent",
    }


def test_snapshot_fails_honest_when_entrypoint_disappears(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = tmp_path / "missing" / "hol-guard"
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda _command: str(missing))

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["components"]["commandShadowing"] == {
        "state": "unknown",
        "healthy": False,
        "reasonCode": "command_shadowing_probe_failed",
    }


def test_snapshot_accepts_runtime_owned_command_entrypoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _paths(tmp_path)
    executable = paths.runtime_root / "hol-guard" / "hol-guard"
    executable.parent.mkdir(parents=True)
    executable.write_text("runtime")
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(integrity.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(shutil, "which", lambda _command: str(executable))

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["components"]["commandShadowing"] == {
        "state": "healthy",
        "healthy": True,
        "reasonCode": "command_shadowing_trusted",
    }


def test_snapshot_rejects_noncanonical_executable_inside_runtime_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    executable = paths.runtime_root / "old" / "hol-guard"
    executable.parent.mkdir(parents=True)
    executable.write_text("old runtime")
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(integrity.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(shutil, "which", lambda _command: str(executable))

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["components"]["commandShadowing"] == {
        "state": "tampered",
        "healthy": False,
        "reasonCode": "command_shadowing_detected",
    }


def test_snapshot_projects_downgrade_into_update_component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(
        integrity,
        "verify_release_manifest",
        lambda *_args, **_kwargs: ManifestVerification("tampered", "release_manifest_version_rollback"),
    )

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["components"]["update"] == {
        "state": "tampered",
        "healthy": False,
        "reasonCode": "release_manifest_version_rollback",
    }


def test_snapshot_accepts_verified_update_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(
        integrity,
        "verify_release_manifest",
        lambda *_args, **_kwargs: ManifestVerification("healthy", "release_manifest_valid", "3.1.0a2", "build-1"),
    )

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["components"]["update"] == {
        "state": "healthy",
        "healthy": True,
        "reasonCode": "update_version_allowed",
    }
