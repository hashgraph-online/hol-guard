from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm
from codex_plugin_scanner.guard.mdm import integrity
from codex_plugin_scanner.guard.mdm.contracts import (
    MDM_POLICY_SCHEMA_VERSION,
    MachinePaths,
    ManagedPolicy,
    ManagedPolicyState,
    ManagedUpdatePolicy,
)
from codex_plugin_scanner.guard.mdm.manifest import ManifestVerification
from codex_plugin_scanner.guard.mdm.native import NativeInstallVerification
from codex_plugin_scanner.version import __version__


@pytest.fixture(autouse=True)
def _isolate_host_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        integrity,
        "load_managed_policy",
        lambda **_kwargs: ManagedPolicyState("absent", "native", reason_code="managed_policy_absent"),
    )


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def test_snapshot_is_fail_honest_and_schema_valid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    snapshot = integrity.machine_integrity_snapshot()

    schema_path = Path(__file__).parents[1] / "docs" / "guard" / "schemas" / "local-integrity-snapshot-v1.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator(schema).validate(snapshot)

    assert snapshot["healthy"] is False
    assert snapshot["assuranceLevel"] == "user-managed"
    components = snapshot["components"]
    assert isinstance(components, dict)
    assert components["ownershipAndAcl"]["state"] == "unsupported"
    assert components["supervisor"]["state"] == "unsupported"
    assert components["deviceKey"]["level"] == "unavailable"
    assert snapshot["reasonCodes"] == sorted(snapshot["reasonCodes"])

    contradictory = json.loads(json.dumps(snapshot))
    contradictory["components"]["manifest"]["healthy"] = True
    assert list(Draft202012Validator(schema).iter_errors(contradictory))

    contradictory = json.loads(json.dumps(snapshot))
    contradictory["healthy"] = True
    contradictory["reasonCodes"] = []
    contradictory["remediationClass"] = "none"
    assert list(Draft202012Validator(schema).iter_errors(contradictory))


def test_snapshot_never_upgrades_incomplete_managed_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(
        integrity,
        "verify_release_manifest",
        lambda *_args, **_kwargs: ManifestVerification("healthy", "release_manifest_valid", "3.1.0a1", "b1"),
    )
    monkeypatch.setattr(
        integrity,
        "verify_native_install",
        lambda *_args, **_kwargs: NativeInstallVerification(
            "healthy", "native_install_valid", "org.hol.guard", "valid", "3.1.0a1"
        ),
    )
    monkeypatch.setattr(
        integrity,
        "load_managed_policy",
        lambda **_kwargs: ManagedPolicyState("absent", "native", reason_code="managed_policy_absent"),
    )

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["assuranceLevel"] == "user-managed"
    assert snapshot["healthy"] is False
    assert snapshot["remediationClass"] == "user-reinstall"
    assert snapshot["product"]["version"] == "3.1.0a1"


def test_snapshot_preserves_cached_managed_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    managed_policy = ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings={},
        locked_settings=frozenset(),
        update=ManagedUpdatePolicy(owner="mdm"),
    )
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(
        integrity,
        "load_managed_policy",
        lambda **_kwargs: ManagedPolicyState(
            "active",
            "native-cache",
            policy=managed_policy,
            reason_code="managed_policy_profile_removed_cached",
        ),
    )

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["installOwner"] == "mdm"
    assert snapshot["assuranceLevel"] == "mdm-managed-unverified"
    assert snapshot["remediationClass"] == "mdm-repair"
    assert "managed_policy_profile_removed_cached" in snapshot["reasonCodes"]


def test_snapshot_normalizes_probe_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(integrity, "verify_release_manifest", lambda *_args, **_kwargs: 1 / 0)
    monkeypatch.setattr(integrity, "verify_native_install", lambda *_args, **_kwargs: 1 / 0)
    monkeypatch.setattr(integrity, "load_managed_policy", lambda **_kwargs: 1 / 0)

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["schemaVersion"] == "local-integrity-snapshot.v1"
    assert snapshot["healthy"] is False
    assert "release_manifest_probe_failed" in snapshot["reasonCodes"]
    assert "native_install_probe_failed" in snapshot["reasonCodes"]
    assert "managed_policy_probe_failed" in snapshot["reasonCodes"]
    assert snapshot["installOwner"] == "mdm"
    assert snapshot["components"]["managedPolicy"]["state"] == "degraded"


def test_snapshot_loads_policy_without_writing_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_load_policy(**kwargs: object) -> ManagedPolicyState:
        calls.append(kwargs)
        return ManagedPolicyState("absent", "native", reason_code="managed_policy_absent")

    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(integrity, "load_managed_policy", fake_load_policy)

    integrity.machine_integrity_snapshot()

    assert calls == [{"write_cache": False}]


def test_running_supervisor_counts_as_healthy_for_remediation() -> None:
    assert integrity._remediation_class("mdm-managed", True, ["healthy", "running"]) == "none"


def test_snapshot_does_not_promote_unverified_manifest_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    monkeypatch.setattr(
        integrity,
        "verify_release_manifest",
        lambda *_args, **_kwargs: ManifestVerification(
            "tampered",
            "release_manifest_unsigned",
            "999.0.0",
            "attacker-build",
        ),
    )
    monkeypatch.setattr(
        integrity,
        "verify_native_install",
        lambda *_args, **_kwargs: NativeInstallVerification(
            "absent", "native_package_receipt_absent", "org.hol.guard", "unknown"
        ),
    )

    snapshot = integrity.machine_integrity_snapshot()

    assert snapshot["product"]["version"] == __version__
    assert snapshot["product"]["buildId"] is None


def test_integrity_snapshot_cli_is_read_only_and_redacted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: _paths(tmp_path))
    exit_code = cli.main(["mdm", "integrity-snapshot", "--scope", "machine", "--json"])
    payload = json.loads(capsys.readouterr().out)
    serialized = json.dumps(payload, sort_keys=True)

    assert exit_code == 1
    assert payload["schemaVersion"] == "local-integrity-snapshot.v1"
    assert str(tmp_path) not in serialized
    assert "home" not in serialized.casefold()
    assert "username" not in serialized.casefold()
    assert list(tmp_path.iterdir()) == []


def test_snapshot_never_serializes_release_verification_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _paths(tmp_path)
    paths.runtime_root.mkdir(parents=True)
    public_key = base64.b64encode(b"public-verification-key").decode()
    (paths.runtime_root / "release-trusted-keys.json").write_text(json.dumps({"release-1": public_key}))
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: paths)

    snapshot = integrity.machine_integrity_snapshot()
    serialized = json.dumps(snapshot, sort_keys=True)

    assert public_key not in serialized
    assert "release-1" not in serialized


def test_integrity_snapshot_cli_does_not_accept_machine_path_override(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "mdm",
                "integrity-snapshot",
                "--scope",
                "machine",
                "--machine-root",
                str(tmp_path),
                "--json",
            ]
        )
    assert error.value.code == 2


def test_integrity_snapshot_cli_requires_json() -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["mdm", "integrity-snapshot", "--scope", "machine"])
    assert error.value.code == 2


def test_cli_dispatch_emits_snapshot_contract(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = {
        "schemaVersion": "local-integrity-snapshot.v1",
        "healthy": False,
        "reasonCodes": ["supervisor_verification_unavailable"],
    }
    monkeypatch.setattr(commands_dispatch_mdm, "machine_integrity_snapshot", lambda: expected)

    exit_code = cli.main(["mdm", "integrity-snapshot", "--scope", "machine", "--json"])

    assert exit_code == 1
    assert json.loads(capsys.readouterr().out) == expected
