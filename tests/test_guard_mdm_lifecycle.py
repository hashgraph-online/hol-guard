from __future__ import annotations

import base64
import hashlib
import json
import platform
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.mdm import lifecycle, removal
from codex_plugin_scanner.guard.mdm.contracts import (
    MDM_STATUS_SCHEMA_VERSION,
    MachinePaths,
)

MACHINE_INSTALLATION_ID = "1" * 32
INSTALLATION_GENERATION = "2" * 32


def _machine_paths(root: Path) -> MachinePaths:
    return MachinePaths(root / "runtime", root / "state", None, root / "logs", root / "manifest")


def _patch_machine_paths(monkeypatch: pytest.MonkeyPatch, paths: MachinePaths) -> None:
    monkeypatch.setattr(removal, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(lifecycle, "default_machine_paths", lambda: paths)


def _write_removal_authorization(root: Path, home: Path, *, generation: str = INSTALLATION_GENERATION) -> Path:
    now = datetime.now(timezone.utc)
    token = root / "token.json"
    token.write_text(
        json.dumps(
            {
                "actor": "mdm-admin@example.test",
                "expiresAt": (now + timedelta(minutes=2)).isoformat(),
                "home": str(home),
                "installationGeneration": generation,
                "issuedAt": now.isoformat(),
                "machineInstallationId": MACHINE_INSTALLATION_ID,
                "nonce": "unique-removal-nonce",
                "operation": "deactivate",
                "reason": "approved device retirement",
                "user": "developer",
            }
        )
    )
    return token


def _write_signed_runtime(runtime: Path, key: Ed25519PrivateKey) -> None:
    runtime.mkdir()
    executable = runtime / "hol-guard"
    executable.write_bytes(b"runtime")
    payload: dict[str, object] = {
        "schemaVersion": "hol-guard-release-manifest.v1",
        "version": "3.1.0a1",
        "buildId": "build-1",
        "sourceCommit": "a" * 40,
        "platform": "macos",
        "architecture": platform.machine().lower(),
        "policySchemaVersion": "hol-guard-mdm-policy.v1",
        "installerIdentity": "org.hol.guard",
        "files": [{"path": "hol-guard", "sha256": hashlib.sha256(b"runtime").hexdigest()}],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    payload["signature"] = {
        "keyId": "release-1",
        "value": base64.b64encode(key.sign(canonical)).decode(),
    }
    (runtime / "release-manifest.json").write_text(json.dumps(payload))


def test_user_status_does_not_conflate_machine_installation(tmp_path: Path) -> None:
    payload = lifecycle.user_status(tmp_path)
    assert payload["schemaVersion"] == MDM_STATUS_SCHEMA_VERSION
    assert payload["scope"] == "user"
    assert payload["state"] == "absent"
    assert payload["healthy"] is False


def test_machine_status_uses_external_managed_release_key(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    key = Ed25519PrivateKey.generate()
    _write_signed_runtime(runtime, key)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "schemaVersion": "hol-guard-mdm-policy.v1",
                "integrityTrust": {"releasePublicKeys": {"release-1": base64.b64encode(public).decode()}},
            }
        )
    )

    payload = lifecycle.machine_status(machine_root=runtime, policy_path=policy)

    assert payload["healthy"] is True
    assert payload["state"] == "protected"


def test_machine_status_ignores_circular_runtime_keyring(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    key = Ed25519PrivateKey.generate()
    _write_signed_runtime(runtime, key)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (runtime / "release-trusted-keys.json").write_text(json.dumps({"release-1": base64.b64encode(public).decode()}))

    payload = lifecycle.machine_status(machine_root=runtime, policy_path=tmp_path / "missing-policy.json")

    assert payload["healthy"] is False
    assert payload["manifest"]["reasonCode"] == "release_manifest_trust_anchor_absent"


def test_user_home_must_be_absolute_and_exist(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mdm_home_must_be_absolute"):
        lifecycle.validate_user_home("relative")
    with pytest.raises(ValueError, match="mdm_home_not_found"):
        lifecycle.validate_user_home(str(tmp_path / "missing"))


def test_activation_is_idempotent_and_writes_user_only_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append(command)
        return {"managed_installs": []}

    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)
    first = lifecycle.activate_user(tmp_path, "developer")
    second = lifecycle.repair_user(tmp_path, "developer")
    marker = tmp_path / ".hol-guard" / "mdm-activation.json"

    assert calls == ["install", "install"]
    assert first["operation"] == "activate"
    assert second["operation"] == "repair"
    assert json.loads(marker.read_text())["user"] == "developer"
    assert marker.stat().st_mode & 0o077 == 0


def test_deactivation_restores_integrations_and_removes_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()
    (guard_home / "mdm-activation.json").write_text("{}")
    commands: list[str] = []
    unregistered: list[tuple[MachinePaths, Path]] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        return {"managed_installs": []}

    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)
    monkeypatch.setattr(
        lifecycle,
        "unregister_user_harnesses",
        lambda machine_paths, home: unregistered.append((machine_paths, home)),
    )
    monkeypatch.setattr(removal, "_authorization_owner_is_trusted", lambda _metadata: True)
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: True)
    monkeypatch.setattr(removal, "_active_binding", lambda _paths: (MACHINE_INSTALLATION_ID, INSTALLATION_GENERATION))
    paths = _machine_paths(tmp_path)
    _patch_machine_paths(monkeypatch, paths)
    authorization_root = paths.state_root / "removal-authorizations"
    authorization_root.mkdir(parents=True)
    token = _write_removal_authorization(authorization_root, tmp_path)
    payload = lifecycle.deactivate_user(
        tmp_path,
        user="developer",
        authorization_file=token,
    )

    assert commands == ["uninstall"]
    assert unregistered == [(paths, tmp_path)]
    assert payload["operation"] == "deactivate"
    assert payload["installationGeneration"] == INSTALLATION_GENERATION
    assert not (guard_home / "mdm-activation.json").exists()
    tombstones = list((paths.state_root / "removal-tombstones").glob("*.json"))
    assert len(tombstones) == 1
    tombstone = json.loads(tombstones[0].read_text())
    assert tombstone["status"] == "completed"
    assert [event["status"] for event in tombstone["events"]] == ["started", "completed"]
    assert tombstone["installationGeneration"] == INSTALLATION_GENERATION
    assert "home" not in tombstone
    assert "user" not in tombstone
    assert "nonce" not in tombstone
    lifecycle.activate_user(tmp_path, "developer")
    assert commands == ["uninstall", "install"]
    assert tombstones[0].is_file()


def test_deactivation_requires_machine_authorization(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="mdm_removal_authorization_required"):
        lifecycle.deactivate_user(tmp_path, user="developer")


def test_failed_deactivation_consumes_authorization_and_preserves_failure_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()
    paths = _machine_paths(tmp_path)
    _patch_machine_paths(monkeypatch, paths)
    authorization_root = paths.state_root / "removal-authorizations"
    authorization_root.mkdir(parents=True)
    token = _write_removal_authorization(authorization_root, tmp_path)
    monkeypatch.setattr(removal, "_authorization_owner_is_trusted", lambda _metadata: True)
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: True)
    monkeypatch.setattr(removal, "_active_binding", lambda _paths: (MACHINE_INSTALLATION_ID, INSTALLATION_GENERATION))

    def fail_install(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise OSError("uninstall failed")

    monkeypatch.setattr(lifecycle, "apply_managed_install", fail_install)

    with pytest.raises(OSError, match="uninstall failed"):
        lifecycle.deactivate_user(
            tmp_path,
            user="developer",
            authorization_file=token,
        )

    assert not token.exists()
    tombstones = list((paths.state_root / "removal-tombstones").glob("*.json"))
    assert len(tombstones) == 1
    tombstone = json.loads(tombstones[0].read_text())
    assert tombstone["status"] == "failed"
    assert [event["status"] for event in tombstone["events"]] == ["started", "failed"]


def test_status_schema_accepts_stable_user_contract(tmp_path: Path) -> None:
    schema_path = Path(__file__).parents[1] / "docs" / "guard" / "schemas" / "mdm-status-v1.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator(schema).validate(lifecycle.user_status(tmp_path))


def test_removal_authorization_is_scoped_short_lived_and_single_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _machine_paths(tmp_path)
    monkeypatch.setattr(removal, "default_machine_paths", lambda: paths)
    authorization_root = paths.state_root / "removal-authorizations"
    authorization_root.mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    token = _write_removal_authorization(authorization_root, home)
    monkeypatch.setattr(removal.platform, "system", lambda: "Windows")
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: True)
    monkeypatch.setattr(removal, "_active_binding", lambda _paths: (MACHINE_INSTALLATION_ID, INSTALLATION_GENERATION))

    evidence = lifecycle.validate_removal_authorization(
        token,
        home=home,
        user="developer",
    )
    assert len(evidence.fingerprint) == 64
    assert evidence.installation_generation == INSTALLATION_GENERATION
    assert not token.exists()

    with pytest.raises(ValueError, match="mdm_removal_authorization_consumed_or_missing"):
        lifecycle.validate_removal_authorization(token, home=home, user="developer")


def test_removal_authorization_rejects_stale_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _machine_paths(tmp_path)
    monkeypatch.setattr(removal, "default_machine_paths", lambda: paths)
    authorization_root = paths.state_root / "removal-authorizations"
    authorization_root.mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    token = _write_removal_authorization(authorization_root, home, generation="3" * 32)
    monkeypatch.setattr(removal.platform, "system", lambda: "Windows")
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: True)
    monkeypatch.setattr(removal, "_active_binding", lambda _paths: (MACHINE_INSTALLATION_ID, INSTALLATION_GENERATION))

    with pytest.raises(ValueError, match="mdm_removal_authorization_wrong_generation"):
        lifecycle.validate_removal_authorization(
            token,
            home=home,
            user="developer",
        )
    assert token.exists()


def test_removal_authorization_rejects_arbitrary_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _machine_paths(tmp_path / "machine")
    monkeypatch.setattr(removal, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: True)
    token = tmp_path / "token.json"
    token.write_text("{}")
    with pytest.raises(ValueError, match="mdm_removal_authorization_wrong_scope"):
        lifecycle.validate_removal_authorization(
            token,
            home=tmp_path,
            user="developer",
        )


def test_removal_authorization_rejects_untrusted_machine_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _machine_paths(tmp_path)
    monkeypatch.setattr(removal, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: False)
    token = paths.state_root / "removal-authorizations" / "token.json"
    token.parent.mkdir(parents=True)
    token.write_text("{}")
    with pytest.raises(ValueError, match="mdm_removal_authorization_untrusted_root"):
        lifecycle.validate_removal_authorization(token, home=tmp_path, user="developer")
    assert token.exists()


def test_authorization_creation_requires_admin_and_safe_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _machine_paths(tmp_path)
    monkeypatch.setattr(removal, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(removal, "_active_binding", lambda _paths: (MACHINE_INSTALLATION_ID, INSTALLATION_GENERATION))
    monkeypatch.setattr(removal, "_is_administrator", lambda: False)
    with pytest.raises(PermissionError, match="mdm_administrator_context_required"):
        lifecycle.authorize_deactivation(
            tmp_path, "developer", actor="mdm-admin@example.test", reason="approved retirement"
        )

    monkeypatch.setattr(removal, "_is_administrator", lambda: True)
    monkeypatch.setattr(removal.platform, "system", lambda: "Windows")
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: True)
    with pytest.raises(ValueError, match="mdm_removal_authorization_name_invalid"):
        lifecycle.authorize_deactivation(
            tmp_path,
            "developer",
            actor="mdm-admin@example.test",
            reason="approved retirement",
            token_name="../escape.json",
        )
    payload = lifecycle.authorize_deactivation(
        tmp_path,
        "developer",
        actor="mdm-admin@example.test",
        reason="approved retirement",
        token_name="developer.json",
    )
    assert Path(str(payload["authorizationPath"])).is_file()
    token = json.loads(Path(str(payload["authorizationPath"])).read_text())
    assert token["installationGeneration"] == INSTALLATION_GENERATION
    assert token["actor"] == "mdm-admin@example.test"
    tombstone = paths.state_root / "removal-tombstones" / f"{payload['authorizationFingerprint']}.json"
    assert json.loads(tombstone.read_text())["status"] == "issued"
    evidence = removal.validate_removal_authorization(
        Path(str(payload["authorizationPath"])),
        home=tmp_path,
        user="developer",
    )
    _ = removal.record_removal_tombstone(evidence, status="started", machine_paths=paths)
    _ = removal.record_removal_tombstone(evidence, status="completed", machine_paths=paths)
    completed = json.loads(tombstone.read_text())
    assert [event["status"] for event in completed["events"]] == ["issued", "started", "completed"]
    with pytest.raises(ValueError, match="mdm_removal_tombstone_transition_invalid"):
        removal.record_removal_tombstone(evidence, status="failed", machine_paths=paths)


@pytest.mark.parametrize("failure", [OSError("audit unavailable"), ValueError("audit unavailable")])
def test_authorization_creation_removes_token_when_tombstone_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    paths = _machine_paths(tmp_path)
    monkeypatch.setattr(removal, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(removal, "_active_binding", lambda _paths: (MACHINE_INSTALLATION_ID, INSTALLATION_GENERATION))
    monkeypatch.setattr(removal, "_is_administrator", lambda: True)
    monkeypatch.setattr(removal.platform, "system", lambda: "Windows")
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: True)

    def fail_tombstone(*_args: object, **_kwargs: object) -> Path:
        raise failure

    monkeypatch.setattr(removal, "record_removal_tombstone", fail_tombstone)
    with pytest.raises((OSError, ValueError), match="audit unavailable"):
        lifecycle.authorize_deactivation(
            tmp_path,
            "developer",
            actor="mdm-admin@example.test",
            reason="approved retirement",
            token_name="developer.json",
        )
    assert not (paths.state_root / "removal-authorizations" / "developer.json").exists()
