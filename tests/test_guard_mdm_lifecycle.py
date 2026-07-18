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
    MDM_POLICY_SCHEMA_VERSION,
    MDM_STATUS_SCHEMA_VERSION,
    MachinePaths,
    ManagedPolicyState,
)
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import (
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
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


def _managed_policy_state(
    *,
    keyring: dict[str, object] | None,
) -> ManagedPolicyState:
    payload: dict[str, object] = {
        "schemaVersion": MDM_POLICY_SCHEMA_VERSION,
        "settings": {"mode": "enforce"},
        "lockedSettings": ["mode"],
    }
    if keyring is not None:
        payload["policyBundleKeyring"] = keyring
    return ManagedPolicyState(
        "active",
        "managed-policy-fixture",
        policy=parse_managed_policy(payload),
    )


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


def test_activation_provisions_managed_policy_keyring_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    policy_state = _managed_policy_state(keyring=keyring)
    monkeypatch.setattr(lifecycle, "load_managed_policy", lambda: policy_state)
    observed_keyrings: list[tuple[object, object]] = []

    def fake_install(
        _command: str,
        _harness: object,
        _all_harnesses: object,
        _context: object,
        store: GuardStore,
        *_args: object,
        **_kwargs: object,
    ) -> dict[str, object]:
        observed_keyrings.append(
            (
                store.get_sync_payload("policy_bundle_keyring"),
                store.get_sync_payload("managed_policy_bundle_keyring_mirror"),
            )
        )
        return {"managed_installs": []}

    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)

    lifecycle.activate_user(tmp_path, "developer")

    assert observed_keyrings == [
        (
            {
                "contractVersion": "guard-policy-keyring.v1",
                "purpose": "policy_bundle",
                "workspaceId": "workspace-managed",
                "keys": [],
            },
            keyring,
        )
    ]
    store = GuardStore(tmp_path / ".hol-guard")
    marker = store.get_sync_payload("managed_policy_bundle_keyring_provenance")
    assert isinstance(marker, dict)
    assert policy_state.policy is not None
    assert marker["contractVersion"] == "guard-managed-policy-keyring-provenance.v1"
    assert marker["managedPolicyContentHash"] == policy_state.policy.content_hash
    assert marker["workspaceId"] == "workspace-managed"


def test_repair_is_idempotent_for_unchanged_managed_policy_keyring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    policy_state = _managed_policy_state(keyring=keyring)
    monkeypatch.setattr(lifecycle, "load_managed_policy", lambda: policy_state)
    monkeypatch.setattr(
        lifecycle,
        "apply_managed_install",
        lambda *_args, **_kwargs: {"managed_installs": []},
    )
    writes: list[str] = []
    original_set_sync_payload = GuardStore.set_sync_payload

    def tracked_set_sync_payload(
        self: GuardStore,
        state_key: str,
        payload: dict[str, object] | list[object],
        now: str,
    ) -> None:
        writes.append(state_key)
        original_set_sync_payload(self, state_key, payload, now)

    monkeypatch.setattr(GuardStore, "set_sync_payload", tracked_set_sync_payload)
    lifecycle.activate_user(tmp_path, "developer")
    writes.clear()

    lifecycle.repair_user(tmp_path, "developer")

    assert writes == []


def test_repair_replaces_managed_policy_keyring_on_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    rotated_key = policy_bundle_test_verification_key(
        key_id="guard-policy-bundle-rotated",
        workspace_id="workspace-managed",
    )
    rotated_keyring = policy_bundle_test_keyring(
        workspace_id="workspace-managed",
        key=rotated_key,
    )
    current_policy = [_managed_policy_state(keyring=initial_keyring)]
    monkeypatch.setattr(lifecycle, "load_managed_policy", lambda: current_policy[0])
    monkeypatch.setattr(
        lifecycle,
        "apply_managed_install",
        lambda *_args, **_kwargs: {"managed_installs": []},
    )
    lifecycle.activate_user(tmp_path, "developer")
    current_policy[0] = _managed_policy_state(keyring=rotated_keyring)

    lifecycle.repair_user(tmp_path, "developer")

    store = GuardStore(tmp_path / ".hol-guard")
    assert store.get_sync_payload("managed_policy_bundle_keyring_mirror") == rotated_keyring
    local_keyring = store.get_sync_payload("policy_bundle_keyring")
    assert isinstance(local_keyring, dict)
    assert local_keyring["keys"] == []
    marker = store.get_sync_payload("managed_policy_bundle_keyring_provenance")
    assert isinstance(marker, dict)
    assert current_policy[0].policy is not None
    assert marker["managedPolicyContentHash"] == current_policy[0].policy.content_hash


def test_repair_removes_managed_mirror_and_legacy_shared_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed_keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    current_policy = [_managed_policy_state(keyring=managed_keyring)]
    monkeypatch.setattr(lifecycle, "load_managed_policy", lambda: current_policy[0])
    monkeypatch.setattr(
        lifecycle,
        "apply_managed_install",
        lambda *_args, **_kwargs: {"managed_installs": []},
    )
    lifecycle.activate_user(tmp_path, "developer")
    current_policy[0] = _managed_policy_state(keyring=None)

    lifecycle.repair_user(tmp_path, "developer")

    store = GuardStore(tmp_path / ".hol-guard")
    assert store.get_sync_payload("policy_bundle_keyring") is None
    assert store.get_sync_payload("managed_policy_bundle_keyring_mirror") is None
    assert store.get_sync_payload("managed_policy_bundle_keyring_provenance") is None

    current_policy[0] = _managed_policy_state(keyring=managed_keyring)
    lifecycle.repair_user(tmp_path, "developer")
    unrelated_key = policy_bundle_test_verification_key(
        key_id="unrelated-local-anchor",
        workspace_id="workspace-managed",
    )
    unrelated_keyring = policy_bundle_test_keyring(
        workspace_id="workspace-managed",
        key=unrelated_key,
    )
    store.set_sync_payload(
        "policy_bundle_keyring",
        unrelated_keyring,
        "2026-07-18T00:00:00Z",
    )
    current_policy[0] = _managed_policy_state(keyring=None)

    lifecycle.repair_user(tmp_path, "developer")

    assert store.get_sync_payload("policy_bundle_keyring") is None
    assert store.get_sync_payload("managed_policy_bundle_keyring_mirror") is None
    assert store.get_sync_payload("managed_policy_bundle_keyring_provenance") is None


def test_activation_rejects_managed_keyring_for_different_connected_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_state = _managed_policy_state(keyring=policy_bundle_test_keyring(workspace_id="workspace-managed"))
    monkeypatch.setattr(lifecycle, "load_managed_policy", lambda: policy_state)
    guard_home = tmp_path / ".hol-guard"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        "oauth_local_credentials",
        {"workspace_id": "workspace-other"},
        "2026-07-18T00:00:00Z",
    )

    with pytest.raises(ValueError, match="managed_policy_bundle_keyring_workspace_mismatch"):
        lifecycle.activate_user(tmp_path, "developer")

    assert store.get_sync_payload("policy_bundle_keyring") is None
    assert store.get_sync_payload("managed_policy_bundle_keyring_provenance") is None


def test_partial_activation_rolls_back_new_harnesses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStore:
        active = False

        def __init__(self, _guard_home: Path) -> None:
            pass

        def list_managed_installs(self) -> list[dict[str, object]]:
            return [{"harness": "codex", "active": True}] if self.active else []

        def get_sync_payload(self, _state_key: str) -> None:
            return None

        def reconcile_managed_policy_bundle_keyring_state(self, **_kwargs: object) -> bool:
            return False

    commands: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        if command == "install":
            FakeStore.active = True
            raise RuntimeError("interrupted")
        FakeStore.active = False
        return {}

    monkeypatch.setattr(lifecycle, "GuardStore", FakeStore)
    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)

    with pytest.raises(RuntimeError, match="interrupted"):
        lifecycle.activate_user(tmp_path, "developer")

    assert commands == ["install", "uninstall"]
    assert FakeStore.active is False


def test_deactivation_restores_integrations_and_removes_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()
    (guard_home / "mdm-activation.json").write_text("{}")
    request = guard_home / "mdm-harness-coverage-request.json"
    request.write_text("{}")
    commands: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        return {"managed_installs": []}

    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)
    monkeypatch.setattr(
        lifecycle,
        "unregister_user_harnesses",
        lambda *_args: pytest.fail("user deactivation attempted a privileged registry mutation"),
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
    assert payload["operation"] == "deactivate"
    assert payload["installationGeneration"] == INSTALLATION_GENERATION
    assert not (guard_home / "mdm-activation.json").exists()
    assert not request.exists()
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


def test_deactivation_removes_matching_managed_policy_keyring_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_state = _managed_policy_state(keyring=policy_bundle_test_keyring(workspace_id="workspace-managed"))
    monkeypatch.setattr(lifecycle, "load_managed_policy", lambda: policy_state)
    monkeypatch.setattr(
        lifecycle,
        "apply_managed_install",
        lambda *_args, **_kwargs: {"managed_installs": []},
    )
    lifecycle.activate_user(tmp_path, "developer")
    store = GuardStore(tmp_path / ".hol-guard")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(
            workspace_id="workspace-managed",
            key=policy_bundle_test_verification_key(
                key_id="substituted-user-key",
                workspace_id="workspace-managed",
            ),
        ),
        "2026-07-18T00:00:00Z",
    )
    # The provenance row is user-writable bookkeeping, not authority. An
    # authorized managed teardown must still clear the shared anchor slot when
    # that row was removed or corrupted before deactivation.
    store.delete_sync_payload("managed_policy_bundle_keyring_provenance")
    assert store.get_sync_payload("managed_policy_bundle_keyring_provenance") is None

    paths = _machine_paths(tmp_path)
    _patch_machine_paths(monkeypatch, paths)
    authorization_root = paths.state_root / "removal-authorizations"
    authorization_root.mkdir(parents=True)
    token = _write_removal_authorization(authorization_root, tmp_path)
    monkeypatch.setattr(removal, "_authorization_owner_is_trusted", lambda _metadata: True)
    monkeypatch.setattr(removal, "_authorization_root_is_trusted", lambda _paths: True)
    monkeypatch.setattr(
        removal,
        "_active_binding",
        lambda _paths: (MACHINE_INSTALLATION_ID, INSTALLATION_GENERATION),
    )

    lifecycle.deactivate_user(
        tmp_path,
        user="developer",
        authorization_file=token,
    )

    assert store.get_sync_payload("policy_bundle_keyring") is None
    assert store.get_sync_payload("managed_policy_bundle_keyring_mirror") is None
    assert store.get_sync_payload("managed_policy_bundle_keyring_provenance") is None


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
