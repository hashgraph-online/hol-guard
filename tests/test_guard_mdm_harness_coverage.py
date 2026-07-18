from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm import harness_coverage, integrity, machine_state_lock
from codex_plugin_scanner.guard.mdm.acl import OwnershipAclVerification
from codex_plugin_scanner.guard.mdm.contracts import (
    MDM_POLICY_SCHEMA_VERSION,
    KeyProtectionStatus,
    MachinePaths,
    ManagedPolicy,
    ManagedPolicyState,
    ManagedUpdatePolicy,
    SupervisorStatus,
)


@pytest.fixture(autouse=True)
def _trusted_test_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(harness_coverage, "_administrator_context", lambda: True)
    monkeypatch.setattr(harness_coverage, "_registry_owner_is_trusted", lambda _metadata: True)
    monkeypatch.setattr(machine_state_lock, "_lock_owner_is_trusted", lambda _metadata: True)


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(root / "runtime", root / "state", root / "policy.json", root / "logs", root / "manifest.json")


def _policy(*required: str) -> ManagedPolicyState:
    return ManagedPolicyState(
        "active",
        "native",
        ManagedPolicy(
            schema_version=MDM_POLICY_SCHEMA_VERSION,
            settings={},
            locked_settings=frozenset(),
            required_harnesses=required,
            update=ManagedUpdatePolicy(owner="mdm"),
        ),
        reason_code="managed_policy_active",
    )


def _install(name: str, artifact: Path) -> dict[str, object]:
    return {"active": True, "harness": name, "manifest": {"config_path": str(artifact)}}


def test_registry_projects_protected_degraded_and_missing_counts(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "home"
    artifact = home / ".codex" / "config.toml"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("managed = true\n")
    harness_coverage.register_user_harnesses(paths, home, [_install("codex", artifact)])

    initial = harness_coverage.verify_harness_coverage(paths, _policy("codex", "claude-code"))
    assert initial.state == "degraded"
    assert initial.reason_code == "harness_coverage_missing"
    assert initial.coverage == {"required": 2, "protected": 1, "degraded": 0, "missing": 1}

    artifact.write_text("managed = false\n")
    tampered = harness_coverage.verify_harness_coverage(paths, _policy("codex", "claude-code"))
    assert tampered.coverage == {"required": 2, "protected": 0, "degraded": 1, "missing": 1}

    artifact.unlink()
    missing = harness_coverage.verify_harness_coverage(paths, _policy("codex", "claude-code"))
    assert missing.coverage == {"required": 2, "protected": 0, "degraded": 0, "missing": 2}


def test_standard_user_cannot_mutate_machine_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(harness_coverage, "_administrator_context", lambda: False)

    with pytest.raises(PermissionError, match="harness_coverage_administrator_context_required"):
        harness_coverage.register_user_harnesses(paths, home, [])

    assert not paths.state_root.exists()


def test_registration_rejects_unbounded_manifest_nesting(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    nested: dict[str, object] = {}
    for _ in range(18):
        nested = {"nested": nested}
    install = {"active": True, "harness": "codex", "manifest": nested}

    with pytest.raises(ValueError, match="harness_coverage_manifest_invalid"):
        harness_coverage.register_user_harnesses(paths, home, [install])


def test_registry_tracks_multiple_users_without_identity_in_projection(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    identities = ("alice", "bob")
    for identity in identities:
        home = tmp_path / identity
        artifact = home / ".codex" / "config.toml"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(f"managed = {identity!r}\n")
        harness_coverage.register_user_harnesses(paths, home, [_install("codex", artifact)])

    verification = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    serialized = json.dumps(verification.coverage)

    assert verification.state == "healthy"
    assert verification.coverage == {"required": 2, "protected": 2, "degraded": 0, "missing": 0}
    assert all(identity not in serialized for identity in identities)
    assert str(tmp_path) not in serialized


def test_concurrent_user_registration_preserves_every_entry(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    barrier = threading.Barrier(2)
    failures: list[Exception] = []

    def register(identity: str) -> None:
        try:
            home = tmp_path / identity
            artifact = home / ".codex" / "config.toml"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("managed = true\n")
            barrier.wait()
            harness_coverage.register_user_harnesses(paths, home, [_install("codex", artifact)])
        except Exception as exc:
            failures.append(exc)

    threads = [threading.Thread(target=register, args=(identity,)) for identity in ("alice", "bob")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    verification = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert verification.coverage == {"required": 2, "protected": 2, "degraded": 0, "missing": 0}


def test_unregistration_preserves_initialized_empty_registry(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "home"
    artifact = home / "config.json"
    home.mkdir()
    artifact.write_text("{}")
    harness_coverage.register_user_harnesses(paths, home, [_install("codex", artifact)])

    harness_coverage.unregister_user_harnesses(paths, home)
    verification = harness_coverage.verify_harness_coverage(paths, _policy("codex"))

    assert verification.state == "healthy"
    assert verification.coverage == {"required": 0, "protected": 0, "degraded": 0, "missing": 0}


def test_registry_absence_and_tamper_fail_honest(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    absent = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert absent.state == "unknown"
    assert absent.reason_code == "harness_coverage_registry_absent"

    paths.state_root.mkdir()
    registry = paths.state_root / "harness-coverage-registry.json"
    registry.write_text("{}")
    tampered = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert tampered.state == "unknown"
    assert tampered.reason_code == "harness_coverage_probe_failed"


def test_registry_rejects_unsafe_permissions_and_symlink(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.state_root.mkdir()
    registry = paths.state_root / "harness-coverage-registry.json"
    registry.write_text(json.dumps({"schemaVersion": "hol-guard-harness-coverage-registry.v1", "users": []}))
    registry.chmod(0o644)

    unsafe_mode = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert unsafe_mode.state == "unknown"
    assert unsafe_mode.reason_code == "harness_coverage_probe_failed"

    registry.unlink()
    target = tmp_path / "attacker-registry.json"
    target.write_text(json.dumps({"schemaVersion": "hol-guard-harness-coverage-registry.v1", "users": []}))
    registry.symlink_to(target)
    symlinked = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert symlinked.state == "unknown"
    assert symlinked.reason_code == "harness_coverage_probe_failed"


def test_symlinked_harness_artifact_is_never_protected(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "attacker-config"
    target.write_text("managed = true\n")
    artifact = home / "config.toml"
    artifact.symlink_to(target)

    harness_coverage.register_user_harnesses(paths, home, [_install("codex", artifact)])
    verification = harness_coverage.verify_harness_coverage(paths, _policy("codex"))

    assert verification.coverage == {"required": 1, "protected": 0, "degraded": 1, "missing": 0}


def test_directory_artifact_detects_nested_hook_tamper(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "home"
    extension = home / ".guard-extension"
    extension.mkdir(parents=True)
    hook = extension / "hook.py"
    hook.write_text("protected = True\n")
    harness_coverage.register_user_harnesses(paths, home, [_install("codex", extension)])

    initial = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert initial.coverage == {"required": 1, "protected": 1, "degraded": 0, "missing": 0}

    hook.write_text("protected = False\n")
    tampered = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert tampered.coverage == {"required": 1, "protected": 0, "degraded": 1, "missing": 0}


def test_mutable_guard_state_is_checked_for_presence_without_hashing_content(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "home"
    artifact = home / ".codex" / "config.toml"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("managed = true\n")
    state = home / ".hol-guard" / "guard.db"
    state.parent.mkdir()
    state.write_bytes(b"initial mutable state")
    harness_coverage.register_user_harnesses(paths, home, [_install("codex", artifact)])

    state.write_bytes(b"updated mutable state")
    updated = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert updated.coverage == {"required": 1, "protected": 1, "degraded": 0, "missing": 0}

    state.unlink()
    missing = harness_coverage.verify_harness_coverage(paths, _policy("codex"))
    assert missing.coverage == {"required": 1, "protected": 0, "degraded": 0, "missing": 1}


def test_machine_snapshot_emits_only_aggregate_harness_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "sensitive-user-home"
    artifact = home / ".codex" / "config.toml"
    artifact.parent.mkdir(parents=True)
    sensitive_content = "token = 'secret-value'\ncommand = 'private command content'\n"
    artifact.write_text(sensitive_content)
    harness_coverage.register_user_harnesses(paths, home, [_install("codex", artifact)])
    monkeypatch.setattr(integrity, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(integrity, "load_managed_policy", lambda **_kwargs: _policy("codex"))
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

    snapshot = integrity.machine_integrity_snapshot()
    serialized = json.dumps(snapshot)

    assert snapshot["harnessCoverage"] == {"required": 1, "protected": 1, "degraded": 0, "missing": 0}
    assert snapshot["components"]["harnessCoverage"] == {
        "state": "healthy",
        "healthy": True,
        "reasonCode": "harness_coverage_healthy",
    }
    assert "sensitive-user-home" not in serialized
    assert str(home) not in serialized
    assert "secret-value" not in serialized
    assert "private command content" not in serialized
