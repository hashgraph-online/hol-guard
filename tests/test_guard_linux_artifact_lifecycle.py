from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.linux_artifact_lifecycle import (
    LinuxArtifactLifecycleError,
    LinuxArtifactLifecycleOperation,
    LinuxArtifactLifecycleOutcome,
    LinuxArtifactLifecycleState,
    install_linux_artifact,
    remove_linux_artifact,
    repair_linux_artifact,
    upgrade_linux_artifact,
)
from codex_plugin_scanner.guard.runtime.linux_artifact_ownership import LinuxArtifactMetadata


def _artifact(
    root: Path,
    *,
    version: str = "1.0.0",
    release_sequence: int = 1,
    content: bytes = b"release-one",
    component_id: str = "hol-guard",
) -> tuple[str, LinuxArtifactMetadata]:
    path = root / f"guard-{release_sequence}-{hashlib.sha256(content).hexdigest()[:8]}"
    _ = path.write_bytes(content)
    _ = path.chmod(0o555)
    return str(path), LinuxArtifactMetadata(
        component_id=component_id,
        version=version,
        source=f"https://pypi.org/project/hol-guard/{version}/",
        license_id="Apache-2.0",
        expected_sha256=hashlib.sha256(content).hexdigest(),
        release_sequence=release_sequence,
    )


def _install(root: Path) -> tuple[LinuxArtifactLifecycleState, str, LinuxArtifactMetadata]:
    path, metadata = _artifact(root)
    transition = install_linux_artifact(LinuxArtifactLifecycleState(), path, metadata, expected_uid=os.getuid())
    return transition.state, path, metadata


def test_install_verifies_file_and_activates_identity_deterministically(tmp_path: Path) -> None:
    path, metadata = _artifact(tmp_path)
    first = install_linux_artifact(LinuxArtifactLifecycleState(), path, metadata, expected_uid=os.getuid())
    second = install_linux_artifact(LinuxArtifactLifecycleState(), path, metadata, expected_uid=os.getuid())

    assert first == second
    assert first.state.active is not None
    assert first.state.rollback is None
    assert first.receipt.operation is LinuxArtifactLifecycleOperation.INSTALL
    assert first.receipt.outcome is LinuxArtifactLifecycleOutcome.ACTIVATED
    assert len(first.receipt.receipt_digest) == 64


def test_install_rejects_active_state_and_unverified_content(tmp_path: Path) -> None:
    state, path, metadata = _install(tmp_path)

    with pytest.raises(LinuxArtifactLifecycleError, match="install-requires-absent-artifact"):
        _ = install_linux_artifact(state, path, metadata, expected_uid=os.getuid())

    other_path, other_metadata = _artifact(tmp_path, release_sequence=2, content=b"trusted")
    _ = Path(other_path).chmod(0o557)
    with pytest.raises(ValueError, match="artifact-writable-by-untrusted"):
        _ = install_linux_artifact(LinuxArtifactLifecycleState(), other_path, other_metadata, expected_uid=os.getuid())


def test_upgrade_requires_monotonic_release_and_retains_rollback(tmp_path: Path) -> None:
    state, _, _ = _install(tmp_path)
    path, metadata = _artifact(tmp_path, version="2.0.0", release_sequence=2, content=b"release-two")
    upgraded = upgrade_linux_artifact(state, path, metadata, expected_uid=os.getuid())

    assert upgraded.state.active is not None
    assert upgraded.state.active.release_sequence == 2
    assert state.active is not None
    assert upgraded.state.rollback == state.active
    assert upgraded.receipt.before_identity_digest == state.active.identity_digest
    assert upgraded.receipt.rollback_identity_digest == state.active.identity_digest


def test_upgrade_rejects_downgrade_same_sequence_and_component_substitution(tmp_path: Path) -> None:
    initial_path, initial_metadata = _artifact(tmp_path, version="2.0.0", release_sequence=2, content=b"release-two")
    state = install_linux_artifact(
        LinuxArtifactLifecycleState(), initial_path, initial_metadata, expected_uid=os.getuid()
    ).state
    old_path, old_metadata = _artifact(tmp_path, version="1.0.0", release_sequence=1, content=b"release-one")
    with pytest.raises(LinuxArtifactLifecycleError, match="upgrade-requires-newer-release"):
        _ = upgrade_linux_artifact(state, old_path, old_metadata, expected_uid=os.getuid())

    same_path, same_metadata = _artifact(tmp_path, version="2.0.1", release_sequence=2, content=b"same-sequence")
    with pytest.raises(LinuxArtifactLifecycleError, match="upgrade-requires-newer-release"):
        _ = upgrade_linux_artifact(state, same_path, same_metadata, expected_uid=os.getuid())

    other_path, other_metadata = _artifact(
        tmp_path,
        version="3.0.0",
        release_sequence=3,
        content=b"other",
        component_id="other",
    )
    with pytest.raises(LinuxArtifactLifecycleError, match="upgrade-component-mismatch"):
        _ = upgrade_linux_artifact(state, other_path, other_metadata, expected_uid=os.getuid())


def test_remove_clears_active_and_rollback_state(tmp_path: Path) -> None:
    state, _, _ = _install(tmp_path)
    path, metadata = _artifact(tmp_path, version="2.0.0", release_sequence=2, content=b"release-two")
    upgraded = upgrade_linux_artifact(state, path, metadata, expected_uid=os.getuid())
    Path(path).unlink()
    removed = remove_linux_artifact(upgraded.state)

    assert removed.state == LinuxArtifactLifecycleState()
    assert removed.receipt.after_identity_digest is None
    assert removed.receipt.rollback_identity_digest is None
    assert removed.receipt.outcome is LinuxArtifactLifecycleOutcome.REMOVED


def test_remove_requires_artifact_absence(tmp_path: Path) -> None:
    state, _, _ = _install(tmp_path)
    with pytest.raises(LinuxArtifactLifecycleError, match="remove-requires-artifact-absence"):
        _ = remove_linux_artifact(state)


def test_repair_verifies_healthy_state_without_changing_identity(tmp_path: Path) -> None:
    state, path, metadata = _install(tmp_path)
    repaired = repair_linux_artifact(state, path, metadata, expected_uid=os.getuid())

    assert repaired.state == state
    assert repaired.receipt.outcome is LinuxArtifactLifecycleOutcome.VERIFIED
    assert repaired.receipt.before_identity_digest == repaired.receipt.after_identity_digest


def test_repair_restores_replaced_artifact_from_verified_file(tmp_path: Path) -> None:
    state, path, metadata = _install(tmp_path)
    artifact = Path(path)
    artifact.unlink()
    _ = artifact.write_bytes(b"release-one")
    _ = artifact.chmod(0o555)
    restored = repair_linux_artifact(state, path, metadata, expected_uid=os.getuid())

    assert state.active is not None
    assert restored.state.active is not None
    assert restored.state.active.inode != state.active.inode
    assert restored.state.rollback is None
    assert restored.receipt.before_identity_digest == state.active.identity_digest
    assert restored.receipt.outcome is LinuxArtifactLifecycleOutcome.RESTORED


def test_repair_preserves_upgrade_rollback_after_same_release_replacement(tmp_path: Path) -> None:
    initial, _, _ = _install(tmp_path)
    path, metadata = _artifact(tmp_path, version="2.0.0", release_sequence=2, content=b"release-two")
    upgraded = upgrade_linux_artifact(initial, path, metadata, expected_uid=os.getuid())
    artifact = Path(path)
    artifact.unlink()
    _ = artifact.write_bytes(b"release-two")
    _ = artifact.chmod(0o555)
    repaired = repair_linux_artifact(upgraded.state, path, metadata, expected_uid=os.getuid())

    assert repaired.receipt.outcome is LinuxArtifactLifecycleOutcome.RESTORED
    assert repaired.state.rollback == upgraded.state.rollback


def test_repair_requires_active_state_and_same_release(tmp_path: Path) -> None:
    path, metadata = _artifact(tmp_path)
    with pytest.raises(LinuxArtifactLifecycleError, match="repair-requires-active-artifact"):
        _ = repair_linux_artifact(LinuxArtifactLifecycleState(), path, metadata, expected_uid=os.getuid())

    installed = install_linux_artifact(LinuxArtifactLifecycleState(), path, metadata, expected_uid=os.getuid()).state
    newer_path, newer_metadata = _artifact(tmp_path, release_sequence=2, content=b"release-two")
    newer = install_linux_artifact(
        LinuxArtifactLifecycleState(), newer_path, newer_metadata, expected_uid=os.getuid()
    ).state
    with pytest.raises(LinuxArtifactLifecycleError, match="repair-requires-same-release"):
        _ = repair_linux_artifact(newer, path, metadata, expected_uid=os.getuid())
    with pytest.raises(LinuxArtifactLifecycleError, match="repair-requires-same-release"):
        _ = repair_linux_artifact(installed, newer_path, newer_metadata, expected_uid=os.getuid())


def test_lifecycle_rejects_noncanonical_path_and_changed_file(tmp_path: Path) -> None:
    path, metadata = _artifact(tmp_path)
    _ = Path(path).chmod(0o755)
    _ = Path(path).write_bytes(b"changed")
    _ = Path(path).chmod(0o555)

    with pytest.raises(ValueError, match=r"artifact-size-mismatch|artifact-digest-mismatch"):
        _ = install_linux_artifact(LinuxArtifactLifecycleState(), path, metadata, expected_uid=os.getuid())
    with pytest.raises(LinuxArtifactLifecycleError, match="invalid-path"):
        _ = install_linux_artifact(LinuxArtifactLifecycleState(), f"/{path}", metadata, expected_uid=os.getuid())


def test_public_evidence_rejects_contradictory_outcome_and_state(tmp_path: Path) -> None:
    state, path, metadata = _install(tmp_path)
    installed = install_linux_artifact(LinuxArtifactLifecycleState(), path, metadata, expected_uid=os.getuid())

    with pytest.raises(LinuxArtifactLifecycleError, match="invalid-operation-outcome"):
        _ = replace(installed.receipt, outcome=LinuxArtifactLifecycleOutcome.REMOVED)
    with pytest.raises(LinuxArtifactLifecycleError, match="transition-state-mismatch"):
        _ = replace(installed, state=LinuxArtifactLifecycleState())
    with pytest.raises(LinuxArtifactLifecycleError, match="invalid-evidence-shape"):
        _ = replace(installed.receipt, rollback_identity_digest=installed.receipt.after_identity_digest)

    absent = LinuxArtifactLifecycleState()
    with pytest.raises(LinuxArtifactLifecycleError, match="remove-requires-active-artifact"):
        _ = remove_linux_artifact(absent)
    with pytest.raises(LinuxArtifactLifecycleError, match="upgrade-requires-active-artifact"):
        _ = upgrade_linux_artifact(absent, path, metadata, expected_uid=os.getuid())
    with pytest.raises(LinuxArtifactLifecycleError, match="invalid-trusted-ancestor-uids"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            path,
            metadata,
            expected_uid=os.getuid(),
            trusted_ancestor_uids=frozenset(),
        )
    with pytest.raises(LinuxArtifactLifecycleError, match="invalid-expected-uid"):
        _ = install_linux_artifact(LinuxArtifactLifecycleState(), path, metadata, expected_uid=True)
    assert state.active is not None
