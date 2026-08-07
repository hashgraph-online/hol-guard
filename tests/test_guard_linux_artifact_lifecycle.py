from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import TypedDict, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing_extensions import override

from codex_plugin_scanner.guard.runtime.linux_artifact_lifecycle import (
    LinuxArtifactLifecycleError,
    LinuxArtifactLifecycleOperation,
    LinuxArtifactLifecycleOutcome,
    LinuxArtifactLifecycleState,
    LinuxArtifactReleaseLedger,
    install_linux_artifact,
    remove_linux_artifact,
    repair_linux_artifact,
    upgrade_linux_artifact,
)
from codex_plugin_scanner.guard.runtime.linux_artifact_ownership import LinuxArtifactMetadata
from codex_plugin_scanner.guard.runtime.linux_artifact_supply_chain import (
    LinuxArtifactSupplyChainReceipt,
    create_linux_artifact_supply_chain_manifest,
    verify_linux_artifact_supply_chain,
)

_SBOM = b'{"bomFormat":"CycloneDX","components":[]}'
_SOURCE_DIGEST = "a" * 64
_SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_PUBLIC_KEY = (
    _SIGNING_KEY.public_key()
    .public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    .hex()
)


class _Trust(TypedDict):
    trusted_builder_ids: frozenset[str]
    trusted_public_keys: dict[str, str]
    release_ledger: LinuxArtifactReleaseLedger


_TRUST: _Trust = {
    "trusted_builder_ids": frozenset({"github-actions-release"}),
    "trusted_public_keys": {"release-2026": _PUBLIC_KEY},
    "release_ledger": LinuxArtifactReleaseLedger(sqlite3.connect(":memory:")),
}


def _independent_trust() -> _Trust:
    return {
        "trusted_builder_ids": _TRUST["trusted_builder_ids"],
        "trusted_public_keys": _TRUST["trusted_public_keys"],
        "release_ledger": LinuxArtifactReleaseLedger(sqlite3.connect(":memory:")),
    }


@pytest.fixture(autouse=True)
def fresh_release_ledger() -> None:
    _TRUST["release_ledger"] = LinuxArtifactReleaseLedger(sqlite3.connect(":memory:"))


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


def _receipt(path: str, metadata: LinuxArtifactMetadata) -> LinuxArtifactSupplyChainReceipt:
    artifact = Path(path).read_bytes()
    manifest = create_linux_artifact_supply_chain_manifest(
        component_id=metadata.component_id,
        version=metadata.version,
        release_sequence=metadata.release_sequence,
        artifact=artifact,
        sbom=_SBOM,
        source_digest=_SOURCE_DIGEST,
        builder_id="github-actions-release",
        key_id="release-2026",
        signing_key=_SIGNING_KEY,
    )
    return verify_linux_artifact_supply_chain(
        manifest,
        artifact=artifact,
        sbom=_SBOM,
        expected_component_id=metadata.component_id,
        expected_release_sequence=metadata.release_sequence,
        trusted_public_keys={"release-2026": _PUBLIC_KEY},
        expected_version=metadata.version,
        expected_source_digest=_SOURCE_DIGEST,
        trusted_builder_ids=frozenset({"github-actions-release"}),
    )


def _install(root: Path) -> tuple[LinuxArtifactLifecycleState, str, LinuxArtifactMetadata]:
    path, metadata = _artifact(root)
    transition = install_linux_artifact(
        LinuxArtifactLifecycleState(), path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
    )
    return transition.state, path, metadata


def test_install_verifies_file_and_activates_identity_deterministically(tmp_path: Path) -> None:
    path, metadata = _artifact(tmp_path)
    first = install_linux_artifact(
        LinuxArtifactLifecycleState(), path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
    )
    second = install_linux_artifact(
        LinuxArtifactLifecycleState(),
        path,
        metadata,
        _receipt(path, metadata),
        expected_uid=os.getuid(),
        **_independent_trust(),
    )

    assert first == second
    assert first.state.active is not None
    assert first.state.rollback is None
    assert first.receipt.operation is LinuxArtifactLifecycleOperation.INSTALL
    assert first.receipt.outcome is LinuxArtifactLifecycleOutcome.ACTIVATED
    assert len(first.receipt.receipt_digest) == 64


def test_install_rejects_active_state_and_unverified_content(tmp_path: Path) -> None:
    state, path, metadata = _install(tmp_path)

    with pytest.raises(LinuxArtifactLifecycleError, match="install-requires-absent-artifact"):
        _ = install_linux_artifact(state, path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST)

    other_path, other_metadata = _artifact(tmp_path, release_sequence=2, content=b"trusted")
    _ = Path(other_path).chmod(0o557)
    with pytest.raises(ValueError, match="artifact-writable-by-untrusted"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            other_path,
            other_metadata,
            _receipt(other_path, other_metadata),
            expected_uid=os.getuid(),
            **_TRUST,
        )


def test_upgrade_requires_monotonic_release_and_retains_rollback(tmp_path: Path) -> None:
    state, _, _ = _install(tmp_path)
    path, metadata = _artifact(tmp_path, version="2.0.0", release_sequence=2, content=b"release-two")
    upgraded = upgrade_linux_artifact(
        state, path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
    )

    assert upgraded.state.active is not None
    assert upgraded.state.active.release_sequence == 2
    assert state.active is not None
    assert upgraded.state.rollback == state.active
    assert upgraded.receipt.before_identity_digest == state.active.identity_digest
    assert upgraded.receipt.rollback_identity_digest == state.active.identity_digest


def test_remove_requires_active_and_rollback_artifacts_absent(tmp_path: Path) -> None:
    state, rollback_path, _ = _install(tmp_path)
    active_path, metadata = _artifact(tmp_path, version="2.0.0", release_sequence=2, content=b"release-two")
    upgraded = upgrade_linux_artifact(
        state, active_path, metadata, _receipt(active_path, metadata), expected_uid=os.getuid(), **_TRUST
    )

    Path(active_path).unlink()
    with pytest.raises(LinuxArtifactLifecycleError, match="remove-requires-artifact-absence"):
        _ = remove_linux_artifact(upgraded.state)

    Path(rollback_path).unlink()
    removed = remove_linux_artifact(upgraded.state)
    assert removed.state == LinuxArtifactLifecycleState()
    assert upgraded.state.rollback is not None
    assert removed.receipt.rollback_identity_digest == upgraded.state.rollback.identity_digest


def test_upgrade_rejects_downgrade_same_sequence_and_component_substitution(tmp_path: Path) -> None:
    initial_path, initial_metadata = _artifact(tmp_path, version="2.0.0", release_sequence=2, content=b"release-two")
    state = install_linux_artifact(
        LinuxArtifactLifecycleState(),
        initial_path,
        initial_metadata,
        _receipt(initial_path, initial_metadata),
        expected_uid=os.getuid(),
        **_TRUST,
    ).state
    old_path, old_metadata = _artifact(tmp_path, version="1.0.0", release_sequence=1, content=b"release-one")
    with pytest.raises(LinuxArtifactLifecycleError, match="upgrade-requires-newer-release"):
        _ = upgrade_linux_artifact(
            state, old_path, old_metadata, _receipt(old_path, old_metadata), expected_uid=os.getuid(), **_TRUST
        )

    same_path, same_metadata = _artifact(tmp_path, version="2.0.1", release_sequence=2, content=b"same-sequence")
    with pytest.raises(LinuxArtifactLifecycleError, match="upgrade-requires-newer-release"):
        _ = upgrade_linux_artifact(
            state, same_path, same_metadata, _receipt(same_path, same_metadata), expected_uid=os.getuid(), **_TRUST
        )

    other_path, other_metadata = _artifact(
        tmp_path,
        version="3.0.0",
        release_sequence=3,
        content=b"other",
        component_id="other",
    )
    with pytest.raises(LinuxArtifactLifecycleError, match="upgrade-component-mismatch"):
        _ = upgrade_linux_artifact(
            state, other_path, other_metadata, _receipt(other_path, other_metadata), expected_uid=os.getuid(), **_TRUST
        )


def test_remove_requires_artifact_absence(tmp_path: Path) -> None:
    state, _, _ = _install(tmp_path)
    with pytest.raises(LinuxArtifactLifecycleError, match="remove-requires-artifact-absence"):
        _ = remove_linux_artifact(state)


def test_remove_rejects_tampered_identity_after_artifact_absence(tmp_path: Path) -> None:
    state, path, _ = _install(tmp_path)
    assert state.active is not None
    Path(path).unlink()
    tampered = replace(state.active)
    object.__setattr__(tampered, "_provenance_seal", b"0" * 32)

    with pytest.raises(LinuxArtifactLifecycleError, match="identity-provenance-invalid"):
        _ = remove_linux_artifact(LinuxArtifactLifecycleState(active=tampered))


def test_repair_verifies_healthy_state_without_changing_identity(tmp_path: Path) -> None:
    state, path, metadata = _install(tmp_path)
    repaired = repair_linux_artifact(
        state, path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
    )

    assert repaired.state == state
    assert repaired.receipt.outcome is LinuxArtifactLifecycleOutcome.VERIFIED
    assert repaired.receipt.before_identity_digest == repaired.receipt.after_identity_digest


def test_repair_restores_replaced_artifact_from_verified_file(tmp_path: Path) -> None:
    state, path, metadata = _install(tmp_path)
    artifact = Path(path)
    with artifact.open("rb") as original_handle:
        artifact.unlink()
        _ = artifact.write_bytes(b"release-one")
        _ = artifact.chmod(0o555)
        restored = repair_linux_artifact(
            state, path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
        )
        assert original_handle.fileno() >= 0

    assert state.active is not None
    assert restored.state.active is not None
    assert restored.state.active.inode != state.active.inode
    assert restored.state.rollback is None
    assert restored.receipt.before_identity_digest == state.active.identity_digest
    assert restored.receipt.outcome is LinuxArtifactLifecycleOutcome.RESTORED


def test_repair_preserves_upgrade_rollback_after_same_release_replacement(tmp_path: Path) -> None:
    initial, _, _ = _install(tmp_path)
    path, metadata = _artifact(tmp_path, version="2.0.0", release_sequence=2, content=b"release-two")
    upgraded = upgrade_linux_artifact(
        initial, path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
    )
    artifact = Path(path)
    with artifact.open("rb") as original_handle:
        artifact.unlink()
        _ = artifact.write_bytes(b"release-two")
        _ = artifact.chmod(0o555)
        repaired = repair_linux_artifact(
            upgraded.state, path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
        )
        assert original_handle.fileno() >= 0

    assert repaired.receipt.outcome is LinuxArtifactLifecycleOutcome.RESTORED
    assert repaired.state.rollback == upgraded.state.rollback


def test_repair_requires_active_state_and_same_release(tmp_path: Path) -> None:
    path, metadata = _artifact(tmp_path)
    with pytest.raises(LinuxArtifactLifecycleError, match="repair-requires-active-artifact"):
        _ = repair_linux_artifact(
            LinuxArtifactLifecycleState(), path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
        )

    installed = install_linux_artifact(
        LinuxArtifactLifecycleState(), path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST
    ).state
    newer_path, newer_metadata = _artifact(tmp_path, release_sequence=2, content=b"release-two")
    newer = install_linux_artifact(
        LinuxArtifactLifecycleState(),
        newer_path,
        newer_metadata,
        _receipt(newer_path, newer_metadata),
        expected_uid=os.getuid(),
        **_TRUST,
    ).state
    with pytest.raises(LinuxArtifactLifecycleError, match="repair-requires-same-release"):
        _ = repair_linux_artifact(newer, path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST)
    with pytest.raises(LinuxArtifactLifecycleError, match="repair-requires-same-release"):
        _ = repair_linux_artifact(
            installed,
            newer_path,
            newer_metadata,
            _receipt(newer_path, newer_metadata),
            expected_uid=os.getuid(),
            **_TRUST,
        )
    substituted_path, substituted_metadata = _artifact(
        tmp_path,
        version="1.0.1",
        release_sequence=1,
        content=b"substituted-release",
    )
    with pytest.raises(LinuxArtifactLifecycleError, match="repair-requires-same-release"):
        _ = repair_linux_artifact(
            installed,
            substituted_path,
            substituted_metadata,
            _receipt(substituted_path, substituted_metadata),
            expected_uid=os.getuid(),
            **_TRUST,
        )


def test_repair_revalidates_active_identity_provenance(tmp_path: Path) -> None:
    trust = _independent_trust()
    path, metadata = _artifact(tmp_path)
    receipt = _receipt(path, metadata)
    installed = install_linux_artifact(
        LinuxArtifactLifecycleState(),
        path,
        metadata,
        receipt,
        expected_uid=os.getuid(),
        **trust,
    ).state
    assert installed.active is not None
    object.__setattr__(installed.active, "version", "attacker-version")

    with pytest.raises(LinuxArtifactLifecycleError, match="artifact-identity-digest-mismatch"):
        _ = repair_linux_artifact(
            installed,
            path,
            metadata,
            receipt,
            expected_uid=os.getuid(),
            **trust,
        )


def test_lifecycle_rejects_noncanonical_path_and_changed_file(tmp_path: Path) -> None:
    path, metadata = _artifact(tmp_path)
    receipt = _receipt(path, metadata)
    _ = Path(path).chmod(0o755)
    _ = Path(path).write_bytes(b"changed")
    _ = Path(path).chmod(0o555)

    with pytest.raises(ValueError, match=r"artifact-digest-mismatch"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(), path, metadata, receipt, expected_uid=os.getuid(), **_TRUST
        )
    with pytest.raises(LinuxArtifactLifecycleError, match="invalid-path"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(), f"/{path}", metadata, receipt, expected_uid=os.getuid(), **_TRUST
        )


def test_public_evidence_rejects_contradictory_outcome_and_state(tmp_path: Path) -> None:
    state, path, metadata = _install(tmp_path)
    installed = install_linux_artifact(
        LinuxArtifactLifecycleState(),
        path,
        metadata,
        _receipt(path, metadata),
        expected_uid=os.getuid(),
        **_independent_trust(),
    )

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
        _ = upgrade_linux_artifact(absent, path, metadata, _receipt(path, metadata), expected_uid=os.getuid(), **_TRUST)
    with pytest.raises(LinuxArtifactLifecycleError, match="invalid-trusted-ancestor-uids"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            path,
            metadata,
            _receipt(path, metadata),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=frozenset(),
            **_TRUST,
        )
    with pytest.raises(LinuxArtifactLifecycleError, match="invalid-expected-uid"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            path,
            metadata,
            _receipt(path, metadata),
            expected_uid=True,
            **_TRUST,
        )
    assert state.active is not None


def test_lifecycle_rejects_forged_and_mismatched_supply_chain_receipts(tmp_path: Path) -> None:
    path, metadata = _artifact(tmp_path)
    receipt = _receipt(path, metadata)
    with pytest.raises(LinuxArtifactLifecycleError, match="supply-chain-receipt-invalid"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            path,
            metadata,
            cast(LinuxArtifactSupplyChainReceipt, object()),
            expected_uid=os.getuid(),
            **_TRUST,
        )

    with pytest.raises(ValueError, match="receipt provenance is invalid"):
        _ = replace(receipt, artifact_digest="0" * 64)

    other_path, other_metadata = _artifact(
        tmp_path,
        version="2.0.0",
        release_sequence=2,
        content=b"release-two",
    )
    mismatched_receipt = _receipt(other_path, other_metadata)
    with pytest.raises(LinuxArtifactLifecycleError, match="supply-chain-receipt-mismatch"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(), path, metadata, mismatched_receipt, expected_uid=os.getuid(), **_TRUST
        )

    replayed_metadata = replace(metadata, release_sequence=3)
    with pytest.raises(LinuxArtifactLifecycleError, match="supply-chain-receipt-mismatch"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            path,
            replayed_metadata,
            receipt,
            expected_uid=os.getuid(),
            **_TRUST,
        )
    with pytest.raises(LinuxArtifactLifecycleError, match="supply-chain-receipt-invalid"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            path,
            metadata,
            receipt,
            expected_uid=os.getuid(),
            revoked_key_ids=frozenset({"release-2026"}),
            **_TRUST,
        )

    _TRUST["release_ledger"].accept(metadata.component_id, 2, allow_equal=False)
    with pytest.raises(LinuxArtifactLifecycleError, match="release-sequence-replay"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            path,
            metadata,
            receipt,
            expected_uid=os.getuid(),
            **_TRUST,
        )


def test_lifecycle_rejects_spoofed_release_ledger_authority(tmp_path: Path) -> None:
    class SpoofedLedger:
        @override
        def __getattribute__(self, name: str) -> object:
            if name == "__class__":
                return LinuxArtifactReleaseLedger
            return cast(object, object.__getattribute__(self, name))

        def accept(self, _component_id: str, _release_sequence: int, *, allow_equal: bool) -> None:
            _ = allow_equal

    path, metadata = _artifact(tmp_path)
    receipt = _receipt(path, metadata)
    trust = _independent_trust()

    def spoofed_authority() -> object:
        return SpoofedLedger()

    trust["release_ledger"] = cast(LinuxArtifactReleaseLedger, spoofed_authority())
    with pytest.raises(LinuxArtifactLifecycleError, match="release-ledger-invalid"):
        _ = install_linux_artifact(
            LinuxArtifactLifecycleState(),
            path,
            metadata,
            receipt,
            expected_uid=os.getuid(),
            **trust,
        )
