from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing_extensions import override

from codex_plugin_scanner.guard.runtime.linux_artifact_supply_chain import (
    LinuxArtifactSupplyChainError,
    LinuxArtifactSupplyChainManifest,
    create_linux_artifact_supply_chain_manifest,
    verify_linux_artifact_supply_chain,
)

_ARTIFACT = b"compiled privileged guard artifact"
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
_TRUST_CASES: list[tuple[dict[str, str], frozenset[str], str]] = [
    ({}, frozenset(), "signer is not trusted"),
    ({"release-2026": _PUBLIC_KEY}, frozenset({"release-2026"}), "signer is revoked"),
    ({"release-2026": "00" * 32}, frozenset(), "signature is invalid"),
]
_PROVENANCE_CASES: list[tuple[str, str, frozenset[str], str]] = [
    ("2.9.0", _SOURCE_DIGEST, frozenset({"github-actions-release"}), "version mismatch"),
    ("3.0.0", "b" * 64, frozenset({"github-actions-release"}), "source digest mismatch"),
    ("3.0.0", _SOURCE_DIGEST, frozenset({"untrusted-builder"}), "builder is not trusted"),
]


def _manifest() -> LinuxArtifactSupplyChainManifest:
    return create_linux_artifact_supply_chain_manifest(
        component_id="guard-linux-ebpf",
        version="3.0.0",
        release_sequence=1,
        artifact=_ARTIFACT,
        sbom=_SBOM,
        source_digest=_SOURCE_DIGEST,
        builder_id="github-actions-release",
        key_id="release-2026",
        signing_key=_SIGNING_KEY,
    )


def test_linux_artifact_supply_chain_accepts_signed_installed_bytes() -> None:
    manifest = _manifest()

    receipt = verify_linux_artifact_supply_chain(
        manifest,
        artifact=_ARTIFACT,
        expected_release_sequence=1,
        sbom=_SBOM,
        expected_component_id="guard-linux-ebpf",
        trusted_public_keys={"release-2026": _PUBLIC_KEY},
        expected_version="3.0.0",
        expected_source_digest=_SOURCE_DIGEST,
        trusted_builder_ids=frozenset({"github-actions-release"}),
    )

    assert receipt.artifact_digest == manifest.artifact_digest
    assert receipt.sbom_digest == manifest.sbom_digest
    assert receipt.source_digest == _SOURCE_DIGEST
    assert receipt.manifest_digest == manifest.digest


@pytest.mark.parametrize(
    "artifact, sbom, message",
    [
        (_ARTIFACT + b"tampered", _SBOM, "artifact digest mismatch"),
        (_ARTIFACT, _SBOM + b"tampered", "SBOM digest mismatch"),
    ],
)
def test_linux_artifact_supply_chain_rejects_tampered_inputs(
    artifact: bytes,
    sbom: bytes,
    message: str,
) -> None:
    with pytest.raises(LinuxArtifactSupplyChainError, match=message):
        _ = verify_linux_artifact_supply_chain(
            _manifest(),
            artifact=artifact,
            expected_release_sequence=1,
            sbom=sbom,
            expected_component_id="guard-linux-ebpf",
            trusted_public_keys={"release-2026": _PUBLIC_KEY},
            expected_version="3.0.0",
            expected_source_digest=_SOURCE_DIGEST,
            trusted_builder_ids=frozenset({"github-actions-release"}),
        )


def test_linux_artifact_supply_chain_rejects_manifest_mutation() -> None:
    forged = replace(_manifest(), signature="0" * 128)

    with pytest.raises(LinuxArtifactSupplyChainError, match="signature is invalid"):
        _ = verify_linux_artifact_supply_chain(
            forged,
            artifact=_ARTIFACT,
            expected_release_sequence=1,
            sbom=_SBOM,
            expected_component_id="guard-linux-ebpf",
            trusted_public_keys={"release-2026": _PUBLIC_KEY},
            expected_version="3.0.0",
            expected_source_digest=_SOURCE_DIGEST,
            trusted_builder_ids=frozenset({"github-actions-release"}),
        )


@pytest.mark.parametrize(
    "trusted_keys, revoked_keys, message",
    _TRUST_CASES,
)
def test_linux_artifact_supply_chain_enforces_signer_trust_and_revocation(
    trusted_keys: dict[str, str],
    revoked_keys: frozenset[str],
    message: str,
) -> None:
    with pytest.raises(LinuxArtifactSupplyChainError, match=message):
        _ = verify_linux_artifact_supply_chain(
            _manifest(),
            artifact=_ARTIFACT,
            expected_release_sequence=1,
            sbom=_SBOM,
            expected_component_id="guard-linux-ebpf",
            trusted_public_keys=trusted_keys,
            expected_version="3.0.0",
            expected_source_digest=_SOURCE_DIGEST,
            trusted_builder_ids=frozenset({"github-actions-release"}),
            revoked_key_ids=revoked_keys,
        )


def test_linux_artifact_supply_chain_binds_component_identity() -> None:
    with pytest.raises(LinuxArtifactSupplyChainError, match="component identity mismatch"):
        _ = verify_linux_artifact_supply_chain(
            _manifest(),
            artifact=_ARTIFACT,
            expected_release_sequence=1,
            sbom=_SBOM,
            expected_component_id="guard-linux-systemd-unit",
            trusted_public_keys={"release-2026": _PUBLIC_KEY},
            expected_version="3.0.0",
            expected_source_digest=_SOURCE_DIGEST,
            trusted_builder_ids=frozenset({"github-actions-release"}),
        )


@pytest.mark.parametrize(
    "expected_version, expected_source_digest, trusted_builder_ids, message",
    _PROVENANCE_CASES,
)
def test_linux_artifact_supply_chain_rejects_rollback_and_provenance_substitution(
    expected_version: str,
    expected_source_digest: str,
    trusted_builder_ids: frozenset[str],
    message: str,
) -> None:
    with pytest.raises(LinuxArtifactSupplyChainError, match=message):
        _ = verify_linux_artifact_supply_chain(
            _manifest(),
            artifact=_ARTIFACT,
            expected_release_sequence=1,
            sbom=_SBOM,
            expected_component_id="guard-linux-ebpf",
            expected_version=expected_version,
            expected_source_digest=expected_source_digest,
            trusted_builder_ids=trusted_builder_ids,
            trusted_public_keys={"release-2026": _PUBLIC_KEY},
        )


def test_linux_artifact_supply_chain_rejects_scalar_subclasses() -> None:
    class LyingString(str):
        @override
        def __ne__(self, value: object) -> bool:
            return False

    manifest = _manifest()
    with pytest.raises(LinuxArtifactSupplyChainError, match="invalid component_id"):
        _ = replace(manifest, component_id=LyingString(manifest.component_id))

    receipt = verify_linux_artifact_supply_chain(
        manifest,
        artifact=_ARTIFACT,
        expected_release_sequence=1,
        sbom=_SBOM,
        expected_component_id="guard-linux-ebpf",
        trusted_public_keys={"release-2026": _PUBLIC_KEY},
        expected_version="3.0.0",
        expected_source_digest=_SOURCE_DIGEST,
        trusted_builder_ids=frozenset({"github-actions-release"}),
    )
    with pytest.raises(LinuxArtifactSupplyChainError, match="receipt provenance is invalid"):
        _ = replace(receipt, component_id=LyingString(receipt.component_id))
