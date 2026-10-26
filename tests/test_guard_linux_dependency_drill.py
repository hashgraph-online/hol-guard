import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.runtime.linux_artifact_supply_chain import (
    LinuxArtifactSupplyChainError,
    LinuxArtifactSupplyChainManifest,
    LinuxArtifactSupplyChainReceipt,
    create_linux_artifact_supply_chain_manifest,
    verify_linux_artifact_supply_chain,
)

_ARTIFACT = b"privileged-linux-artifact"
_PROC_HEADER = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
_SBOM = b'{"bomFormat":"CycloneDX","components":[]}'
_SOURCE_DIGEST = "a" * 64
_TRUSTED_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_COMPROMISED_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
_ROTATION_KEY = bytes(range(32))


def _public_key(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )


def _manifest(
    key: Ed25519PrivateKey,
    key_id: str,
) -> LinuxArtifactSupplyChainManifest:
    return create_linux_artifact_supply_chain_manifest(
        component_id="guard-linux-ebpf",
        version="3.0.0",
        release_sequence=1,
        artifact=_ARTIFACT,
        sbom=_SBOM,
        source_digest=_SOURCE_DIGEST,
        builder_id="github-actions-release",
        key_id=key_id,
        signing_key=key,
    )


def _verify(
    key: Ed25519PrivateKey,
    key_id: str,
    *,
    revoked: frozenset[str] | None = None,
) -> LinuxArtifactSupplyChainReceipt:
    return verify_linux_artifact_supply_chain(
        _manifest(key, key_id),
        artifact=_ARTIFACT,
        expected_release_sequence=1,
        sbom=_SBOM,
        expected_component_id="guard-linux-ebpf",
        expected_version="3.0.0",
        expected_source_digest=_SOURCE_DIGEST,
        trusted_builder_ids=frozenset({"github-actions-release"}),
        trusted_public_keys={"release-2026": _public_key(_TRUSTED_KEY)},
        revoked_key_ids=revoked,
    )


def test_untrusted_dependency_signing_key_cannot_substitute_artifact() -> None:
    with pytest.raises(LinuxArtifactSupplyChainError, match="signer is not trusted"):
        _ = _verify(_COMPROMISED_KEY, "compromised-key")


def test_compromised_previously_trusted_key_is_revoked() -> None:
    with pytest.raises(LinuxArtifactSupplyChainError, match="signer is revoked"):
        _ = _verify(_TRUSTED_KEY, "release-2026", revoked=frozenset({"release-2026"}))
