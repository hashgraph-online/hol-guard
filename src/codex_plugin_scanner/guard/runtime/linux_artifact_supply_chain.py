"""Signed supply-chain acceptance for privileged Linux Guard artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{128}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_SCHEMA_VERSION = 1
_SIGNATURE_DOMAIN = b"hol-guard-linux-artifact-manifest-v1\0"


class LinuxArtifactSupplyChainError(ValueError):
    """Raised when a privileged Linux artifact lacks trusted provenance."""


@dataclass(frozen=True, slots=True)
class LinuxArtifactSupplyChainManifest:
    schema_version: int
    component_id: str
    version: str
    artifact_digest: str
    sbom_digest: str
    source_digest: str
    builder_id: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION:
            raise LinuxArtifactSupplyChainError("unsupported manifest schema")
        for label, value in (
            ("component_id", self.component_id),
            ("builder_id", self.builder_id),
            ("key_id", self.key_id),
        ):
            if _IDENTIFIER_PATTERN.fullmatch(value) is None:
                raise LinuxArtifactSupplyChainError(f"invalid {label}")
        if not self.version or self.version != self.version.strip() or len(self.version) > 128:
            raise LinuxArtifactSupplyChainError("invalid version")
        for label, value in (
            ("artifact_digest", self.artifact_digest),
            ("sbom_digest", self.sbom_digest),
            ("source_digest", self.source_digest),
        ):
            if _SHA256_PATTERN.fullmatch(value) is None:
                raise LinuxArtifactSupplyChainError(f"invalid {label}")
        if _SIGNATURE_PATTERN.fullmatch(self.signature) is None:
            raise LinuxArtifactSupplyChainError("invalid signature")

    @property
    def digest(self) -> str:
        return _sha256(_canonical_json(asdict(self)))


@dataclass(frozen=True, slots=True)
class LinuxArtifactSupplyChainReceipt:
    component_id: str
    version: str
    artifact_digest: str
    sbom_digest: str
    source_digest: str
    builder_id: str
    key_id: str
    manifest_digest: str


def create_linux_artifact_supply_chain_manifest(
    *,
    component_id: str,
    version: str,
    artifact: bytes,
    sbom: bytes,
    source_digest: str,
    builder_id: str,
    key_id: str,
    signing_key: Ed25519PrivateKey,
) -> LinuxArtifactSupplyChainManifest:
    """Create a build-time manifest; runtime verification never downloads artifacts."""
    unsigned = LinuxArtifactSupplyChainManifest(
        schema_version=_SCHEMA_VERSION,
        component_id=component_id,
        version=version,
        artifact_digest=_sha256(artifact),
        sbom_digest=_sha256(sbom),
        source_digest=source_digest,
        builder_id=builder_id,
        key_id=key_id,
        signature="0" * 128,
    )
    return replace(
        unsigned,
        signature=signing_key.sign(_signature_payload(unsigned)).hex(),
    )


def verify_linux_artifact_supply_chain(
    manifest: LinuxArtifactSupplyChainManifest,
    *,
    artifact: bytes,
    sbom: bytes,
    expected_component_id: str,
    expected_version: str,
    expected_source_digest: str,
    trusted_builder_ids: frozenset[str],
    trusted_public_keys: Mapping[str, str],
    revoked_key_ids: frozenset[str] | None = None,
) -> LinuxArtifactSupplyChainReceipt:
    """Verify installed bytes, SBOM, provenance signature, trust, and revocation."""
    revoked_keys: frozenset[str] = revoked_key_ids if revoked_key_ids is not None else frozenset()
    if manifest.component_id != expected_component_id:
        raise LinuxArtifactSupplyChainError("component identity mismatch")
    if manifest.version != expected_version:
        raise LinuxArtifactSupplyChainError("artifact version mismatch")
    if manifest.source_digest != expected_source_digest:
        raise LinuxArtifactSupplyChainError("source digest mismatch")
    if manifest.builder_id not in trusted_builder_ids:
        raise LinuxArtifactSupplyChainError("artifact builder is not trusted")
    if manifest.key_id in revoked_keys:
        raise LinuxArtifactSupplyChainError("manifest signer is revoked")
    public_key_hex = trusted_public_keys.get(manifest.key_id)
    if public_key_hex is None:
        raise LinuxArtifactSupplyChainError("manifest signer is not trusted")
    if manifest.artifact_digest != _sha256(artifact):
        raise LinuxArtifactSupplyChainError("artifact digest mismatch")
    if manifest.sbom_digest != _sha256(sbom):
        raise LinuxArtifactSupplyChainError("SBOM digest mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(manifest.signature), _signature_payload(manifest))
    except (InvalidSignature, ValueError) as error:
        raise LinuxArtifactSupplyChainError("manifest signature is invalid") from error
    return LinuxArtifactSupplyChainReceipt(
        component_id=manifest.component_id,
        version=manifest.version,
        artifact_digest=manifest.artifact_digest,
        sbom_digest=manifest.sbom_digest,
        source_digest=manifest.source_digest,
        builder_id=manifest.builder_id,
        key_id=manifest.key_id,
        manifest_digest=manifest.digest,
    )


def _signature_payload(manifest: LinuxArtifactSupplyChainManifest) -> bytes:
    fields = asdict(manifest)
    fields.pop("signature")
    return _SIGNATURE_DOMAIN + _canonical_json(fields)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


__all__ = [
    "LinuxArtifactSupplyChainError",
    "LinuxArtifactSupplyChainManifest",
    "LinuxArtifactSupplyChainReceipt",
    "create_linux_artifact_supply_chain_manifest",
    "verify_linux_artifact_supply_chain",
]
