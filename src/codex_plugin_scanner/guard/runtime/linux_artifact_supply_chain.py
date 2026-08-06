"""Signed supply-chain acceptance for privileged Linux Guard artifacts."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{128}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_SCHEMA_VERSION = 1
_SIGNATURE_DOMAIN = b"hol-guard-linux-artifact-manifest-v1\0"
_RECEIPT_SEAL_KEY = secrets.token_bytes(32)


class LinuxArtifactSupplyChainError(ValueError):
    """Raised when a privileged Linux artifact lacks trusted provenance."""


@dataclass(frozen=True, slots=True)
class LinuxArtifactSupplyChainManifest:
    schema_version: int
    component_id: str
    version: str
    release_sequence: int
    artifact_digest: str
    sbom_digest: str
    source_digest: str
    builder_id: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != _SCHEMA_VERSION:
            raise LinuxArtifactSupplyChainError("unsupported manifest schema")
        if type(self.release_sequence) is not int or self.release_sequence < 0:
            raise LinuxArtifactSupplyChainError("invalid release sequence")
        for label, value in (
            ("component_id", self.component_id),
            ("builder_id", self.builder_id),
            ("key_id", self.key_id),
        ):
            if type(value) is not str or _IDENTIFIER_PATTERN.fullmatch(value) is None:
                raise LinuxArtifactSupplyChainError(f"invalid {label}")
        if (
            type(self.version) is not str
            or not self.version
            or self.version != self.version.strip()
            or len(self.version) > 128
        ):
            raise LinuxArtifactSupplyChainError("invalid version")
        for label, value in (
            ("artifact_digest", self.artifact_digest),
            ("sbom_digest", self.sbom_digest),
            ("source_digest", self.source_digest),
        ):
            if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
                raise LinuxArtifactSupplyChainError(f"invalid {label}")
        if type(self.signature) is not str or _SIGNATURE_PATTERN.fullmatch(self.signature) is None:
            raise LinuxArtifactSupplyChainError("invalid signature")

    @property
    def digest(self) -> str:
        return _sha256(_canonical_json(asdict(self)))


@dataclass(frozen=True, slots=True)
class LinuxArtifactSupplyChainReceipt:
    component_id: str
    version: str
    release_sequence: int
    artifact_digest: str
    sbom_digest: str
    source_digest: str
    builder_id: str
    key_id: str
    manifest_digest: str
    manifest: LinuxArtifactSupplyChainManifest = field(repr=False, compare=False)
    _provenance_seal: bytes = field(default=b"", repr=False, compare=False)

    def __post_init__(self) -> None:
        self.validate_provenance()

    def validate_provenance(self) -> None:
        string_fields = (
            self.component_id,
            self.version,
            self.artifact_digest,
            self.sbom_digest,
            self.source_digest,
            self.builder_id,
            self.key_id,
            self.manifest_digest,
        )
        if (
            any(type(value) is not str for value in string_fields)
            or type(self.release_sequence) is not int
            or type(self.manifest) is not LinuxArtifactSupplyChainManifest
            or type(self._provenance_seal) is not bytes
        ):
            raise LinuxArtifactSupplyChainError("receipt provenance is invalid")
        expected_seal = _receipt_seal(self)
        if not hmac.compare_digest(self._provenance_seal, expected_seal):
            raise LinuxArtifactSupplyChainError("receipt provenance is invalid")


def create_linux_artifact_supply_chain_manifest(
    *,
    component_id: str,
    version: str,
    release_sequence: int,
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
        release_sequence=release_sequence,
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
    expected_release_sequence: int,
    expected_source_digest: str,
    trusted_builder_ids: frozenset[str],
    trusted_public_keys: Mapping[str, str],
    revoked_key_ids: frozenset[str] | None = None,
) -> LinuxArtifactSupplyChainReceipt:
    """Verify installed bytes, SBOM, provenance signature, trust, and revocation."""
    if type(manifest) is not LinuxArtifactSupplyChainManifest:
        raise LinuxArtifactSupplyChainError("manifest provenance is invalid")
    revoked_keys: frozenset[str] = revoked_key_ids if revoked_key_ids is not None else frozenset()
    if manifest.component_id != expected_component_id:
        raise LinuxArtifactSupplyChainError("component identity mismatch")
    if manifest.version != expected_version:
        raise LinuxArtifactSupplyChainError("artifact version mismatch")
    if manifest.release_sequence != expected_release_sequence:
        raise LinuxArtifactSupplyChainError("artifact release sequence mismatch")
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
    receipt_fields = {
        "artifact_digest": manifest.artifact_digest,
        "builder_id": manifest.builder_id,
        "component_id": manifest.component_id,
        "release_sequence": manifest.release_sequence,
        "key_id": manifest.key_id,
        "manifest_digest": manifest.digest,
        "sbom_digest": manifest.sbom_digest,
        "source_digest": manifest.source_digest,
        "version": manifest.version,
    }
    return LinuxArtifactSupplyChainReceipt(
        component_id=manifest.component_id,
        release_sequence=manifest.release_sequence,
        version=manifest.version,
        artifact_digest=manifest.artifact_digest,
        sbom_digest=manifest.sbom_digest,
        source_digest=manifest.source_digest,
        builder_id=manifest.builder_id,
        key_id=manifest.key_id,
        manifest=manifest,
        manifest_digest=manifest.digest,
        _provenance_seal=_receipt_seal_fields(receipt_fields),
    )


def validate_linux_artifact_supply_chain_receipt(receipt: LinuxArtifactSupplyChainReceipt) -> None:
    """Reject caller-authored or modified supply-chain evidence."""
    if type(receipt) is not LinuxArtifactSupplyChainReceipt:
        raise LinuxArtifactSupplyChainError("receipt provenance is invalid")
    receipt.validate_provenance()


def _receipt_seal(receipt: LinuxArtifactSupplyChainReceipt) -> bytes:
    return _receipt_seal_fields(
        {
            "artifact_digest": receipt.artifact_digest,
            "builder_id": receipt.builder_id,
            "component_id": receipt.component_id,
            "release_sequence": receipt.release_sequence,
            "key_id": receipt.key_id,
            "manifest_digest": receipt.manifest_digest,
            "sbom_digest": receipt.sbom_digest,
            "source_digest": receipt.source_digest,
            "version": receipt.version,
        }
    )


def _receipt_seal_fields(fields: Mapping[str, object]) -> bytes:
    return hmac.new(_RECEIPT_SEAL_KEY, _canonical_json(fields), hashlib.sha256).digest()


def revalidate_linux_artifact_supply_chain_receipt(
    receipt: LinuxArtifactSupplyChainReceipt,
    *,
    artifact_digest: str,
    trusted_builder_ids: frozenset[str],
    trusted_public_keys: Mapping[str, str],
    revoked_key_ids: frozenset[str] | None = None,
) -> None:
    """Revalidate signed provenance against current activation-time trust and revocation."""
    validate_linux_artifact_supply_chain_receipt(receipt)
    manifest = receipt.manifest
    if type(manifest) is not LinuxArtifactSupplyChainManifest:
        raise LinuxArtifactSupplyChainError("receipt manifest is invalid")
    revoked_keys: frozenset[str] = revoked_key_ids if revoked_key_ids is not None else frozenset()
    if manifest.builder_id not in trusted_builder_ids:
        raise LinuxArtifactSupplyChainError("artifact builder is not trusted")
    if manifest.key_id in revoked_keys:
        raise LinuxArtifactSupplyChainError("manifest signer is revoked")
    public_key_hex = trusted_public_keys.get(manifest.key_id)
    if public_key_hex is None:
        raise LinuxArtifactSupplyChainError("manifest signer is not trusted")
    if manifest.artifact_digest != artifact_digest:
        raise LinuxArtifactSupplyChainError("artifact digest mismatch")
    if (
        receipt.component_id != manifest.component_id
        or receipt.version != manifest.version
        or receipt.release_sequence != manifest.release_sequence
        or receipt.artifact_digest != manifest.artifact_digest
        or receipt.sbom_digest != manifest.sbom_digest
        or receipt.source_digest != manifest.source_digest
        or receipt.builder_id != manifest.builder_id
        or receipt.key_id != manifest.key_id
        or receipt.manifest_digest != manifest.digest
    ):
        raise LinuxArtifactSupplyChainError("receipt manifest binding is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(manifest.signature),
            _signature_payload(manifest),
        )
    except (InvalidSignature, ValueError) as error:
        raise LinuxArtifactSupplyChainError("manifest signature is invalid") from error


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
    "revalidate_linux_artifact_supply_chain_receipt",
    "validate_linux_artifact_supply_chain_receipt",
    "verify_linux_artifact_supply_chain",
]
