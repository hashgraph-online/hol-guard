"""Signed release-manifest verification for machine-owned runtimes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import RELEASE_MANIFEST_SCHEMA_VERSION

_MAX_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ManifestVerification:
    status: str
    reason_code: str
    version: str | None = None
    build_id: str | None = None
    installer_identity: str | None = None
    signature_state: str = "unverified"

    @property
    def healthy(self) -> bool:
        return self.status == "healthy"

    def to_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reasonCode": self.reason_code,
            "version": self.version,
            "buildId": self.build_id,
            "installerIdentity": self.installer_identity,
            "signatureState": self.signature_state,
        }


def _canonical_unsigned_payload(payload: Mapping[str, object]) -> bytes:
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _valid_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value:
        return None
    return value


def verify_release_manifest(
    manifest_path: Path,
    runtime_root: Path,
    *,
    trusted_keys: Mapping[str, bytes] | None = None,
    require_signature: bool = True,
    expected_platform: str | None = None,
    expected_architecture: str | None = None,
    expected_owner_uid: int | None = None,
) -> ManifestVerification:
    """Verify manifest schema, signature, and every runtime file hash."""

    if not manifest_path.exists():
        return ManifestVerification("absent", "release_manifest_absent")
    try:
        if manifest_path.stat().st_size > _MAX_MANIFEST_BYTES:
            raise ValueError("manifest exceeds size limit")
        manifest_metadata = manifest_path.stat()
        if expected_owner_uid is not None and manifest_metadata.st_uid != expected_owner_uid:
            return ManifestVerification("tampered", "release_manifest_wrong_owner")
        if expected_owner_uid is not None and manifest_metadata.st_mode & 0o022:
            return ManifestVerification("tampered", "release_manifest_insecure_permissions")
        raw: object = json.loads(manifest_path.read_bytes())
        if not isinstance(raw, dict):
            raise ValueError("manifest must be an object")
        payload = cast(dict[str, object], raw)
        if payload.get("schemaVersion") != RELEASE_MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported manifest schema")
        version = payload.get("version")
        build_id = payload.get("buildId")
        installer_identity = payload.get("installerIdentity")
        source_commit = payload.get("sourceCommit")
        manifest_platform = payload.get("platform")
        architecture = payload.get("architecture")
        policy_schema = payload.get("policySchemaVersion")
        if not all(
            isinstance(value, str) and value
            for value in (
                version,
                build_id,
                installer_identity,
                source_commit,
                manifest_platform,
                architecture,
                policy_schema,
            )
        ):
            raise ValueError("manifest identity fields are required")
        version = cast(str, version)
        build_id = cast(str, build_id)
        installer_identity = cast(str, installer_identity)
        if expected_platform is not None and manifest_platform != expected_platform:
            return ManifestVerification(
                "unsupported", "release_manifest_platform_mismatch", version, build_id, installer_identity
            )
        if expected_architecture is not None and str(architecture).lower() != expected_architecture.lower():
            return ManifestVerification(
                "unsupported", "release_manifest_architecture_mismatch", version, build_id, installer_identity
            )

        signature_state = "unsigned"
        signature = payload.get("signature")
        if signature is not None:
            if not isinstance(signature, dict):
                raise ValueError("signature must be an object")
            key_id = signature.get("keyId")
            encoded = signature.get("value")
            if not isinstance(key_id, str) or not isinstance(encoded, str):
                raise ValueError("signature keyId and value are required")
            key_bytes = (trusted_keys or {}).get(key_id)
            if key_bytes is None:
                return ManifestVerification(
                    "tampered", "release_manifest_untrusted_key", version, build_id, installer_identity
                )
            Ed25519PublicKey.from_public_bytes(key_bytes).verify(
                base64.b64decode(encoded, validate=True), _canonical_unsigned_payload(payload)
            )
            signature_state = "valid"
        elif require_signature:
            return ManifestVerification(
                "tampered", "release_manifest_unsigned", version, build_id, installer_identity, signature_state
            )

        files = payload.get("files")
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty array")
        resolved_root = runtime_root.resolve(strict=True)
        for entry in files:
            if not isinstance(entry, dict):
                raise ValueError("file entry must be an object")
            relative = _valid_relative_path(entry.get("path"))
            digest = entry.get("sha256")
            if relative is None or not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("invalid file entry")
            candidate = (resolved_root / relative).resolve(strict=True)
            if not candidate.is_relative_to(resolved_root) or not candidate.is_file():
                return ManifestVerification(
                    "tampered", "release_manifest_path_escape", version, build_id, installer_identity, signature_state
                )
            metadata = candidate.stat()
            if expected_owner_uid is not None and metadata.st_uid != expected_owner_uid:
                return ManifestVerification(
                    "tampered", "release_runtime_wrong_owner", version, build_id, installer_identity, signature_state
                )
            if expected_owner_uid is not None and metadata.st_mode & 0o022:
                return ManifestVerification(
                    "tampered",
                    "release_runtime_insecure_permissions",
                    version,
                    build_id,
                    installer_identity,
                    signature_state,
                )
            actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if actual != digest.lower():
                return ManifestVerification(
                    "tampered", "release_manifest_hash_mismatch", version, build_id, installer_identity, signature_state
                )
        return ManifestVerification(
            "healthy", "release_manifest_valid", version, build_id, installer_identity, signature_state
        )
    except (OSError, ValueError, json.JSONDecodeError, InvalidSignature, binascii.Error):
        return ManifestVerification("tampered", "release_manifest_invalid")


__all__ = ["ManifestVerification", "verify_release_manifest"]
