"""Signed release-manifest verification for machine-owned runtimes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.version import InvalidVersion, Version

from .contracts import RELEASE_MANIFEST_SCHEMA_VERSION

_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_RUNTIME_FILES = 100_000
_MAX_RUNTIME_DIRECTORIES = 100_000
_MAX_RUNTIME_ENTRIES = 200_000
_MAX_RUNTIME_BYTES = 2 * 1024 * 1024 * 1024
_MAX_RUNTIME_FILE_BYTES = 512 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_TRAVERSAL_SECONDS = 30.0


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


def _runtime_file_paths(runtime_root: Path, manifest_path: Path) -> tuple[set[str], str | None]:
    files: set[str] = set()
    directory_count = 1
    entry_count = 0
    manifest_relative = manifest_path.relative_to(runtime_root).as_posix()
    deadline = time.monotonic() + _MAX_TRAVERSAL_SECONDS
    pending = [runtime_root]
    while pending:
        current_path = pending.pop()
        with os.scandir(current_path) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > _MAX_RUNTIME_ENTRIES or time.monotonic() > deadline:
                    return files, "release_manifest_file_limit_exceeded"
                candidate = Path(entry.path)
                entry_metadata = entry.stat(follow_symlinks=False)
                reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if entry.is_symlink() or getattr(entry_metadata, "st_file_attributes", 0) & reparse_flag:
                    return files, "release_manifest_path_escape"
                if entry.is_dir(follow_symlinks=False):
                    directory_count += 1
                    if directory_count > _MAX_RUNTIME_DIRECTORIES:
                        return files, "release_manifest_file_limit_exceeded"
                    pending.append(candidate)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    return files, "release_manifest_path_escape"
                relative = candidate.relative_to(runtime_root).as_posix()
                if relative == manifest_relative:
                    continue
                files.add(relative)
                if len(files) > _MAX_RUNTIME_FILES:
                    return files, "release_manifest_file_limit_exceeded"
    return files, None


def _open_readonly_no_follow(path: Path) -> int:
    if os.name != "nt":
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.open(path, flags)
    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(str(path), 0x80000000, 0x7, None, 3, 0x00200000 | 0x08000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        binary_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        descriptor = msvcrt.open_osfhandle(int(handle), binary_flags)
    except OSError:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise
    metadata = os.fstat(descriptor)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
        os.close(descriptor)
        raise OSError("runtime entry is a reparse point")
    return descriptor


def _hash_regular_file(path: Path, remaining_bytes: int) -> tuple[str, int, os.stat_result]:
    descriptor = _open_readonly_no_follow(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("runtime entry is not a regular file")
        limit = min(_MAX_RUNTIME_FILE_BYTES, remaining_bytes)
        if before.st_size > limit:
            raise OverflowError("runtime size limit exceeded")
        digest = hashlib.sha256()
        consumed = 0
        while chunk := os.read(descriptor, min(_HASH_CHUNK_BYTES, limit - consumed + 1)):
            consumed += len(chunk)
            if consumed > limit:
                raise OverflowError("runtime size limit exceeded")
            digest.update(chunk)
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        changed = any(getattr(before, field) != getattr(after, field) for field in stable_fields)
        if consumed != before.st_size or changed:
            raise OSError("runtime file changed during verification")
        return digest.hexdigest(), consumed, before
    finally:
        os.close(descriptor)


def _read_bounded_regular_file(path: Path, maximum_bytes: int) -> tuple[bytes, os.stat_result]:
    descriptor = _open_readonly_no_follow(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise ValueError("file is not a bounded regular file")
        chunks: list[bytes] = []
        consumed = 0
        while chunk := os.read(descriptor, min(_HASH_CHUNK_BYTES, maximum_bytes - consumed + 1)):
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise ValueError("file exceeds size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        changed = any(getattr(before, field) != getattr(after, field) for field in stable_fields)
        if consumed != before.st_size or changed:
            raise OSError("file changed during read")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def verify_release_manifest(
    manifest_path: Path,
    runtime_root: Path,
    *,
    trusted_keys: Mapping[str, bytes] | None = None,
    require_signature: bool = True,
    expected_platform: str | None = None,
    expected_architecture: str | None = None,
    expected_owner_uid: int | None = None,
    expected_installer_identity: str | None = None,
    expected_native_version: str | None = None,
    minimum_version: str | None = None,
) -> ManifestVerification:
    """Verify manifest identity, signature, complete runtime coverage, and every file hash."""

    try:
        try:
            manifest_lstat = manifest_path.lstat()
        except FileNotFoundError:
            return ManifestVerification("absent", "release_manifest_absent")
        if stat.S_ISLNK(manifest_lstat.st_mode):
            return ManifestVerification("tampered", "release_manifest_path_escape")
        manifest_bytes, manifest_metadata = _read_bounded_regular_file(manifest_path, _MAX_MANIFEST_BYTES)
        if expected_owner_uid is not None and manifest_metadata.st_uid != expected_owner_uid:
            return ManifestVerification("tampered", "release_manifest_wrong_owner")
        if expected_owner_uid is not None and manifest_metadata.st_mode & 0o022:
            return ManifestVerification("tampered", "release_manifest_insecure_permissions")
        raw: object = json.loads(manifest_bytes)
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
        try:
            manifest_version = Version(version)
        except InvalidVersion:
            return ManifestVerification(
                "tampered", "release_manifest_version_invalid", version, build_id, installer_identity
            )
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
                reason = "release_manifest_untrusted_key" if trusted_keys else "release_manifest_trust_anchor_absent"
                return ManifestVerification("tampered", reason, version, build_id, installer_identity)
            Ed25519PublicKey.from_public_bytes(key_bytes).verify(
                base64.b64decode(encoded, validate=True), _canonical_unsigned_payload(payload)
            )
            signature_state = "valid"
        elif require_signature:
            return ManifestVerification(
                "tampered", "release_manifest_unsigned", version, build_id, installer_identity, signature_state
            )

        if expected_installer_identity is not None and installer_identity != expected_installer_identity:
            return ManifestVerification(
                "tampered",
                "release_manifest_installer_identity_mismatch",
                version,
                build_id,
                installer_identity,
                signature_state,
            )
        # Both package builders stamp the exact release version into native metadata and this manifest.
        # Equality prevents a validly signed native binary from authenticating a different release payload.
        if expected_native_version is not None and manifest_version != Version(expected_native_version):
            return ManifestVerification(
                "tampered",
                "release_manifest_native_version_mismatch",
                version,
                build_id,
                installer_identity,
                signature_state,
            )
        if minimum_version is not None and manifest_version < Version(minimum_version):
            return ManifestVerification(
                "tampered",
                "release_manifest_version_rollback",
                version,
                build_id,
                installer_identity,
                signature_state,
            )

        files = payload.get("files")
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty array")
        if len(files) > _MAX_RUNTIME_FILES:
            return ManifestVerification(
                "tampered",
                "release_manifest_file_limit_exceeded",
                version,
                build_id,
                installer_identity,
                signature_state,
            )
        resolved_root = runtime_root.resolve(strict=True)
        resolved_manifest = manifest_path.resolve(strict=True)
        if not resolved_manifest.is_relative_to(resolved_root):
            return ManifestVerification(
                "tampered", "release_manifest_path_escape", version, build_id, installer_identity, signature_state
            )
        listed_paths: set[str] = set()
        total_runtime_bytes = 0
        for entry in files:
            if not isinstance(entry, dict):
                raise ValueError("file entry must be an object")
            relative = _valid_relative_path(entry.get("path"))
            digest = entry.get("sha256")
            if relative is None or not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("invalid file entry")
            if relative in listed_paths:
                return ManifestVerification(
                    "tampered",
                    "release_manifest_duplicate_path",
                    version,
                    build_id,
                    installer_identity,
                    signature_state,
                )
            listed_paths.add(relative)
            unresolved_candidate = resolved_root / relative
            if unresolved_candidate.is_symlink():
                return ManifestVerification(
                    "tampered", "release_manifest_path_escape", version, build_id, installer_identity, signature_state
                )
            if not unresolved_candidate.exists():
                return ManifestVerification(
                    "tampered",
                    "release_manifest_file_missing",
                    version,
                    build_id,
                    installer_identity,
                    signature_state,
                )
            candidate = unresolved_candidate.resolve(strict=True)
            if not candidate.is_relative_to(resolved_root) or not candidate.is_file():
                return ManifestVerification(
                    "tampered", "release_manifest_path_escape", version, build_id, installer_identity, signature_state
                )
            try:
                actual, hashed_bytes, metadata = _hash_regular_file(candidate, _MAX_RUNTIME_BYTES - total_runtime_bytes)
            except OverflowError:
                return ManifestVerification(
                    "tampered",
                    "release_manifest_size_limit_exceeded",
                    version,
                    build_id,
                    installer_identity,
                    signature_state,
                )
            total_runtime_bytes += hashed_bytes
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
            if actual != digest.lower():
                return ManifestVerification(
                    "tampered", "release_manifest_hash_mismatch", version, build_id, installer_identity, signature_state
                )
        actual_paths, coverage_error = _runtime_file_paths(resolved_root, resolved_manifest)
        if coverage_error is not None:
            return ManifestVerification(
                "tampered", coverage_error, version, build_id, installer_identity, signature_state
            )
        if actual_paths - listed_paths:
            return ManifestVerification(
                "tampered",
                "release_manifest_coverage_gap",
                version,
                build_id,
                installer_identity,
                signature_state,
            )
        if listed_paths - actual_paths:
            return ManifestVerification(
                "tampered",
                "release_manifest_file_missing",
                version,
                build_id,
                installer_identity,
                signature_state,
            )
        return ManifestVerification(
            "healthy", "release_manifest_valid", version, build_id, installer_identity, signature_state
        )
    except (OSError, ValueError, json.JSONDecodeError, InvalidSignature, InvalidVersion, binascii.Error):
        return ManifestVerification("tampered", "release_manifest_invalid")


__all__ = ["ManifestVerification", "verify_release_manifest"]
