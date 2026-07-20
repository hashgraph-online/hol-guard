"""Authenticated local identity records for Guard-managed Codex hooks.

The Codex configuration is user-editable and therefore cannot establish Guard
ownership by itself.  This module keeps the ownership authority in a private,
Guard-owned key file and authenticates canonical manifests with HMAC-SHA256.
Manifests contain only public identity material; the HMAC key is never copied
into Codex configuration or returned by status APIs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .codex_hook_file_integrity import CodexHookIntegrityError, canonical_path
from .local_authority_integrity import (
    LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM,
    sign_local_authority_payload,
    verify_local_authority_payload,
)

HOOK_MANIFEST_SCHEMA_VERSION = 2
HOOK_MANIFEST_MAC_ALGORITHM = LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM
_HOOK_SECRET_SCHEMA_VERSION = 1
_HOOK_KEY_BYTES = 32
_HOOK_MANIFEST_INTEGRITY_PURPOSE = "codex-managed-hook-manifest"
_PRIVATE_FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class HookSecretMaterial:
    installation_id: str
    key_id: str
    key: bytes = field(repr=False)


def hook_manifest_path(guard_home: Path, config_path: Path) -> Path:
    target_hash = hashlib.sha256(canonical_path(config_path).encode("utf-8")).hexdigest()[:24]
    return guard_home / "managed" / "codex" / f"hooks-{target_hash}.manifest.json"


def hook_secret_path(guard_home: Path) -> Path:
    return guard_home / "managed" / "codex" / "hook-manifest.key"


def canonical_manifest_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_or_create_hook_secret(guard_home: Path) -> HookSecretMaterial:
    path = hook_secret_path(guard_home)
    _ensure_private_directory(path.parent, repair_mode=True)
    if path.exists() or path.is_symlink():
        return load_hook_secret(guard_home)

    payload = {
        "installation_id": secrets.token_hex(16),
        "key": base64.urlsafe_b64encode(secrets.token_bytes(_HOOK_KEY_BYTES)).decode("ascii"),
        "key_id": secrets.token_hex(12),
        "schema_version": _HOOK_SECRET_SCHEMA_VERSION,
    }
    encoded = canonical_manifest_bytes(payload) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    except FileExistsError:
        return load_hook_secret(guard_home)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, _PRIVATE_FILE_MODE)
        _fsync_directory(path.parent)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return _parse_hook_secret_payload(payload)


def load_hook_secret(guard_home: Path) -> HookSecretMaterial:
    path = hook_secret_path(guard_home)
    if not path.exists() and not path.is_symlink():
        raise CodexHookIntegrityError(
            "codex_hook_manifest_secret_missing",
            "The private Codex hook authentication key is missing; run `hol-guard install codex` to repair it.",
        )
    _ensure_private_directory(path.parent, repair_mode=False)
    _validate_private_regular_file(
        path,
        reason_prefix="codex_hook_manifest_secret",
        label="Codex hook authentication key",
    )
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexHookIntegrityError(
            "codex_hook_manifest_secret_invalid",
            "The private Codex hook authentication key is unreadable; repair the Codex installation.",
        ) from exc
    if not isinstance(value, dict):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_secret_invalid",
            "The private Codex hook authentication key has an invalid format; repair the Codex installation.",
        )
    return _parse_hook_secret_payload(value)


def sign_hook_manifest(unsigned_manifest: dict[str, object], secret: HookSecretMaterial) -> dict[str, object]:
    if "authentication" in unsigned_manifest:
        raise ValueError("Unsigned Codex hook manifests must not contain authentication metadata.")
    generated_at = unsigned_manifest.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise ValueError("Unsigned Codex hook manifests require a generation time.")
    payload = dict(unsigned_manifest)
    payload["authentication"] = {
        "algorithm": HOOK_MANIFEST_MAC_ALGORITHM,
        **sign_local_authority_payload(
            payload,
            key=secret.key,
            key_id=secret.key_id,
            purpose=_HOOK_MANIFEST_INTEGRITY_PURPOSE,
            signed_at=generated_at,
        ),
    }
    return payload


def load_authenticated_hook_manifest(
    guard_home: Path,
    config_path: Path,
) -> dict[str, object]:
    return load_authenticated_hook_manifest_path(guard_home, hook_manifest_path(guard_home, config_path))


def load_authenticated_hook_manifest_path(
    guard_home: Path,
    path: Path,
) -> dict[str, object]:
    """Authenticate an explicit private manifest path without creating state."""

    if not path.exists() and not path.is_symlink():
        raise CodexHookIntegrityError(
            "codex_hook_manifest_missing",
            "The authenticated Codex hook manifest is missing; run `hol-guard install codex` to repair it.",
        )
    _validate_private_regular_file(path, reason_prefix="codex_hook_manifest", label="Codex hook manifest")
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexHookIntegrityError(
            "codex_hook_manifest_invalid",
            "The authenticated Codex hook manifest is unreadable; run `hol-guard install codex` to repair it.",
        ) from exc
    if not isinstance(value, dict):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_invalid",
            "The authenticated Codex hook manifest has an invalid format; repair the Codex installation.",
        )
    manifest = {str(key): item for key, item in value.items() if isinstance(key, str)}
    authentication = manifest.get("authentication")
    if not isinstance(authentication, dict):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_authentication_missing",
            "The Codex hook manifest is not authenticated; run `hol-guard install codex` to repair it.",
        )
    algorithm = authentication.get("algorithm")
    if algorithm != HOOK_MANIFEST_MAC_ALGORITHM:
        raise CodexHookIntegrityError(
            "codex_hook_manifest_authentication_invalid",
            "The Codex hook manifest authentication metadata is invalid; repair the Codex installation.",
        )

    secret = load_hook_secret(guard_home)
    unsigned = dict(manifest)
    unsigned.pop("authentication", None)
    verification = verify_local_authority_payload(
        unsigned,
        authentication,
        key=secret.key,
        key_id=secret.key_id,
        purpose=_HOOK_MANIFEST_INTEGRITY_PURPOSE,
    )
    if verification.status == "missing_integrity":
        raise CodexHookIntegrityError(
            "codex_hook_manifest_authentication_invalid",
            "The Codex hook manifest authentication metadata is invalid; repair the Codex installation.",
        )
    if verification.status == "unknown_key":
        raise CodexHookIntegrityError(
            "codex_hook_manifest_key_mismatch",
            "The Codex hook manifest belongs to another Guard installation; run `hol-guard install codex`.",
        )
    if verification.status != "valid":
        raise CodexHookIntegrityError(
            "codex_hook_manifest_mac_invalid",
            "The Codex hook manifest authentication failed; run `hol-guard install codex` to repair it.",
        )
    installation_id = manifest.get("installation_id")
    if not isinstance(installation_id, str) or not hmac.compare_digest(installation_id, secret.installation_id):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_installation_mismatch",
            "The Codex hook manifest belongs to another Guard installation; run `hol-guard install codex`.",
        )
    if authentication.get("signed_at") != manifest.get("generated_at"):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_authentication_invalid",
            "The Codex hook manifest generation binding is invalid; repair the Codex installation.",
        )
    return manifest


def write_hook_manifest(guard_home: Path, config_path: Path, manifest: dict[str, object]) -> Path:
    path = hook_manifest_path(guard_home, config_path)
    _ensure_private_directory(path.parent, repair_mode=True)
    atomic_write_bytes(path, canonical_manifest_bytes(manifest) + b"\n", mode=_PRIVATE_FILE_MODE, private=True)
    return path


def remove_hook_manifest(guard_home: Path, config_path: Path) -> None:
    path = hook_manifest_path(guard_home, config_path)
    if path.is_symlink():
        raise CodexHookIntegrityError(
            "codex_hook_manifest_not_regular",
            "Guard refused to remove a symlink in place of the Codex hook manifest.",
        )
    if path.exists():
        path.unlink()


def remove_hook_secret_if_unused(guard_home: Path) -> None:
    """Remove the private key after an explicit uninstall removes its last manifest."""

    path = hook_secret_path(guard_home)
    managed_directory = path.parent
    if not managed_directory.is_dir():
        return
    if any(
        candidate.exists() or candidate.is_symlink() for candidate in managed_directory.glob("hooks-*.manifest.json")
    ):
        return
    if not path.exists() and not path.is_symlink():
        return
    _validate_private_regular_file(
        path,
        reason_prefix="codex_hook_manifest_secret",
        label="Codex hook authentication key",
    )
    path.unlink()
    _fsync_directory(managed_directory)


def snapshot_regular_file(path: Path) -> bytes | None:
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise CodexHookIntegrityError(
            "codex_hook_manifest_not_regular",
            "Guard refused to replace a non-regular Codex hook manifest.",
        )
    return path.read_bytes()


def restore_private_file(path: Path, payload: bytes | None) -> None:
    if payload is None:
        if path.is_symlink():
            raise CodexHookIntegrityError(
                "codex_hook_manifest_not_regular",
                "Guard refused to replace a symlink in place of the Codex hook manifest.",
            )
        path.unlink(missing_ok=True)
        return
    atomic_write_bytes(path, payload, mode=_PRIVATE_FILE_MODE, private=True)


def atomic_write_text(path: Path, text: str, *, mode: int = _PRIVATE_FILE_MODE) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode, private=False)


def atomic_write_bytes(path: Path, payload: bytes, *, mode: int, private: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise CodexHookIntegrityError(
            "codex_hook_transaction_target_not_regular",
            f"Guard refused to replace a non-regular managed file at {path}.",
        )
    if private:
        _ensure_private_directory(path.parent, repair_mode=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def _parse_hook_secret_payload(payload: dict[str, Any]) -> HookSecretMaterial:
    version = payload.get("schema_version")
    installation_id = payload.get("installation_id")
    key_id = payload.get("key_id")
    encoded_key = payload.get("key")
    if (
        version != _HOOK_SECRET_SCHEMA_VERSION
        or not isinstance(installation_id, str)
        or len(installation_id) < 32
        or not isinstance(key_id, str)
        or len(key_id) < 24
        or not isinstance(encoded_key, str)
    ):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_secret_invalid",
            "The private Codex hook authentication key has an invalid format; repair the installation.",
        )
    try:
        key = base64.urlsafe_b64decode(encoded_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise CodexHookIntegrityError(
            "codex_hook_manifest_secret_invalid",
            "The private Codex hook authentication key has invalid encoding; repair the installation.",
        ) from exc
    if len(key) != _HOOK_KEY_BYTES:
        raise CodexHookIntegrityError(
            "codex_hook_manifest_secret_invalid",
            "The private Codex hook authentication key has an invalid length; repair the installation.",
        )
    return HookSecretMaterial(installation_id=installation_id, key_id=key_id, key=key)


def _ensure_private_directory(path: Path, *, repair_mode: bool) -> None:
    path.mkdir(parents=True, exist_ok=True)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_directory_unsafe",
            "The Codex managed-hook directory is not a private regular directory.",
        )
    if os.name == "nt":
        return
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    if current_uid is not None and metadata.st_uid != current_uid:
        raise CodexHookIntegrityError(
            "codex_hook_manifest_directory_owner_mismatch",
            "The Codex managed-hook directory has an unexpected owner.",
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077:
        if not repair_mode:
            raise CodexHookIntegrityError(
                "codex_hook_manifest_directory_permissions_unsafe",
                "The Codex managed-hook directory permissions are not owner-only.",
            )
        # Owner-only access is required for this secret-bearing directory; the
        # generic file-permission rule incorrectly recommends world-readable
        # 0644, which is both unsuitable for a directory and less restrictive.
        os.chmod(path, 0o700)  # nosemgrep


def _validate_private_regular_file(path: Path, *, reason_prefix: str, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CodexHookIntegrityError(f"{reason_prefix}_missing", f"The {label} is missing.") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CodexHookIntegrityError(
            f"{reason_prefix}_not_regular",
            f"The {label} must be a private regular file, not a symlink.",
        )
    if os.name == "nt":
        return
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    if current_uid is not None and metadata.st_uid != current_uid:
        raise CodexHookIntegrityError(
            f"{reason_prefix}_owner_mismatch",
            f"The {label} has an unexpected owner.",
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CodexHookIntegrityError(
            f"{reason_prefix}_permissions_unsafe",
            f"The {label} permissions are not owner-only.",
        )


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "HOOK_MANIFEST_MAC_ALGORITHM",
    "HOOK_MANIFEST_SCHEMA_VERSION",
    "CodexHookIntegrityError",
    "HookSecretMaterial",
    "atomic_write_text",
    "canonical_path",
    "hook_manifest_path",
    "hook_secret_path",
    "load_authenticated_hook_manifest",
    "load_authenticated_hook_manifest_path",
    "load_or_create_hook_secret",
    "remove_hook_manifest",
    "remove_hook_secret_if_unused",
    "restore_private_file",
    "sign_hook_manifest",
    "snapshot_regular_file",
    "write_hook_manifest",
]
