"""Authenticated local identity records for Guard-managed Codex hooks.

The Codex configuration is user-editable and therefore cannot establish Guard
ownership by itself.  Ownership rests on a private, Guard-owned key file that only the native
runtime creates, reads, signs with and removes; canonical manifests are
authenticated with HMAC-SHA256 under it. Python sees only the key's public
identity, and the key is never copied into Codex configuration or returned
by status APIs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .codex_hook_file_integrity import CodexHookIntegrityError, canonical_path, check_hook_validation_deadline
from .codex_install_transaction import record_codex_mutation
from .durable_io import fsync_directory as _fsync_directory
from .local_authority_integrity import (
    LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM,
    LOCAL_AUTHORITY_INTEGRITY_UNAVAILABLE,
    sign_local_authority_payload,
    verify_local_authority_payload,
)
from .private_file_io import read_private_regular_text

HOOK_MANIFEST_SCHEMA_VERSION = 2
HOOK_MANIFEST_MAC_ALGORITHM = LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM
_HOOK_MANIFEST_INTEGRITY_PURPOSE = "codex-managed-hook-manifest"
_PRIVATE_FILE_MODE = 0o600
_MAX_HOOK_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class HookSecretMaterial:
    """The Codex hook key's public identity; the native runtime alone holds the key."""

    installation_id: str
    key_id: str
    fingerprint: str
    guard_home: Path = field(compare=False)


_KEY_MISSING_MESSAGE = (
    "The private Codex hook authentication key is missing; run `hol-guard install codex` to repair it."
)
_KEY_UNAVAILABLE_REASONS = frozenset({"runtime_unavailable", "invalid"})


def hook_manifest_path(guard_home: Path, config_path: Path) -> Path:
    target_hash = hashlib.sha256(canonical_path(config_path).encode("utf-8")).hexdigest()[:24]
    return guard_home / "managed" / "codex" / f"hooks-{target_hash}.manifest.json"


def hook_secret_path(guard_home: Path) -> Path:
    return guard_home / "managed" / "codex" / "hook-manifest.key"


def hook_authority_receipt_path(guard_home: Path, config_path: Path) -> Path:
    manifest = hook_manifest_path(guard_home, config_path)
    return manifest.with_name(manifest.name.replace(".manifest.json", ".authority-receipt.json"))


def canonical_manifest_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_or_create_hook_secret(guard_home: Path) -> HookSecretMaterial:
    with _ordinary_hook_writer(guard_home, hook_secret_path(guard_home), actor="codex.authority-key"):
        return _hook_key("key_ensure", guard_home)


@contextmanager
def _ordinary_hook_writer(guard_home: Path, target: Path, *, actor: str) -> Iterator[None]:
    from .codex_install_transaction import codex_install_transaction
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(guard_home)
    with codex_install_transaction(guard_home, target, actor=actor):
        assert_transition_mutation_allowed(guard_home)
        yield


def load_hook_secret(guard_home: Path) -> HookSecretMaterial:
    return _hook_key("key_identity", guard_home)


def _home_text(guard_home: Path) -> str:
    return os.path.abspath(guard_home)


_KeyOp = Literal["key_identity", "key_ensure", "key_remove_if_unused"]


def _hook_key_answer(op: _KeyOp, guard_home: Path) -> dict[str, object]:
    from .codex_hook_authority_record import AuthorityRecordRefusedError, hook_key_answer

    try:
        return hook_key_answer(op, _home_text(guard_home))
    except AuthorityRecordRefusedError as exc:
        if exc.reason in _KEY_UNAVAILABLE_REASONS:
            raise CodexHookIntegrityError(
                "codex_hook_manifest_verification_unavailable",
                "Guard's native runtime did not answer for the Codex hook key; run `hol-guard repair`.",
            ) from exc
        message = (
            _KEY_MISSING_MESSAGE
            if exc.reason == "codex_hook_manifest_secret_missing"
            else "The private Codex hook authentication key is not usable; repair the Codex installation."
        )
        raise CodexHookIntegrityError(exc.reason, message) from exc


def _hook_key(op: _KeyOp, guard_home: Path) -> HookSecretMaterial:
    answer = _hook_key_answer(op, guard_home)
    fields = (answer.get("installation_id"), answer.get("key_id"), answer.get("fingerprint"))
    if not all(isinstance(value, str) and value for value in fields):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_verification_unavailable",
            "Guard's native runtime did not answer for the Codex hook key; run `hol-guard repair`.",
        )
    installation_id, key_id, fingerprint = (str(value) for value in fields)
    return HookSecretMaterial(installation_id, key_id, fingerprint, guard_home)


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
            key_home=_home_text(secret.guard_home),
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

    check_hook_validation_deadline()
    if not path.exists() and not path.is_symlink():
        raise CodexHookIntegrityError(
            "codex_hook_manifest_missing",
            "The authenticated Codex hook manifest is missing; run `hol-guard install codex` to repair it.",
        )
    _validate_private_regular_file(path, reason_prefix="codex_hook_manifest", label="Codex hook manifest")
    raw = read_private_regular_text(path, max_bytes=_MAX_HOOK_MANIFEST_BYTES)
    check_hook_validation_deadline()
    if raw is None:
        raise CodexHookIntegrityError(
            "codex_hook_manifest_invalid",
            "The authenticated Codex hook manifest is unreadable; run `hol-guard install codex` to repair it.",
        )
    return authenticate_hook_manifest_text(guard_home, raw)


def authenticate_hook_manifest_text(
    guard_home: Path,
    raw: str,
    *,
    _secret: HookSecretMaterial | None = None,
) -> dict[str, object]:
    """Authenticate bounded captured text; this does not validate its file or package."""
    check_hook_validation_deadline()
    if len(raw.encode("utf-8")) > _MAX_HOOK_MANIFEST_BYTES:
        raise CodexHookIntegrityError("codex_hook_manifest_invalid", "Codex hook manifest exceeds its read limit.")
    try:
        value: object = json.loads(raw)
    except json.JSONDecodeError as exc:
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

    check_hook_validation_deadline()
    secret = load_hook_secret(guard_home) if _secret is None else _secret
    check_hook_validation_deadline()
    unsigned = dict(manifest)
    unsigned.pop("authentication", None)
    verification = verify_local_authority_payload(
        unsigned,
        authentication,
        key_home=_home_text(secret.guard_home),
        key_id=secret.key_id,
        purpose=_HOOK_MANIFEST_INTEGRITY_PURPOSE,
    )
    if verification.message == LOCAL_AUTHORITY_INTEGRITY_UNAVAILABLE:
        # No runtime answered, so no key was compared: report the deadline or
        # the missing verifier, never another installation's manifest.
        check_hook_validation_deadline()
        raise CodexHookIntegrityError(
            "codex_hook_manifest_verification_unavailable",
            "Guard could not verify the Codex hook installation; run repair and retry.",
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
    check_hook_validation_deadline()
    return manifest


def write_hook_manifest(guard_home: Path, config_path: Path, manifest: dict[str, object]) -> Path:
    with _ordinary_hook_writer(guard_home, config_path, actor="codex.authority-manifest"):
        return _write_hook_manifest_owned(guard_home, config_path, manifest)


def _write_hook_manifest_owned(guard_home: Path, config_path: Path, manifest: dict[str, object]) -> Path:
    path = hook_manifest_path(guard_home, config_path)
    _ensure_private_directory(path.parent, repair_mode=True)
    atomic_write_bytes(path, canonical_manifest_bytes(manifest) + b"\n", mode=_PRIVATE_FILE_MODE, private=True)
    return path


def remove_hook_manifest(guard_home: Path, config_path: Path) -> None:
    with _ordinary_hook_writer(guard_home, config_path, actor="codex.remove-manifest"):
        _remove_hook_manifest_owned(guard_home, config_path)


def _remove_hook_manifest_owned(guard_home: Path, config_path: Path) -> None:
    path = hook_manifest_path(guard_home, config_path)
    receipt = hook_authority_receipt_path(guard_home, config_path)
    if path.is_symlink() or receipt.is_symlink():
        raise CodexHookIntegrityError(
            "codex_hook_manifest_not_regular",
            "Guard refused to remove a symlink in place of the Codex hook manifest.",
        )
    # Explicit uninstall revokes the retained authority before removing the
    # live manifest. A crash can leave protection without a repair receipt,
    # but cannot leave a receipt behind after successful removal.
    if receipt.exists():
        before_receipt = snapshot_regular_file(receipt)
        receipt.unlink()
        _fsync_directory(receipt.parent)
        record_codex_mutation("remove_authority_receipt", receipt, before_receipt, None)
    if path.exists():
        before = snapshot_regular_file(path)
        path.unlink()
        _fsync_directory(path.parent)
        record_codex_mutation("remove_manifest", path, before, None)


def remove_hook_secret_if_unused(guard_home: Path) -> None:
    """Remove the private key after an explicit uninstall removes its last manifest."""

    with _ordinary_hook_writer(guard_home, hook_secret_path(guard_home), actor="codex.remove-unused-key"):
        _remove_hook_secret_if_unused_owned(guard_home)


def _remove_hook_secret_if_unused_owned(guard_home: Path) -> None:
    if _hook_key_answer("key_remove_if_unused", guard_home).get("removed") is True:
        record_codex_mutation("remove_unused_key", hook_secret_path(guard_home), b"", None)


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
        before = snapshot_regular_file(path) if path.name != "hook-manifest.key" else (b"" if path.exists() else None)
        path.unlink(missing_ok=True)
        if path.parent.exists():
            _fsync_directory(path.parent)
        record_codex_mutation("restore_absent", path, before, None)
        return
    atomic_write_bytes(path, payload, mode=_PRIVATE_FILE_MODE, private=True)


def atomic_write_text(
    path: Path,
    text: str,
    *,
    mode: int = _PRIVATE_FILE_MODE,
    on_publish: Callable[[tuple[int, int, int, int, int]], None] | None = None,
) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode, private=False, on_publish=on_publish)


def atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    private: bool,
    on_publish: Callable[[tuple[int, int, int, int, int]], None] | None = None,
    before_publish: Callable[[], None] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise CodexHookIntegrityError(
            "codex_hook_transaction_target_not_regular",
            f"Guard refused to replace a non-regular managed file at {path}.",
        )
    if private:
        _ensure_private_directory(path.parent, repair_mode=True)
    before = snapshot_regular_file(path) if path.name != "hook-manifest.key" else (b"" if path.exists() else None)
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
            written = os.fstat(handle.fileno())
        if before_publish is not None:
            before_publish()
        os.replace(temporary_path, path)
        os.chmod(path, mode)
        if on_publish is not None:
            published = path.lstat()
            if (published.st_dev, published.st_ino, published.st_size, published.st_mtime_ns) != (
                written.st_dev,
                written.st_ino,
                written.st_size,
                written.st_mtime_ns,
            ):
                raise CodexHookIntegrityError(
                    "codex_hook_transaction_target_changed", "Codex configuration changed during publication."
                )
            on_publish(
                (published.st_dev, published.st_ino, published.st_size, published.st_mtime_ns, published.st_ctime_ns)
            )
        _fsync_directory(path.parent)
        record_codex_mutation("publish", path, before, payload)
    finally:
        temporary_path.unlink(missing_ok=True)


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
