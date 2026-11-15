"""Authenticated local identity records for Guard-managed Codex hooks.

The Codex configuration is user-editable and therefore cannot establish Guard
ownership by itself.  Ownership rests on a private, Guard-owned key file that only the native
runtime creates, reads, signs with and removes; canonical manifests are
authenticated with HMAC-SHA256 under it. Python sees only the key's public
identity, and the key is never copied into Codex configuration or returned
by status APIs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .codex_hook_file_integrity import CodexHookIntegrityError, canonical_path, check_hook_validation_deadline
from .codex_install_transaction import record_codex_mutation
from .local_authority_integrity import (
    LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM,
    sign_local_authority_payload,
)

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

    return _authenticated(guard_home, path=os.path.abspath(path))


def authenticate_hook_manifest_text(
    guard_home: Path,
    raw: str,
    *,
    _secret: HookSecretMaterial | None = None,
) -> dict[str, object]:
    """Authenticate bounded captured text; this does not validate its file or package."""

    if len(raw.encode("utf-8")) > _MAX_HOOK_MANIFEST_BYTES:
        raise CodexHookIntegrityError("codex_hook_manifest_invalid", "Codex hook manifest exceeds its read limit.")
    if _secret is None:
        return _authenticated(guard_home, text=raw)
    return _authenticated(_secret.guard_home, text=raw, key_id=_secret.key_id, installation_id=_secret.installation_id)


_REPAIR = "run `hol-guard install codex` to repair it."
_MANIFEST_MESSAGES = {
    "codex_hook_manifest_missing": f"The authenticated Codex hook manifest is missing; {_REPAIR}",
    "codex_hook_manifest_not_regular": "The Codex hook manifest must be a private regular file, not a symlink.",
    "codex_hook_manifest_owner_mismatch": "The Codex hook manifest has an unexpected owner.",
    "codex_hook_manifest_permissions_unsafe": "The Codex hook manifest permissions are not owner-only.",
    "codex_hook_manifest_invalid": f"The authenticated Codex hook manifest is unreadable; {_REPAIR}",
    "codex_hook_manifest_authentication_missing": f"The Codex hook manifest is not authenticated; {_REPAIR}",
    "codex_hook_manifest_authentication_invalid": (
        "The Codex hook manifest authentication metadata is invalid; repair the Codex installation."
    ),
    "codex_hook_manifest_key_mismatch": (
        "The Codex hook manifest belongs to another Guard installation; run `hol-guard install codex`."
    ),
    "codex_hook_manifest_installation_mismatch": (
        "The Codex hook manifest belongs to another Guard installation; run `hol-guard install codex`."
    ),
    "codex_hook_manifest_mac_invalid": f"The Codex hook manifest authentication failed; {_REPAIR}",
    "codex_hook_manifest_secret_missing": _KEY_MISSING_MESSAGE,
}


def _authenticated(guard_home: Path, **request: str | None) -> dict[str, object]:
    from .codex_hook_authority_record import AuthorityRecordRefusedError, authenticated_manifest

    check_hook_validation_deadline()
    try:
        manifest = authenticated_manifest(_home_text(guard_home), **request)
    except AuthorityRecordRefusedError as exc:
        check_hook_validation_deadline()
        if exc.reason in _KEY_UNAVAILABLE_REASONS:
            raise CodexHookIntegrityError(
                "codex_hook_manifest_verification_unavailable",
                "Guard could not verify the Codex hook installation; run repair and retry.",
            ) from exc
        message = _MANIFEST_MESSAGES.get(
            exc.reason, "The private Codex hook authentication key is not usable; repair the Codex installation."
        )
        raise CodexHookIntegrityError(exc.reason, message) from exc
    check_hook_validation_deadline()
    return manifest


def write_hook_manifest(guard_home: Path, config_path: Path, manifest: dict[str, object]) -> Path:
    with _ordinary_hook_writer(guard_home, config_path, actor="codex.authority-manifest"):
        return _write_hook_manifest_owned(guard_home, config_path, manifest)


def _write_hook_manifest_owned(guard_home: Path, config_path: Path, manifest: dict[str, object]) -> Path:
    path = hook_manifest_path(guard_home, config_path)
    atomic_write_bytes(path, canonical_manifest_bytes(manifest) + b"\n", mode=_PRIVATE_FILE_MODE, private=True)
    return path


def remove_hook_manifest(guard_home: Path, config_path: Path) -> None:
    with _ordinary_hook_writer(guard_home, config_path, actor="codex.remove-manifest"):
        _remove_hook_manifest_owned(guard_home, config_path)


def _remove_hook_manifest_owned(guard_home: Path, config_path: Path) -> None:
    # Explicit uninstall revokes the retained authority before removing the
    # live manifest. A crash can leave protection without a repair receipt,
    # but cannot leave a receipt behind after successful removal.
    _native("remove_manifest", guard_home, config=_path_text(config_path))


def remove_hook_secret_if_unused(guard_home: Path) -> None:
    """Remove the private key after an explicit uninstall removes its last manifest."""

    with _ordinary_hook_writer(guard_home, hook_secret_path(guard_home), actor="codex.remove-unused-key"):
        _remove_hook_secret_if_unused_owned(guard_home)


def _remove_hook_secret_if_unused_owned(guard_home: Path) -> None:
    if _hook_key_answer("key_remove_if_unused", guard_home).get("removed") is True:
        record_codex_mutation("remove_unused_key", hook_secret_path(guard_home), b"", None)


def restore_private_file(path: Path, payload: bytes | None) -> None:
    _native("restore", path.parent, path=_path_text(path), payload=_encode(payload))


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
    """Publish ``payload`` through the resident; it journals the write."""

    if before_publish is not None:
        before_publish()
    identity = _native(
        "write", path.parent, path=_path_text(path), payload=_encode(payload), mode=mode, private=private
    )
    if on_publish is not None:
        if not isinstance(identity, list) or len(identity) != 5 or not all(isinstance(part, int) for part in identity):
            raise CodexHookIntegrityError(
                "codex_hook_transaction_target_changed", "Codex configuration changed during publication."
            )
        on_publish((identity[0], identity[1], identity[2], identity[3], identity[4]))


def _path_text(path: Path) -> str:
    return os.path.abspath(path.expanduser())


def _encode(payload: bytes | None) -> str | None:
    return None if payload is None else base64.b64encode(payload).decode("ascii")


def _native(op: str, home: Path, **fields: object) -> object:
    from .native_transition_files import publication

    return publication(op, home, **fields)


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
    "write_hook_manifest",
]
