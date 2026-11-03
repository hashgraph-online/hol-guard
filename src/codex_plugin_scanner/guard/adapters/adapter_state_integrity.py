"""Authentication for adapter lifecycle state containing filesystem paths.

An adapter's manifest records the configuration file Guard took over and the
backup it will restore, so a manifest an attacker can edit names a file Guard
overwrites during install, repair or uninstall. The MAC that stops that is
computed and compared in the native runtime; this module resolves the key file
the runtime signs with, and applies the verdict it returns. Without the
runtime there is no verdict, so nothing authenticates.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import stat
from pathlib import Path

from ...path_support import read_text_file_within_root
from ..native_adapter_state_integrity import (
    AdapterStateIntegrityUnavailableError,
    adapter_state_runtime_available,
    native_adapter_state_integrity,
)
from .base import _ensure_path_within_root

_SCHEMA_VERSION = 1
_KEY_BYTES = 32
_KEY_FILENAME = "adapter-state.key"


def require_adapter_state_runtime(guard_home: Path) -> None:
    """Refuse a lifecycle change nothing will be able to authenticate.

    An install writes the harness configuration first and stamps its manifest
    last, so a resident that cannot answer turns the whole install into a
    half-applied one: the user's configuration is changed and no authenticated
    state records what to put back. Asking first keeps that failure before the
    first write.
    """

    if not adapter_state_runtime_available(guard_home):
        raise AdapterStateIntegrityUnavailableError


def authenticate_adapter_state(
    guard_home: Path,
    *,
    harness: str,
    payload: dict[str, object],
    create_key: bool = True,
) -> dict[str, object]:
    """Return ``payload`` with the authentication block the runtime computed."""

    key_id, key = _load_or_create_key(guard_home) if create_key else _load_key(guard_home)
    return native_adapter_state_integrity(
        action="authenticate",
        harness=harness,
        payload=payload,
        integrity_key_b64=_wire_key(key),
        integrity_key_id=key_id,
        guard_home=guard_home,
    )


def adapter_state_is_authenticated(
    guard_home: Path,
    *,
    harness: str,
    payload: dict[str, object],
) -> bool:
    """Whether the runtime recomputes the manifest's own authentication block."""

    return _answer(guard_home, action="verify", harness=harness, payload=payload) is not None


def authenticated_adapter_path(
    guard_home: Path,
    *,
    harness: str,
    payload: dict[str, object],
    field: str,
) -> Path | None:
    """Return a canonical path only when its complete state payload authenticates."""

    answer = _answer(guard_home, action="authenticated_field", harness=harness, payload=payload, field=field)
    if answer is None:
        return None
    value = answer.get("value")
    if not isinstance(value, str):
        return None
    stored = Path(value)
    if not stored.is_absolute():
        # The runtime accepts either family's spelling, because a manifest can
        # be carried between machines. Resolution happens here, against this
        # host, where a foreign spelling such as ``C:\\Users\\dev\\x`` is a
        # relative path and would resolve against the working directory.
        return None
    # The runtime authenticated this complete payload, and rejected a relative
    # path or one carrying a NUL, before the stored path is resolved here.
    # Sonar cannot model that application-level sanitizer.
    return stored.resolve()  # NOSONAR


def _answer(
    guard_home: Path,
    *,
    action: str,
    harness: str,
    payload: dict[str, object],
    field: str | None = None,
) -> dict[str, object] | None:
    """The runtime's answer, or ``None`` when it did not authenticate the state.

    A missing key file and an unusable one are the same answer here: the
    stored state is not Guard's own. An unavailable runtime is not. It is no
    answer at all, and callers act on "not Guard's own" by discarding the
    state — Hermes falls back to legacy cleanup and deletes the saved previous
    section, Copilot skips the backup it would have restored — so the error
    travels instead of being read as a verdict nothing produced.
    """

    try:
        key_id, key = _load_key(guard_home)
    except (OSError, ValueError):
        return None
    answer = native_adapter_state_integrity(
        action=action,
        harness=harness,
        payload=payload,
        field=field,
        integrity_key_b64=_wire_key(key),
        integrity_key_id=key_id,
        guard_home=guard_home,
    )
    return answer if answer.get("authenticated") is True else None


def _wire_key(key: bytes) -> str:
    """The key as the runtime decodes it: unpadded URL-safe base64."""

    return base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")


def _key_path(guard_home: Path) -> Path:
    return guard_home / "managed" / _KEY_FILENAME


def _load_or_create_key(guard_home: Path) -> tuple[str, bytes]:
    path = _key_path(guard_home)
    _ensure_path_within_root(guard_home, path, label="adapter state key")
    if os.name == "posix":
        parent_descriptor = _private_key_directory_descriptor(path.parent, create=True)
        try:
            payload: dict[str, object] = {
                "key": base64.urlsafe_b64encode(secrets.token_bytes(_KEY_BYTES)).decode("ascii"),
                "key_id": secrets.token_hex(12),
                "schema_version": _SCHEMA_VERSION,
            }
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            try:
                descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
            except FileExistsError:
                return _load_key_from_descriptor(parent_descriptor)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(payload, sort_keys=True) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path.name, dir_fd=parent_descriptor)
                raise
            return _parse_key(payload)
        finally:
            os.close(parent_descriptor)
    if path.exists() or path.is_symlink():
        return _load_key(guard_home)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        # Semgrep recommends 0o644 here, which would expose signing material;
        # owner-only access is required for authenticated adapter state.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path.parent, 0o700)
    payload: dict[str, object] = {
        "key": base64.urlsafe_b64encode(secrets.token_bytes(_KEY_BYTES)).decode("ascii"),
        "key_id": secrets.token_hex(12),
        "schema_version": _SCHEMA_VERSION,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return _load_key(guard_home)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return _parse_key(payload)


def _load_key(guard_home: Path) -> tuple[str, bytes]:
    path = _key_path(guard_home)
    _ensure_path_within_root(guard_home, path, label="adapter state key")
    if os.name == "posix":
        parent_descriptor = _private_key_directory_descriptor(path.parent, create=False)
        try:
            return _load_key_from_descriptor(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("adapter state key is not a regular file")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("adapter state key permissions are not private")
    value = json.loads(read_text_file_within_root(path.parent, path, max_bytes=16_384))
    if not isinstance(value, dict):
        raise ValueError("adapter state key has an invalid format")
    return _parse_key(value)


def _private_key_directory_descriptor(path: Path, *, create: bool) -> int:
    if create:
        path.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("adapter state key parent is not a directory")
        if create:
            # Owner-only access is required because this directory contains HMAC key material.
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.fchmod(descriptor, 0o700)
        elif stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("adapter state key parent permissions are not private")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _load_key_from_descriptor(parent_descriptor: int) -> tuple[str, bytes]:
    descriptor = os.open(
        _KEY_FILENAME,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_descriptor,
    )
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("adapter state key is not a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("adapter state key permissions are not private")
        raw = handle.read(16_385)
    if len(raw) > 16_384:
        raise ValueError("adapter state key has an invalid format")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("adapter state key has an invalid format") from error
    value = json.loads(decoded)
    if not isinstance(value, dict):
        raise ValueError("adapter state key has an invalid format")
    return _parse_key(value)


def _parse_key(payload: dict[str, object]) -> tuple[str, bytes]:
    key_id = payload.get("key_id")
    encoded = payload.get("key")
    if payload.get("schema_version") != _SCHEMA_VERSION or not isinstance(key_id, str) or not key_id:
        raise ValueError("adapter state key has invalid metadata")
    if not isinstance(encoded, str):
        raise ValueError("adapter state key has invalid key material")
    try:
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("adapter state key has invalid key material") from exc
    if len(key) != _KEY_BYTES:
        raise ValueError("adapter state key has invalid key length")
    return key_id, key
