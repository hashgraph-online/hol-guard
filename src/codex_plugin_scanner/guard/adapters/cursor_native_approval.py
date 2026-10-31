"""Cursor hook attestation key: the secret the hook script signs observer proofs with."""

from __future__ import annotations

import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

_CURSOR_HOOK_ATTESTATION_RELATIVE = Path("secrets") / "cursor-hook-attestation.key"


def cursor_hook_attestation_secret_path(guard_home: Path) -> Path:
    return guard_home / _CURSOR_HOOK_ATTESTATION_RELATIVE


_ATTESTATION_SECRET_MAX_BYTES = 4096


def _attestation_open_flags(extra: int) -> int:
    return extra | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _unlink_attestation_secret(secret_path: Path) -> None:
    try:
        secret_path.unlink()
    except FileNotFoundError:
        return


def _read_private_attestation_secret(secret_path: Path) -> bytes | None:
    """Return a key the resident can verify, or nothing when it cannot."""

    try:
        info = secret_path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        if os.name == "posix":
            _unlink_attestation_secret(secret_path)
        return None
    if os.name == "posix":
        if info.st_uid != os.getuid():
            _unlink_attestation_secret(secret_path)
            return None
        if info.st_mode & 0o077:
            try:
                os.chmod(secret_path, 0o600)
            except OSError:
                _unlink_attestation_secret(secret_path)
                return None
    try:
        descriptor = os.open(secret_path, _attestation_open_flags(os.O_RDONLY))
    except OSError:
        if os.name == "posix":
            _unlink_attestation_secret(secret_path)
        return None
    try:
        with os.fdopen(descriptor, "rb") as handle:
            existing = handle.read(_ATTESTATION_SECRET_MAX_BYTES + 1)
            confirmed = os.fstat(handle.fileno()) if os.name == "posix" else None
    except OSError:
        return None
    if confirmed is not None and (
        not stat.S_ISREG(confirmed.st_mode) or confirmed.st_uid != os.getuid() or confirmed.st_mode & 0o077
    ):
        _unlink_attestation_secret(secret_path)
        return None
    if not existing or len(existing) > _ATTESTATION_SECRET_MAX_BYTES:
        _unlink_attestation_secret(secret_path)
        return None
    return existing


def _write_attestation_secret(secret_path: Path, generated: bytes) -> None:
    try:
        descriptor = os.open(
            secret_path,
            _attestation_open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
        )
    except OSError:
        descriptor = os.open(secret_path, _attestation_open_flags(os.O_WRONLY | os.O_TRUNC), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(generated)
            handle.flush()
            if os.name != "posix":
                return
            os.fchmod(handle.fileno(), 0o600)
            if os.fstat(handle.fileno()).st_mode & 0o077:
                raise OSError("attestation key mode is not private")
    except OSError:
        with suppress(OSError):
            secret_path.unlink()
        raise


def ensure_cursor_hook_attestation_secret(guard_home: Path) -> bytes:
    secret_path = cursor_hook_attestation_secret_path(guard_home)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_private_attestation_secret(secret_path)
    if existing is not None:
        return existing
    generated = secrets.token_bytes(32)
    _write_attestation_secret(secret_path, generated)
    return generated


__all__ = [
    "cursor_hook_attestation_secret_path",
    "ensure_cursor_hook_attestation_secret",
]
