"""Authentication for adapter lifecycle state containing filesystem paths."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path

from ...path_support import read_text_file_within_root
from .base import _ensure_path_within_root

_SCHEMA_VERSION = 1
_KEY_BYTES = 32
_KEY_FILENAME = "adapter-state.key"


def authenticate_adapter_state(
    guard_home: Path,
    *,
    harness: str,
    payload: dict[str, object],
) -> dict[str, object]:
    key_id, key = _load_or_create_key(guard_home)
    authenticated = dict(payload)
    authenticated["state_authentication"] = {
        "algorithm": "hmac-sha256",
        "key_id": key_id,
        "mac": hmac.new(key, _message(harness, payload), hashlib.sha256).hexdigest(),
        "schema_version": _SCHEMA_VERSION,
    }
    return authenticated


def adapter_state_is_authenticated(
    guard_home: Path,
    *,
    harness: str,
    payload: dict[str, object],
) -> bool:
    authentication = payload.get("state_authentication")
    if not isinstance(authentication, dict):
        return False
    unsigned = dict(payload)
    unsigned.pop("state_authentication", None)
    try:
        key_id, key = _load_key(guard_home)
    except (OSError, ValueError):
        return False
    supplied_key_id = authentication.get("key_id")
    supplied_mac = authentication.get("mac")
    if authentication.get("algorithm") != "hmac-sha256" or authentication.get("schema_version") != _SCHEMA_VERSION:
        return False
    if not isinstance(supplied_key_id, str) or not hmac.compare_digest(supplied_key_id, key_id):
        return False
    if not isinstance(supplied_mac, str):
        return False
    expected = hmac.new(key, _message(harness, unsigned), hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied_mac, expected)


def _message(harness: str, payload: dict[str, object]) -> bytes:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"hol-guard.adapter-state.v1\0{harness}\0{canonical}".encode()


def _key_path(guard_home: Path) -> Path:
    return guard_home / "managed" / _KEY_FILENAME


def _load_or_create_key(guard_home: Path) -> tuple[str, bytes]:
    path = _key_path(guard_home)
    _ensure_path_within_root(guard_home, path, label="adapter state key")
    if path.exists() or path.is_symlink():
        return _load_key(guard_home)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
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
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("adapter state key is not a regular file")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("adapter state key permissions are not private")
    value = json.loads(read_text_file_within_root(path.parent, path, max_bytes=16_384))
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
