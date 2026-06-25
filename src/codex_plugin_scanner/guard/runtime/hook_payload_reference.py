"""Local hook payload reference hydration."""

from __future__ import annotations

import hashlib
import json
import tempfile
from base64 import urlsafe_b64decode
from collections.abc import Mapping
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOOK_PAYLOAD_REFERENCE_KEY = "guard_payload_ref"
MAX_HOOK_PAYLOAD_REFERENCE_BYTES = 5 * 1024 * 1024
_REFERENCE_DIR_PREFIX = "hol-guard-hook-payload-"


class HookPayloadReferenceError(ValueError):
    """Raised when a hook payload reference cannot be safely hydrated."""


def hydrate_hook_payload_reference(payload: Mapping[str, object]) -> dict[str, object]:
    ref = payload.get(HOOK_PAYLOAD_REFERENCE_KEY)
    if not isinstance(ref, Mapping):
        return dict(payload)
    path_value = ref.get("path")
    sha256_value = ref.get("sha256")
    if ref.get("version") != 1 or not isinstance(path_value, str) or not isinstance(sha256_value, str):
        raise HookPayloadReferenceError("Invalid HOL Guard hook payload reference metadata.")
    expected_sha256 = sha256_value.strip().lower()
    if len(expected_sha256) != 64 or any(char not in "0123456789abcdef" for char in expected_sha256):
        raise HookPayloadReferenceError("Invalid HOL Guard hook payload reference digest.")
    path = _safe_reference_path(path_value)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise HookPayloadReferenceError("HOL Guard hook payload reference is not readable.") from error
    if size > MAX_HOOK_PAYLOAD_REFERENCE_BYTES:
        raise HookPayloadReferenceError("HOL Guard hook payload reference exceeds the safe local size limit.")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise HookPayloadReferenceError("HOL Guard hook payload reference is not readable.") from error
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise HookPayloadReferenceError("HOL Guard hook payload reference digest mismatch.")
    if ref.get("encryption") == "aes-256-gcm":
        raw = _decrypt_payload_reference(raw, ref)
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HookPayloadReferenceError("HOL Guard hook payload reference is not valid JSON.") from error
    if not isinstance(loaded, dict):
        raise HookPayloadReferenceError("HOL Guard hook payload reference must contain a JSON object.")
    return loaded


def _decrypt_payload_reference(raw: bytes, ref: Mapping[str, object]) -> bytes:
    key = _base64url_bytes(ref.get("key"), expected_length=32, label="key")
    nonce = _base64url_bytes(ref.get("nonce"), expected_length=12, label="nonce")
    try:
        return AESGCM(key).decrypt(nonce, raw, None)
    except ValueError as error:
        raise HookPayloadReferenceError("HOL Guard hook payload reference could not be decrypted.") from error


def _base64url_bytes(value: object, *, expected_length: int, label: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise HookPayloadReferenceError(f"HOL Guard hook payload reference missing encryption {label}.")
    padded = value.strip() + "=" * (-len(value.strip()) % 4)
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise HookPayloadReferenceError(f"HOL Guard hook payload reference has invalid encryption {label}.") from error
    if len(decoded) != expected_length:
        raise HookPayloadReferenceError(f"HOL Guard hook payload reference has invalid encryption {label}.")
    return decoded


def _safe_reference_path(path_value: str) -> Path:
    try:
        path = Path(path_value).resolve(strict=True)
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    except OSError as error:
        raise HookPayloadReferenceError("HOL Guard hook payload reference path is invalid.") from error
    parent = path.parent
    if parent.parent != temp_root or not parent.name.startswith(_REFERENCE_DIR_PREFIX):
        raise HookPayloadReferenceError("HOL Guard hook payload reference must be in a Guard-owned temp directory.")
    if not path.is_file():
        raise HookPayloadReferenceError("HOL Guard hook payload reference must be a file.")
    return path
