"""Local hook payload reference hydration."""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Mapping
from pathlib import Path

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
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HookPayloadReferenceError("HOL Guard hook payload reference is not valid JSON.") from error
    if not isinstance(loaded, dict):
        raise HookPayloadReferenceError("HOL Guard hook payload reference must contain a JSON object.")
    return loaded


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
