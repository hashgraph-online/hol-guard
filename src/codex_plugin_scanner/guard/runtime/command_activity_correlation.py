# pyright: reportPrivateUsage=false
"""Private correlation-key lifecycle and proven request-ID adapters."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Final, cast

from .command_activity_contract import CorrelationHandle, CorrelationKind
from .command_activity_privacy import (
    InstallationCorrelationKey,
    StrongHarnessIdentifier,
    derive_correlation_handle,
)

COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION: Final = "guard.command-activity-correlation-key.v1"
COMMAND_ACTIVITY_CORRELATION_KEY_FILE: Final = "command-activity-correlation-key.json"
_PRIVATE_FILE_MODE: Final = 0o600
_PRIVATE_DIRECTORY_MODE: Final = 0o700
_KEY_BYTES: Final = 32

# Only native, top-level request identifiers documented by these hook adapters
# can pair pre- and post-execution evidence. Content and session fields are absent.
_PROVEN_REQUEST_ID_FIELDS: Final[dict[tuple[str, str], str]] = {
    ("codex", "PreToolUse"): "tool_call_id",
    ("codex", "PostToolUse"): "tool_call_id",
    ("codex", "PostToolUseFailure"): "tool_call_id",
    ("claude-code", "PreToolUse"): "tool_use_id",
    ("claude-code", "PostToolUse"): "tool_use_id",
    ("claude-code", "PostToolUseFailure"): "tool_use_id",
    ("cursor", "PreToolUse"): "generation_id",
    ("cursor", "afterShellExecution"): "generation_id",
    ("cursor", "afterMCPExecution"): "generation_id",
    ("pi", "PreToolUse"): "tool_call_id",
    ("pi", "PostToolUse"): "tool_call_id",
}


def load_or_create_installation_correlation_key(guard_home: Path) -> InstallationCorrelationKey:
    """Load one per-install key, creating it without exposing partial contents."""

    key_path = _prepare_key_path(guard_home)
    try:
        return _read_key(key_path)
    except FileNotFoundError:
        pass

    generated = _new_key()
    temporary_path = _write_private_temporary(key_path, _serialize_key(generated))
    try:
        try:
            os.link(temporary_path, key_path)
            _set_private_mode(key_path)
            _fsync_directory(key_path.parent)
            return generated
        except FileExistsError:
            return _read_key(key_path)
    finally:
        with suppress(OSError):
            temporary_path.unlink()


def rotate_installation_correlation_key(guard_home: Path) -> InstallationCorrelationKey:
    """Atomically replace the active key and return its new versioned identity."""

    key_path = _prepare_key_path(guard_home)
    generated = _new_key()
    temporary_path = _write_private_temporary(key_path, _serialize_key(generated))
    try:
        os.replace(temporary_path, key_path)
        _set_private_mode(key_path)
        _fsync_directory(key_path.parent)
    finally:
        with suppress(OSError):
            temporary_path.unlink()
    return generated


def derive_proven_request_correlation(
    *,
    harness: str,
    event: str,
    payload: Mapping[str, object],
    key: InstallationCorrelationKey,
) -> CorrelationHandle | None:
    """Derive a handle only from an allowlisted native top-level request ID."""

    field = _PROVEN_REQUEST_ID_FIELDS.get((harness, event))
    if field is None:
        return None
    if (
        harness == "cursor"
        and event == "PreToolUse"
        and payload.get("cursor_source_hook_event")
        not in {
            "beforeShellExecution",
            "beforeMCPExecution",
        }
    ):
        return None
    value = payload.get(field)
    if value is None:
        return None
    if type(value) is not str:
        raise ValueError(f"{harness} {event} {field} must be an exact string")
    identifier = StrongHarnessIdentifier(
        harness=harness,
        kind=CorrelationKind.REQUEST,
        value=value,
    )
    return derive_correlation_handle(identifier, key)


def _prepare_key_path(guard_home: Path) -> Path:
    guard_home.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIRECTORY_MODE)
    if not guard_home.is_dir():
        raise ValueError("guard_home must be a directory")
    return guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE


def _new_key() -> InstallationCorrelationKey:
    material = secrets.token_bytes(_KEY_BYTES)
    fingerprint = hashlib.sha256(material).hexdigest()[:16]
    return InstallationCorrelationKey(key_id=f"correlation.v1.{fingerprint}", material=material)


def _serialize_key(key: InstallationCorrelationKey) -> bytes:
    material = key._material
    payload = {
        "schema_version": COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION,
        "key_id": key.key_id,
        "material": base64.b64encode(material).decode("ascii"),
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _read_key(path: Path) -> InstallationCorrelationKey:
    file_stat = path.lstat()
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError("command activity correlation key must be a regular file")
    _set_private_mode(path)
    try:
        raw_payload = cast(object, json.loads(path.read_text(encoding="ascii")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid command activity correlation key file") from error
    if not isinstance(raw_payload, dict):
        raise ValueError("invalid command activity correlation key file shape")
    payload = cast(dict[object, object], raw_payload)
    if set(payload) != {"schema_version", "key_id", "material"}:
        raise ValueError("invalid command activity correlation key file shape")
    if payload["schema_version"] != COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION:
        raise ValueError("unsupported command activity correlation key schema")
    key_id = payload["key_id"]
    encoded_material = payload["material"]
    if type(key_id) is not str or type(encoded_material) is not str:
        raise ValueError("invalid command activity correlation key fields")
    try:
        material = base64.b64decode(encoded_material, validate=True)
    except ValueError as error:
        raise ValueError("invalid command activity correlation key material") from error
    key = InstallationCorrelationKey(key_id=key_id, material=material)
    expected_id = f"correlation.v1.{hashlib.sha256(material).hexdigest()[:16]}"
    if key.key_id != expected_id:
        raise ValueError("command activity correlation key identity does not match its material")
    return key


def _write_private_temporary(path: Path, payload: bytes) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            _ = handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary_path
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            temporary_path.unlink()
        raise


def _set_private_mode(path: Path) -> None:
    if os.name != "nt":
        os.chmod(path, _PRIVATE_FILE_MODE, follow_symlinks=False)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "COMMAND_ACTIVITY_CORRELATION_KEY_FILE",
    "COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION",
    "derive_proven_request_correlation",
    "load_or_create_installation_correlation_key",
    "rotate_installation_correlation_key",
]
