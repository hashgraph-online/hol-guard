"""Read-only correlation-key access and proven request-ID adapters.

The resident creates the per-install key on its first evidence write
(``rust/crates/guard-runtime/src/hook_evidence_correlation.rs``). Python only
reads an existing key and derives the request handle it pairs evidence by.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Final, cast

from ..private_file_io import read_private_regular_bytes
from .command_activity_contract import CorrelationHandle, CorrelationKind
from .command_activity_privacy import (
    InstallationCorrelationKey,
    StrongHarnessIdentifier,
    derive_correlation_handle,
)

COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION: Final = "guard.command-activity-correlation-key.v1"
COMMAND_ACTIVITY_CORRELATION_KEY_FILE: Final = "command-activity-correlation-key.json"

# Only native, top-level request identifiers documented by these hook adapters
# can pair pre- and post-execution evidence. Content and session fields are absent.
_PROVEN_REQUEST_ID_FIELDS: Final[dict[tuple[str, str], str]] = {
    ("grok", "PreToolUse"): "toolUseId",
    ("grok", "PostToolUse"): "toolUseId",
    ("grok", "PostToolUseFailure"): "toolUseId",
    ("zcode", "PreToolUse"): "tool_use_id",
    ("zcode", "PostToolUse"): "tool_use_id",
    ("zcode", "PostToolUseFailure"): "tool_use_id",
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
    ("omp", "PreToolUse"): "tool_call_id",
    ("omp", "PostToolUse"): "tool_call_id",
}


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


def load_existing_installation_correlation_key(guard_home: Path) -> InstallationCorrelationKey | None:
    """Read existing private correlation material without creation or chmod.

    Used by a locally authorized functional observer, never for diagnostics or
    to repair missing authority. Missing or unsafe files remain unavailable.
    """
    raw = read_private_regular_bytes(
        guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE,
        max_bytes=4096,
        require_private_parent=True,
    )
    if raw is None:
        return None
    return _parse_key(raw.decode("ascii"))


def _parse_key(raw: str) -> InstallationCorrelationKey:
    try:
        raw_payload = cast(object, json.loads(raw))
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


__all__ = [
    "COMMAND_ACTIVITY_CORRELATION_KEY_FILE",
    "COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION",
    "derive_proven_request_correlation",
    "load_existing_installation_correlation_key",
]
