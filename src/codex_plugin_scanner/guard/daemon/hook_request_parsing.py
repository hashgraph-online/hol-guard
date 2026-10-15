"""Normalize daemon hook payloads into the native review request model."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..runtime.hook_review_types import (
    HookPayloadKind,
)
from ..runtime.local_temp_paths import trusted_temporary_root_for_path

HOOK_PAYLOAD_REFERENCE_KEY = "guard_payload_ref"
MAX_HOOK_PAYLOAD_REFERENCE_BYTES = 5 * 1024 * 1024
_REFERENCE_DIR_PREFIX = "hol-guard-hook-payload-"


class HookPayloadReferenceError(ValueError):
    """Raised when a hook payload reference cannot be safely validated."""


def hook_payload_reference_size(payload: Mapping[str, object]) -> int | None:
    """Return the conservative reservation required before reading a reference."""

    ref = payload.get(HOOK_PAYLOAD_REFERENCE_KEY)
    if not isinstance(ref, Mapping):
        return None
    _ = _validated_reference(ref)
    return MAX_HOOK_PAYLOAD_REFERENCE_BYTES


def _validated_reference(ref: Mapping[str, object]) -> tuple[Path, str]:
    path_value = ref.get("path")
    sha256_value = ref.get("sha256")
    if ref.get("version") != 1 or not isinstance(path_value, str) or not isinstance(sha256_value, str):
        raise HookPayloadReferenceError("Invalid HOL Guard hook payload reference metadata.")
    expected_sha256 = sha256_value.strip().lower()
    if len(expected_sha256) != 64 or any(char not in "0123456789abcdef" for char in expected_sha256):
        raise HookPayloadReferenceError("Invalid HOL Guard hook payload reference digest.")
    path = _safe_reference_path(path_value)
    return path, expected_sha256


def _safe_reference_path(path_value: str) -> Path:
    try:
        path = Path(path_value).resolve(strict=True)
        temp_root = trusted_temporary_root_for_path(path)
    except OSError as error:
        raise HookPayloadReferenceError("HOL Guard hook payload reference path is invalid.") from error
    parent = path.parent
    if temp_root is None or parent.parent != temp_root or not parent.name.startswith(_REFERENCE_DIR_PREFIX):
        raise HookPayloadReferenceError("HOL Guard hook payload reference must be in a Guard-owned temp directory.")
    if not path.is_file():
        raise HookPayloadReferenceError("HOL Guard hook payload reference must be a file.")
    return path


def runtime_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            raw = value.strip()
            compact = raw.lower().replace("_", "").replace("-", "")
            if compact in {
                "pretool",
                "pretooluse",
                "pretoolcall",
                "beforeshellexecution",
                "beforereadfile",
                "beforewritefile",
                "beforemcpexecution",
            }:
                return "PreToolUse"
            if compact in {
                "posttool",
                "posttooluse",
                "posttoolcall",
                "aftershellexecution",
                "afterreadfile",
                "afterwritefile",
                "aftermcpexecution",
            }:
                return "PostToolUse"
            if compact in {"permissionrequest", "permissionrequestv2"}:
                return "PermissionRequest"
            if compact in {"prompt", "userpromptsubmit", "userpromptsubmitted"}:
                return "UserPromptSubmit"
            return raw
    return "PreToolUse"


def payload_kind(payload: Mapping[str, object]) -> HookPayloadKind:
    if "guard_payload_ref" in payload:
        return "encrypted_payload_ref"
    if "guard_source_ref" in payload:
        return "source_file_ref"
    return "inline"


def pre_tool_input(payload: Mapping[str, object]) -> Mapping[str, object] | None:
    """Return the tool input for snake_case and camelCase (ZCode, Devin, Grok) payloads."""

    for key in ("tool_input", "toolInput"):
        candidate = payload.get(key)
        if isinstance(candidate, Mapping):
            return candidate
    return None


def pre_tool_command(payload: Mapping[str, object]) -> str | None:
    for candidate in (pre_tool_input(payload), payload.get("arguments"), payload):
        if not isinstance(candidate, Mapping):
            continue
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


__all__ = [
    "HOOK_PAYLOAD_REFERENCE_KEY",
    "MAX_HOOK_PAYLOAD_REFERENCE_BYTES",
    "HookPayloadReferenceError",
    "hook_payload_reference_size",
    "payload_kind",
    "pre_tool_command",
    "pre_tool_input",
    "runtime_hook_event_name",
]
