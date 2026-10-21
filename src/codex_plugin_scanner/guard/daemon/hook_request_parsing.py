"""Normalize daemon hook payloads into the native review request model."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..runtime.hook_review_types import (
    HookPayloadKind,
)

HOOK_PAYLOAD_REFERENCE_KEY = "guard_payload_ref"
MAX_HOOK_PAYLOAD_REFERENCE_BYTES = 5 * 1024 * 1024


class HookPayloadReferenceError(ValueError):
    """Raised when a hook payload reference cannot be safely validated."""


def hook_payload_reference_size(
    payload: Mapping[str, object],
    *,
    guard_home: Path | str,
    deadline_monotonic: float | None = None,
) -> int | None:
    """Return the conservative reservation required before reading a reference.

    Whether the referenced file is one Guard's own writer could have put where
    it is, is a runtime verdict, so settling it needs the Guard home to reach
    the resident and the caller's deadline to stay inside the hook's budget.
    """

    ref = payload.get(HOOK_PAYLOAD_REFERENCE_KEY)
    if not isinstance(ref, Mapping):
        return None
    _ = _validated_reference(ref, guard_home=guard_home, deadline_monotonic=deadline_monotonic)
    return MAX_HOOK_PAYLOAD_REFERENCE_BYTES


def _validated_reference(
    ref: Mapping[str, object],
    *,
    guard_home: Path | str,
    deadline_monotonic: float | None = None,
) -> tuple[Path, str]:
    path_value = ref.get("path")
    sha256_value = ref.get("sha256")
    if ref.get("version") != 1 or not isinstance(path_value, str) or not isinstance(sha256_value, str):
        raise HookPayloadReferenceError("Invalid HOL Guard hook payload reference metadata.")
    expected_sha256 = sha256_value.strip().lower()
    if len(expected_sha256) != 64 or any(char not in "0123456789abcdef" for char in expected_sha256):
        raise HookPayloadReferenceError("Invalid HOL Guard hook payload reference digest.")
    path = _safe_reference_path(path_value, guard_home=guard_home, deadline_monotonic=deadline_monotonic)
    return path, expected_sha256


def _safe_reference_path(
    path_value: str,
    *,
    guard_home: Path | str,
    deadline_monotonic: float | None = None,
) -> Path:
    """The file this reference names, once the runtime says Guard wrote it.

    The runtime owns the rule: the file has to resolve, sit directly inside a
    `hol-guard-hook-payload-` directory under a temporary root this user owns,
    and be a regular file. A runtime that cannot answer refuses the reference
    rather than letting the daemon decide for itself.
    """

    # Imported here so the hook bridges, which import this module, stay off the
    # native runtime's import closure until a payload actually carries a
    # reference. ``tests/test_hook_bridge_import_closure.py`` holds that line.
    from ..native_directory_trust import NativeDirectoryTrustError, native_directory_trust

    try:
        verdicts = native_directory_trust(
            [("payload-reference", path_value)],
            guard_home=guard_home,
            deadline_monotonic=deadline_monotonic,
        )
    except NativeDirectoryTrustError as error:
        raise HookPayloadReferenceError("HOL Guard could not settle the hook payload reference.") from error
    settled = verdicts[0].path if verdicts else None
    if settled is None:
        raise HookPayloadReferenceError("HOL Guard hook payload reference must be in a Guard-owned temp directory.")
    return Path(settled)


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
