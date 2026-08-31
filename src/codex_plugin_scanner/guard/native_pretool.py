"""Mechanical Python launcher for Rust PreToolUse authority.

This module validates and returns the native decision. It does not parse,
classify, or lower the semantic result. Command-model shadow comparison stays
in native_command_model and is not a PreToolUse authority.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .native_resident_client import native_resident_client_request
from .native_route_receipt import record_native_hook_result
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

_MAX_REQUEST_BYTES = 64 * 1024
_PRETOOL_AUTHORITY_FEATURE = "pre-tool-command-authority-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"


def _decode_pre_tool(payload: object, *, command: str) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    decision = payload.get("decision")
    action = payload.get("minimum_action") or payload.get("policy_action")
    reason_code = payload.get("reason_code")
    reason = payload.get("reason")
    explicitly_benign = payload.get("explicitly_benign")
    model = payload.get("command_model")
    if (
        decision not in {"allow", "deny"}
        or action not in {"allow", "review", "block"}
        or not isinstance(reason_code, str)
        or not reason_code
        or not isinstance(reason, str)
        or not reason
        or not isinstance(explicitly_benign, bool)
        or not isinstance(model, dict)
        or model.get("normalized_text") != command.strip()
    ):
        return record_native_hook_result("native_fail_safe", None)
    if explicitly_benign != (decision == "allow" and action == "allow"):
        return record_native_hook_result("native_fail_safe", None)
    return payload


def review_pre_tool_native(
    command: str,
    *,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
    timeout_seconds: float = 0.5,
) -> dict[str, Any] | None:
    """Return the Rust PreToolUse decision, or None when native cannot decide."""
    del cwd, home_dir
    status = native_runtime_status()
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _PRETOOL_AUTHORITY_FEATURE not in status.capabilities.features
        or timeout_seconds <= 0
    ):
        if status.mode in {"auto", "force"}:
            return record_native_hook_result("native_fail_safe", None)
        return None
    timeout_seconds = min(timeout_seconds, 1.0)
    deadline_started = time.monotonic()
    deadline_monotonic = deadline_started + timeout_seconds
    deadline_budget_ms = max(1, min(9_000, int(timeout_seconds * 1_000)))
    request = {
        "command": command,
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
    }
    encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return record_native_hook_result("native_fail_safe", None)
    environment = _isolated_environment()
    if _RESIDENT_PROTOCOL_FEATURE in status.capabilities.features:
        resident = json.dumps(
            {
                "operation": "pre_tool_use",
                "deadline_budget_ms": deadline_budget_ms,
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=environment,
            payload=resident,
            deadline_monotonic=deadline_monotonic,
        )
        if output is not None:
            try:
                payload = json.loads(output)
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = None
            if _native_error(payload) == "native_overloaded":
                native_record_overload(status.identity.sha256, guard_home)
                return record_native_hook_result("native_fail_safe", None)
            decoded = _decode_pre_tool(payload, command=command)
            if decoded is not None:
                native_record_resident_success(status.identity.sha256, guard_home)
                return record_native_hook_result("native_resident", decoded)
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_pre_tool_resident_unavailable",
        )
    return record_native_hook_result("native_fail_safe", None)


def native_pre_tool_policy_floor(
    command: str,
    *,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
) -> str | None:
    """Return a native PreToolUse floor, or ``block`` when native is expected but absent."""
    native = review_pre_tool_native(
        command,
        guard_home=guard_home,
        cwd=cwd,
        home_dir=home_dir,
    )
    if native is not None:
        action = native.get("minimum_action")
        return action if action in {"allow", "review", "block"} else "block"
    status = native_runtime_status()
    if status.mode in {"off", "shadow"}:
        return None
    return "block"


__all__ = [
    "native_pre_tool_policy_floor",
    "review_pre_tool_native",
]
