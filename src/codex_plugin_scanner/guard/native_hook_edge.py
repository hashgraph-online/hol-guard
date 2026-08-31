"""Raw hook-envelope bridge to the package-bound Rust edge."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_resident_client import native_resident_client_request
from .native_route_receipt import record_native_hook_result
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resilience import (
    native_record_resident_failure,
    native_record_resident_success,
)

_EDGE_FEATURE = "hook-envelope-v2"
_CLIENT_FEATURE = "native-resident-client-v1"
_GENERIC_PRE_TOOL_SCHEMA = "guard-pre-tool-result.v1"
_GENERIC_PRE_TOOL_ACTION_SCHEMA = "guard-pre-tool-action.v1"
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESULT_TEXT = 2_048
_PRE_TOOL_ACTION_TYPES = {
    "command",
    "file_read",
    "file_write",
    "package",
    "mcp_tool",
    "network",
    "process_service",
    "browser",
    "config",
    "prompt",
    "harness",
    "unknown",
}
_PRE_TOOL_OPERATIONS = {
    "execute",
    "read",
    "write",
    "install",
    "call",
    "request",
    "start",
    "stop",
    "navigate",
    "set",
    "submit",
    "unknown",
}
_PRE_TOOL_ACTION_OPERATIONS = {
    "command": {"execute"},
    "file_read": {"read"},
    "file_write": {"write"},
    "package": {"install"},
    "mcp_tool": {"call"},
    "network": {"request"},
    "process_service": {"start", "stop"},
    "browser": {"navigate"},
    "config": {"set"},
    "prompt": {"submit"},
    "harness": {"start", "stop"},
    "unknown": {"unknown"},
}
_PRE_TOOL_RESULT_KEYS = {
    "schema",
    "version",
    "authority",
    "action",
    "decision",
    "policy_action",
    "minimum_action",
    "reason_code",
    "reason",
    "explicitly_benign",
}
_PRE_TOOL_POLICY_ACTIONS = {
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
}
_PRE_TOOL_ACTION_KEYS = {
    "schema",
    "version",
    "harness",
    "event",
    "action_type",
    "operation",
    "bounded",
    "sensitive_target",
}


def _capture_deadline(deadline: float | None) -> tuple[float, int]:
    now = time.monotonic()
    effective_deadline = deadline if deadline is not None else now + 0.75
    budget_ms = max(1, min(9_000, int((effective_deadline - now) * 1_000)))
    return effective_deadline, budget_ms


def _valid_pre_tool_result_fields(result: dict[str, Any]) -> bool:
    decision = result.get("decision")
    policy_action = result.get("policy_action")
    reason_code = result.get("reason_code")
    reason = result.get("reason")
    minimum_action = result.get("minimum_action")
    return not (
        result.get("schema") != _GENERIC_PRE_TOOL_SCHEMA
        or result.get("version") != 1
        or result.get("authority") != "rust"
        or not isinstance(decision, str)
        or decision not in {"allow", "deny"}
        or not isinstance(policy_action, str)
        or policy_action not in _PRE_TOOL_POLICY_ACTIONS
        or minimum_action != policy_action
        or not isinstance(reason_code, str)
        or not reason_code
        or len(reason_code) > _MAX_RESULT_TEXT
        or not isinstance(reason, str)
        or not reason
        or len(reason) > _MAX_RESULT_TEXT
        or not isinstance(result.get("explicitly_benign"), bool)
    )


def _valid_pre_tool_action(action: dict[str, Any], *, harness: str) -> bool:
    action_type = action.get("action_type")
    operation = action.get("operation")
    action_harness = action.get("harness")
    if (
        action.get("schema") != _GENERIC_PRE_TOOL_ACTION_SCHEMA
        or action.get("version") != 1
        or action_harness != harness
        or action.get("event") != "PreToolUse"
        or not isinstance(action_type, str)
        or action_type not in _PRE_TOOL_ACTION_TYPES
        or not isinstance(operation, str)
        or operation not in _PRE_TOOL_OPERATIONS
        or not isinstance(action_harness, str)
        or not action_harness
        or len(action_harness) > 64
        or not isinstance(action.get("bounded"), bool)
        or not isinstance(action.get("sensitive_target"), bool)
    ):
        return False
    return operation in _PRE_TOOL_ACTION_OPERATIONS[action_type]


def _decode_pre_tool_result(result: object, *, harness: str) -> bool:
    if not isinstance(result, dict) or set(result) != _PRE_TOOL_RESULT_KEYS:
        return False
    if not _valid_pre_tool_result_fields(result):
        return False
    action = result.get("action")
    if not isinstance(action, dict) or set(action) != _PRE_TOOL_ACTION_KEYS:
        return False
    if not _valid_pre_tool_action(action, harness=harness):
        return False
    decision = result["decision"]
    minimum_action = result["minimum_action"]
    if result["explicitly_benign"] != (decision == "allow" and minimum_action == "allow"):
        return False
    # `warn` is an allow-with-warning floor. All stronger actions remain
    # denying floors; this keeps the Python edge purely mechanical.
    return decision == ("allow" if minimum_action in {"allow", "warn"} else "deny")


def _decode_edge(payload: object) -> dict[str, Any] | None:
    required = {
        "schema",
        "authority",
        "harness",
        "event_name",
        "payload_kind",
        "result",
    }
    allowed = required | {"request_id"}
    if not isinstance(payload, dict) or not required <= set(payload) or set(payload) - allowed:
        return None
    event_name = payload.get("event_name")
    payload_kind = payload.get("payload_kind")
    if (
        payload.get("schema") != "guard-hook-edge-result.v2"
        or payload.get("authority") != "rust"
        or not isinstance(event_name, str)
        or event_name not in {"PreToolUse", "PostToolUse"}
        or not isinstance(payload_kind, str)
        or payload_kind not in {"inline", "source_file_ref", "encrypted_payload_ref"}
        or not isinstance(payload.get("harness"), str)
        or not payload["harness"]
        or len(payload["harness"]) > 64
        or not isinstance(payload.get("result"), dict)
    ):
        return None
    if event_name == "PreToolUse" and not _decode_pre_tool_result(payload["result"], harness=payload["harness"]):
        return None
    if event_name == "PreToolUse" and payload_kind == "encrypted_payload_ref":
        return None
    return payload


def review_raw_hook_native(
    *,
    payload: dict[str, object],
    harness: str,
    event: str,
    guard_home: Path,
    home_dir: Path,
    cwd: Path | None,
    source_ref_external_allowed: bool,
    observe_mode: bool,
    deadline: float | None,
    policy_snapshot: Mapping[str, object] | None = None,
) -> dict[str, Any] | None:
    """Return a typed Rust edge result, or fail closed without reinterpretation."""
    status = native_runtime_status()
    event_key = event.strip().lower().replace("_", "").replace("-", "")
    required_features = {_EDGE_FEATURE, _CLIENT_FEATURE}
    if event_key in {
        "pretool",
        "pretooluse",
        "beforeshellexecution",
        "beforereadfile",
        "beforewritefile",
        "beforemcpexecution",
    }:
        required_features.add("pre-tool-generic-authority-v1")
    if (
        status.mode not in {"auto", "force"}
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not required_features <= set(status.capabilities.features)
    ):
        return record_native_hook_result("native_fail_safe", None)
    deadline_monotonic, deadline_budget_ms = _capture_deadline(deadline)
    del observe_mode
    if policy_snapshot is None:
        return record_native_hook_result("native_fail_safe", None)
    snapshot = dict(policy_snapshot)
    generation = snapshot.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        return record_native_hook_result("native_fail_safe", None)
    envelope = {
        "schema": "guard-hook-envelope.v2",
        "request_id": None,
        "harness": harness,
        "event": event,
        "raw_payload": payload,
        "deadline_budget_ms": deadline_budget_ms,
        "policy_generation": snapshot["generation"],
        # The resident already authenticated and cached the full snapshot at
        # push/startup. Keep the request binding compact so each hook only
        # carries the generation and identity it must match, rather than
        # re-deserializing and re-authenticating the complete policy.
        "policy_snapshot": {
            "generation": snapshot["generation"],
            "policy_digest": snapshot.get("policy_digest"),
            "runtime_identity": snapshot.get("runtime_identity"),
        },
        "source": {
            "cwd": str(cwd) if cwd is not None else None,
            "home_dir": str(home_dir),
            "guard_home": str(guard_home),
            "source_ref_external_allowed": source_ref_external_allowed,
        },
    }
    try:
        encoded = json.dumps(
            envelope,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError):
        return record_native_hook_result("native_fail_safe", None)
    if len(encoded) > _MAX_REQUEST_BYTES:
        return record_native_hook_result("native_fail_safe", None)
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=encoded,
        deadline_monotonic=deadline_monotonic,
        raw_hook_envelope=True,
    )
    if output is None:
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_hook_edge_unavailable",
        )
        return record_native_hook_result("native_fail_safe", None)
    try:
        decoded = _decode_edge(json.loads(output))
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = None
    if decoded is None:
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_hook_edge_invalid_response",
        )
        return record_native_hook_result("native_fail_safe", None)
    native_record_resident_success(status.identity.sha256, guard_home)
    return record_native_hook_result("native_resident", decoded)


__all__ = ["review_raw_hook_native"]
