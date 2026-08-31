"""Raw hook-envelope bridge to the package-bound Rust edge."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .native_policy_snapshot import NativePolicySnapshotError, native_policy_snapshot
from .native_resident_client import native_resident_client_request
from .native_route_receipt import record_native_hook_result
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resilience import (
    native_record_resident_failure,
    native_record_resident_success,
)

_EDGE_FEATURE = "hook-envelope-v2"
_CLIENT_FEATURE = "native-resident-client-v1"
_MAX_REQUEST_BYTES = 6 * 1024 * 1024


def _deadline_budget_ms(deadline: float | None) -> int:
    if deadline is None:
        return 750
    return max(1, min(9_000, int((deadline - time.monotonic()) * 1_000)))


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
    if (
        payload.get("schema") != "guard-hook-edge-result.v2"
        or payload.get("authority") != "rust"
        or payload.get("event_name") not in {"PreToolUse", "PostToolUse"}
        or payload.get("payload_kind") not in {"inline", "source_file_ref", "encrypted_payload_ref"}
        or not isinstance(payload.get("harness"), str)
        or not isinstance(payload.get("result"), dict)
    ):
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
) -> dict[str, Any] | None:
    """Return a typed Rust edge result, or fail closed without reinterpretation."""
    status = native_runtime_status()
    if (
        status.mode not in {"auto", "force"}
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not {_EDGE_FEATURE, _CLIENT_FEATURE} <= set(status.capabilities.features)
    ):
        return record_native_hook_result("native_fail_safe", None)
    try:
        snapshot = native_policy_snapshot(
            rule_digest=status.capabilities.rule_digest,
            observe_mode=observe_mode,
            guard_home=guard_home,
            deadline_monotonic=deadline,
        )
    except (NativePolicySnapshotError, OSError):
        return record_native_hook_result("native_fail_safe", None)
    envelope = {
        "schema": "guard-hook-envelope.v2",
        "request_id": None,
        "harness": harness,
        "event": event,
        "raw_payload": payload,
        "deadline_budget_ms": _deadline_budget_ms(deadline),
        "policy_generation": snapshot["generation"],
        "policy_snapshot": snapshot,
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
        timeout_seconds=max(0.05, min(9.0, _deadline_budget_ms(deadline) / 1_000)),
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
