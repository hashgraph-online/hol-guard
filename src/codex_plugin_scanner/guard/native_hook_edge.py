"""Transport raw hook envelopes to the Rust hook/data-plane authority.

Python supplies only bounded transport metadata and the current observe-mode
snapshot. Rust extracts the hook event and action, performs decision-critical
content/file I/O, and returns the semantic decision. Native failure never
invokes a Python semantic evaluator.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_policy_snapshot import native_policy_snapshot
from .native_runtime import (
    _INTEGRITY_FAILURE_REASONS,
    _MAX_REQUEST_BYTES,
    _RESIDENT_PROTOCOL_FEATURE,
    _identity_key,
    _isolated_environment,
    _native_error,
    _run_native_process,
    native_runtime_status,
)
from .native_runtime_resident import resident_native_request
from .native_runtime_resilience import (
    native_oneshot_lease,
    native_record_integrity_failure,
    native_record_oneshot_failure,
    native_record_oneshot_success,
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

_HOOK_EDGE_FEATURE = "hook-edge-v2"


def _deadline_budget_ms(deadline: float | None) -> int:
    if deadline is None:
        return 750
    return max(1, min(9_000, int((deadline - time.monotonic()) * 1_000)))


def _decode_hook_edge(payload: object) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or payload.get("authority") != "rust":
        return None
    event_name = payload.get("event_name")
    decision = payload.get("decision")
    reason_code = payload.get("reason_code")
    if not isinstance(event_name, str) or not event_name.strip():
        return None
    if decision not in {"allow", "deny"} or not isinstance(reason_code, str) or not reason_code:
        return None
    if event_name == "PreToolUse":
        action = payload.get("minimum_action") or payload.get("policy_action")
        if action not in {"allow", "review", "block"}:
            return None
    elif event_name == "PostToolUse":
        model_output_action = payload.get("model_output_action")
        notice = payload.get("notice")
        if model_output_action not in {
            "allow_original",
            "replace_with_reviewed_excerpt",
            "block",
            "not_applicable",
        }:
            return None
        if notice not in {"none", "excerpt", "warning"}:
            return None
    return payload


def review_hook_edge_native(
    *,
    payload: Mapping[str, object],
    harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    observe_mode: bool,
    deadline: float | None = None,
) -> dict[str, Any] | None:
    """Return the Rust semantic hook decision for a raw harness envelope."""

    status = native_runtime_status()
    identity_key = _identity_key(status)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _HOOK_EDGE_FEATURE not in status.capabilities.features
    ):
        if status.reason in _INTEGRITY_FAILURE_REASONS:
            native_record_integrity_failure(identity_key, guard_home, reason=status.reason)
        return None

    envelope: dict[str, object] = {
        "protocol_version": 1,
        "harness": harness,
        "payload": dict(payload),
        "cwd": str(workspace) if workspace is not None else None,
        "home_dir": str(home_dir),
        "guard_home": str(guard_home),
        "observe_mode": observe_mode,
        "deadline_budget_ms": _deadline_budget_ms(deadline),
        "policy_snapshot": native_policy_snapshot(
            rule_digest=status.capabilities.rule_digest,
            observe_mode=observe_mode,
        ),
    }
    input_text = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    encoded = input_text.encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return None
    timeout_seconds = max(0.05, min(9.0, _deadline_budget_ms(deadline) / 1_000.0))

    if _RESIDENT_PROTOCOL_FEATURE in status.capabilities.features:
        resident_request = json.dumps(
            {"operation": "hook_edge", "request": envelope},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        resident_output = resident_native_request(
            executable=status.identity.path,
            identity_sha256=status.identity.sha256,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=resident_request,
            timeout_seconds=timeout_seconds,
        )
        if resident_output is not None:
            try:
                resident_payload = json.loads(resident_output)
            except (UnicodeDecodeError, json.JSONDecodeError):
                resident_payload = None
            resident_error = _native_error(resident_payload)
            if resident_error == "native_overloaded":
                native_record_overload(status.identity.sha256, guard_home)
                return None
            response = _decode_hook_edge(resident_payload)
            if response is not None:
                native_record_resident_success(status.identity.sha256, guard_home)
                return response
            failure_reason = resident_error or "native_hook_edge_resident_invalid_response"
        else:
            failure_reason = "native_hook_edge_resident_unavailable"
        native_record_resident_failure(status.identity.sha256, guard_home, reason=failure_reason)

    with native_oneshot_lease(status.identity.sha256, guard_home) as acquired:
        if not acquired:
            return None
        output = _run_native_process(
            status.identity.path,
            ("hook-edge", "--stdin"),
            input_text=input_text,
            timeout_seconds=timeout_seconds,
        )
        if output is None:
            native_record_oneshot_failure(
                status.identity.sha256,
                guard_home,
                reason="native_hook_edge_oneshot_failed",
            )
            return None
        try:
            oneshot_payload = json.loads(output)
        except json.JSONDecodeError:
            oneshot_payload = None
        response = _decode_hook_edge(oneshot_payload)
        if response is None:
            native_record_oneshot_failure(
                status.identity.sha256,
                guard_home,
                reason=_native_error(oneshot_payload) or "native_hook_edge_oneshot_invalid_response",
            )
            return None
        native_record_oneshot_success(status.identity.sha256, guard_home)
        return response


__all__ = ["review_hook_edge_native"]
