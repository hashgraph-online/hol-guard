"""Raw hook-envelope bridge to the package-bound Rust edge."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from .native_approval_errors import resident_refusal_code
from .native_resident_client import (
    native_resident_client_request,
    record_native_resident_client_failure_code,
)
from .native_route_receipt import record_native_hook_result
from .native_runtime import NativeRuntimeStatus, _isolated_environment, native_runtime_status
from .native_runtime_resilience import (
    native_record_resident_failure,
    native_record_resident_success,
)

_EDGE_FEATURE = "hook-envelope-v2"
_CLIENT_FEATURE = "native-resident-client-v1"
_RESPONSE_FEATURE = "hook-harness-response-v1"
# Python no longer re-checks the edge result or receipt; only a resident that
# checks its own answer may be trusted with it.
_SELF_CHECK_FEATURE = "edge-self-check-v1"
_UNSUPPORTED_EVENT_CODE = "native_hook_event_unsupported"
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_LOCAL_CLI_RULE_FEATURE = "edge-local-cli-rule-v1"
# The custom extension rule is read after the review, and identifying a
# launch can take seconds. It once had its own request with this timeout;
# the edge keeps that allowance rather than spending the review's budget.
_LOCAL_CLI_RULE_SECONDS = 5.0


def _capture_deadline(deadline: float | None) -> tuple[float, int]:
    now = time.monotonic()
    effective_deadline = deadline if deadline is not None else now + 0.75
    budget_ms = max(1, min(9_000, int((effective_deadline - now) * 1_000)))
    return effective_deadline, budget_ms


def _native_error_code(payload: object) -> str | None:
    """Accept only the resident's finite error envelope for local diagnostics."""
    return resident_refusal_code(payload)


def _decode_edge(payload: object) -> dict[str, Any] | None:
    required = {
        "schema",
        "authority",
        "harness",
        "event_name",
        "payload_kind",
        "result",
        "receipt",
    }
    allowed = required | {"request_id", "harness_response", "containment_route", "local_cli_rule"}
    if not isinstance(payload, dict) or not required <= set(payload) or set(payload) - allowed:
        return None
    event_name = payload.get("event_name")
    payload_kind = payload.get("payload_kind")
    if (
        payload.get("schema") != "guard-hook-edge-result.v2"
        or payload.get("authority") != "rust"
        or not isinstance(event_name, str)
        or event_name not in {"PreToolUse", "PostToolUse", "UserPromptSubmit"}
        or not isinstance(payload_kind, str)
        or payload_kind not in {"inline", "source_file_ref", "encrypted_payload_ref"}
        or not isinstance(payload.get("harness"), str)
        or not payload["harness"]
        or len(payload["harness"]) > 64
        or not isinstance(payload.get("result"), dict)
        or not isinstance(payload.get("harness_response"), dict)
    ):
        return None
    route = payload.get("containment_route", "none")
    if not isinstance(route, str) or route not in {"none", "sink", "grant"}:
        return None
    receipt = payload.get("receipt")
    if not isinstance(receipt, dict) or not isinstance(receipt.get("request_id"), str):
        return None
    rule = payload.get("local_cli_rule")
    if rule is not None and (
        not isinstance(rule, dict)
        or set(rule) != {"blocked", "harness_response"}
        or not isinstance(rule["blocked"], bool)
        or not isinstance(rule["harness_response"], dict)
    ):
        return None
    return payload


def _encode_hook_envelope(
    *,
    payload: dict[str, object],
    harness: str,
    event: str,
    guard_home: Path,
    home_dir: Path,
    cwd: Path | None,
    source_ref_external_allowed: bool,
    deadline_budget_ms: int,
    snapshot: Mapping[str, object],
    execution_context_supported: bool = False,
    request_id: str | None = None,
    recording_only: bool = False,
    local_cli_rules: Mapping[str, object] | None = None,
) -> bytes | None:
    from .hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY, collect_hook_execution_environment

    raw_payload = dict(payload)
    caller_context = raw_payload.pop(HOOK_EXECUTION_ENVIRONMENT_KEY, ...)
    envelope = {
        "schema": "guard-hook-envelope.v2",
        "request_id": request_id,
        "harness": harness,
        "event": event,
        "raw_payload": raw_payload,
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
    if recording_only:
        envelope["recording_only"] = True
    if local_cli_rules is not None:
        envelope["local_cli_rules"] = dict(local_cli_rules)
    if execution_context_supported:
        # Direct CLI calls capture locally; daemon workers explicitly pass
        # None when caller context is unavailable instead of using daemon env.
        if caller_context is ...:
            caller_context = collect_hook_execution_environment()
        if caller_context is not None:
            if not isinstance(caller_context, Mapping):
                return None
            cast(dict[str, Any], envelope["source"])["execution_environment"] = dict(caller_context)
    try:
        encoded = json.dumps(
            envelope,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError):
        return None
    return encoded if len(encoded) <= _MAX_REQUEST_BYTES else None


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
    runtime_status: NativeRuntimeStatus | None = None,
    request_id: str | None = None,
    local_cli_rules: Mapping[str, object] | None = None,
) -> dict[str, Any] | None:
    """Return a typed Rust edge result, or fail closed without reinterpretation."""
    record_native_resident_client_failure_code(None)
    if request_id is not None and (
        not isinstance(request_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,255}", request_id) is None
    ):
        return record_native_hook_result("native_fail_safe", None)
    status = runtime_status if runtime_status is not None else native_runtime_status()
    event_key = event.strip().lower().replace("_", "").replace("-", "")
    required_features = {_EDGE_FEATURE, _CLIENT_FEATURE, _RESPONSE_FEATURE, _SELF_CHECK_FEATURE}
    if event_key in {
        "pretool",
        "pretooluse",
        "beforeshellexecution",
        "beforereadfile",
        "beforewritefile",
        "beforemcpexecution",
        "userpromptsubmit",
        "userpromptsubmitted",
        "prompt",
    }:
        required_features.add("pre-tool-generic-authority-v1")
        if event_key not in {"userpromptsubmit", "userpromptsubmitted", "prompt"}:
            required_features.add("git-execution-context-v1")
            if local_cli_rules is not None:
                required_features.add(_LOCAL_CLI_RULE_FEATURE)
    if _LOCAL_CLI_RULE_FEATURE not in required_features:
        # Only a tool call has a custom extension rule to settle.
        local_cli_rules = None
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not required_features <= set(status.capabilities.features)
    ):
        return record_native_hook_result("native_fail_safe", None)
    deadline_monotonic, deadline_budget_ms = _capture_deadline(deadline)
    if policy_snapshot is None:
        return record_native_hook_result("native_fail_safe", None)
    snapshot = dict(policy_snapshot)
    generation = snapshot.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        return record_native_hook_result("native_fail_safe", None)
    encoded = _encode_hook_envelope(
        payload=payload,
        harness=harness,
        event=event,
        guard_home=guard_home,
        home_dir=home_dir,
        cwd=cwd,
        source_ref_external_allowed=source_ref_external_allowed,
        deadline_budget_ms=deadline_budget_ms,
        snapshot=snapshot,
        execution_context_supported="git-execution-context-v1" in status.capabilities.features,
        request_id=request_id,
        recording_only=observe_mode,
        local_cli_rules=local_cli_rules,
    )
    if encoded is None:
        return record_native_hook_result("native_fail_safe", None)
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=encoded,
        deadline_monotonic=deadline_monotonic + (_LOCAL_CLI_RULE_SECONDS if local_cli_rules is not None else 0.0),
        raw_hook_envelope=True,
    )
    if output is None:
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_hook_edge_unavailable",
        )
        return record_native_hook_result("native_fail_safe", None)
    error_code: str | None = None
    try:
        response_payload = json.loads(output)
        error_code = _native_error_code(response_payload)
        if error_code == _UNSUPPORTED_EVENT_CODE:
            # A lifecycle event the edge does not review. The resident
            # answered, so this neither counts against its health nor proves it.
            return record_native_hook_result("native_fail_safe", None)
        if error_code is not None:
            record_native_resident_client_failure_code(error_code)
        decoded = _decode_edge(response_payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = None
    if decoded is None or (request_id is not None and decoded["receipt"]["request_id"] != request_id):
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_hook_edge_invalid_response",
        )
        return record_native_hook_result("native_fail_safe", None)
    native_record_resident_success(status.identity.sha256, guard_home)
    return record_native_hook_result("native_resident", decoded)


__all__ = ["review_raw_hook_native"]
