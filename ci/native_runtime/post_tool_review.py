"""Direct PostToolUse review through the native resident, for tests and benchmarks.

Production hooks reach the resident through the daemon's edge request. This
client sends one bare PostToolUse envelope so tests and the release-gate
benchmark can exercise the resident without a daemon. Its request, response
and decoder live here because nothing in the shipped runtime uses them; the
module stays self-contained so scripts can load it by path.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
from codex_plugin_scanner.guard.native_response_decoder import native_error
from codex_plugin_scanner.guard.native_route_receipt import record_native_hook_result
from codex_plugin_scanner.guard.native_runtime_resilience import (
    native_record_integrity_failure,
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)
from codex_plugin_scanner.guard.native_runtime_values import _INTEGRITY_FAILURE_REASONS, _identity_key

ModelOutputAction = Literal[
    "allow_original",
    "replace_with_reviewed_excerpt",
    "block",
    "not_applicable",
]

HookDecision = Literal["allow", "deny"]


@dataclass(frozen=True, slots=True)
class HookSourceFileRef:
    """Adapter-provided reference to a direct source-file read.

    This is an optimization hint, never trusted authority. The resident
    re-reads, re-stats, re-hashes, and re-scans the file before allowing
    original output.
    """

    version: int
    path: str
    output_sha256: str
    output_chars: int
    tool_input_path: str | None = None
    adapter_stat: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HookReviewRequest:
    """One PostToolUse review request."""

    harness: str
    event_name: str
    payload: dict[str, object]
    payload_kind: Literal["inline", "encrypted_payload_ref", "source_file_ref", "unknown"]
    config_path: str | None
    cwd: Path | None
    home_dir: Path
    guard_home: Path
    source_scope: str
    source_ref_external_allowed: bool = False
    source_ref: HookSourceFileRef | None = None
    received_at_monotonic: float = 0.0
    deadline_monotonic: float | None = None
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class HookReviewResponse:
    """The resident's decision and model-output directive.

    ``allow_original`` preserves original output only when
    ``reviewed_output_sha256`` matches the locally computed output hash.
    ``replace_with_reviewed_excerpt`` must replace the raw result; a missing
    excerpt is a block.
    """

    decision: HookDecision
    reason: str | None
    model_output_action: ModelOutputAction
    reviewed_output_sha256: str | None = None
    reviewed_excerpt: str | None = None
    notice: Literal["none", "excerpt", "warning"] = "none"
    reason_code: str = "unknown"
    policy_action: str | None = None
    observed_policy_action: str | None = None
    observe_mode: bool = False
    metrics: dict[str, object] = field(default_factory=dict)


def native_output_sha256(text: str) -> str:
    """Hash bounded native-hook output for parity evidence."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parity_signature(response: HookReviewResponse) -> tuple[object, ...]:
    excerpt_hash = native_output_sha256(response.reviewed_excerpt) if response.reviewed_excerpt is not None else None
    return (
        response.decision,
        response.model_output_action,
        response.reason_code,
        response.notice,
        response.policy_action,
        response.observed_policy_action,
        response.reviewed_output_sha256,
        excerpt_hash,
    )


_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
# The response decoder no longer re-checks the receipt; only a resident that
# checks its own answer may be trusted with a PostToolUse review.
_SELF_CHECK_FEATURE = "edge-self-check-v1"


def response_from_payload(payload: object) -> HookReviewResponse | None:
    """Decode one strict native response without assigning new semantics."""

    if not isinstance(payload, dict):
        return None
    decoded = cast(dict[str, object], payload)
    if decoded.get("schema") == "guard-hook-edge-result.v2":
        required = {
            "schema",
            "authority",
            "harness",
            "event_name",
            "payload_kind",
            "result",
            "receipt",
        }
        if not required <= set(decoded) or set(decoded) - (
            required | {"request_id", "harness_response", "containment_route"}
        ):
            return None
        # A PostToolUse answer is never routed into the containment sink.
        if decoded.get("containment_route", "none") != "none":
            return None
        harness = decoded.get("harness")
        if (
            decoded.get("authority") != "rust"
            or decoded.get("event_name") != "PostToolUse"
            or decoded.get("payload_kind") not in {"inline", "source_file_ref", "encrypted_payload_ref"}
            or not isinstance(harness, str)
            or not harness
            or len(harness) > 64
            or not isinstance(decoded.get("result"), dict)
        ):
            return None
        request_id = decoded.get("request_id")
        if request_id is not None and (not isinstance(request_id, str) or len(request_id) > 256):
            return None
        result = decoded.get("result")
        if not isinstance(result, dict):
            return None
        # The edge checked its receipt against this result before it answered.
        if not isinstance(decoded.get("receipt"), dict):
            return None
        decoded = cast(dict[str, object], result)
    decision = decoded.get("decision")
    model_output_action = decoded.get("model_output_action")
    notice = decoded.get("notice")
    reason_code = decoded.get("reason_code")
    if decision not in {"allow", "deny"}:
        return None
    if model_output_action not in {
        "allow_original",
        "replace_with_reviewed_excerpt",
        "block",
        "not_applicable",
    }:
        return None
    if notice not in {"none", "excerpt", "warning"} or not isinstance(reason_code, str):
        return None
    decision_value = cast(HookDecision, decision)
    model_output_action_value = cast(ModelOutputAction, model_output_action)
    notice_value = cast(Literal["none", "excerpt", "warning"], notice)
    reason = decoded.get("reason")
    reviewed_output_sha256 = decoded.get("reviewed_output_sha256")
    reviewed_excerpt = decoded.get("reviewed_excerpt")
    policy_action = decoded.get("policy_action")
    observed_policy_action = decoded.get("observed_policy_action")
    return HookReviewResponse(
        decision=decision_value,
        reason=reason if isinstance(reason, str) else None,
        model_output_action=model_output_action_value,
        reviewed_output_sha256=reviewed_output_sha256 if isinstance(reviewed_output_sha256, str) else None,
        reviewed_excerpt=reviewed_excerpt if isinstance(reviewed_excerpt, str) else None,
        notice=notice_value,
        reason_code=reason_code,
        policy_action=policy_action if isinstance(policy_action, str) else None,
        observed_policy_action=observed_policy_action if isinstance(observed_policy_action, str) else None,
        observe_mode=decoded.get("observe_mode") is True,
    )


def _capture_native_deadline(request: HookReviewRequest) -> tuple[float, int]:
    """Capture one absolute native deadline and its bounded envelope budget."""
    now = time.monotonic()
    requested = request.deadline_monotonic
    deadline = requested if requested is not None and math.isfinite(requested) else now + 0.75
    budget_ms = max(1, min(9_000, int((deadline - now) * 1_000)))
    return deadline, budget_ms


def review_post_tool_native(
    request: HookReviewRequest,
    *,
    observe_mode: bool,
    policy_snapshot: Mapping[str, object] | None,
) -> HookReviewResponse | None:
    """Review PostToolUse through the native Rust client and resident.

    Native failure returns ``None`` so the caller fails closed without Python
    re-evaluation or a semantic one-shot fallback.
    """
    del observe_mode
    status = native_runtime.native_runtime_status()
    identity_key = _identity_key(status)
    if not status.available or not status.compatible or status.identity is None:
        if status.reason in _INTEGRITY_FAILURE_REASONS:
            native_record_integrity_failure(
                identity_key,
                request.guard_home,
                reason=status.reason,
            )
        return record_native_hook_result("native_fail_safe", None)

    deadline_monotonic, deadline_budget_ms = _capture_native_deadline(request)
    if policy_snapshot is None:
        return record_native_hook_result("native_fail_safe", None)
    generation = policy_snapshot.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        return record_native_hook_result("native_fail_safe", None)
    envelope = {
        "schema": "guard-hook-envelope.v2",
        "request_id": request.request_id,
        "harness": request.harness,
        "event": request.event_name,
        "raw_payload": request.payload,
        "deadline_budget_ms": deadline_budget_ms,
        "policy_generation": generation,
        # The resident already authenticated and cached the full snapshot at
        # push/startup. Bind each request to that snapshot without copying
        # policy rules or re-running their integrity checks on the hot path.
        "policy_snapshot": {
            "generation": generation,
            "policy_digest": policy_snapshot.get("policy_digest"),
            "runtime_identity": policy_snapshot.get("runtime_identity"),
        },
        "source": {
            "cwd": str(request.cwd) if request.cwd is not None else None,
            "home_dir": str(request.home_dir),
            "guard_home": str(request.guard_home),
            "source_ref_external_allowed": request.source_ref_external_allowed,
        },
    }
    input_text = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    if len(encoded := input_text.encode("utf-8")) > _MAX_REQUEST_BYTES:
        return record_native_hook_result("native_fail_safe", None)
    resident_output = None
    resident_supported = status.capabilities is not None and {
        _RESIDENT_PROTOCOL_FEATURE,
        _SELF_CHECK_FEATURE,
    } <= set(status.capabilities.features)
    if resident_supported:
        resident_output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=request.guard_home,
            environment=native_runtime._isolated_environment(),
            payload=encoded,
            deadline_monotonic=deadline_monotonic,
        )
    if resident_output is not None:
        try:
            resident_payload = json.loads(resident_output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            resident_payload = None
        resident_error = native_error(resident_payload)
        if resident_error == "native_overloaded":
            native_record_overload(status.identity.sha256, request.guard_home)
            return record_native_hook_result("native_fail_safe", None)
        response = response_from_payload(resident_payload)
        if response is not None:
            native_record_resident_success(status.identity.sha256, request.guard_home)
            return record_native_hook_result("native_resident", response)
        failure_reason = resident_error or "native_resident_invalid_response"
    else:
        failure_reason = "native_resident_unavailable" if resident_supported else "native_resident_protocol_unsupported"

    native_record_resident_failure(
        status.identity.sha256,
        request.guard_home,
        reason=failure_reason,
    )
    return record_native_hook_result("native_fail_safe", None)
