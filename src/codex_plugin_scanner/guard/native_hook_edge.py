"""Raw hook-envelope bridge to the package-bound Rust edge."""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Mapping, Sequence
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
# The resident records the CLI an answered PreToolUse launches, off the answer path.
_LOCAL_CLI_OBSERVATION_FEATURE = "edge-local-cli-observation-v1"
_RECEIPT_RECORD_FEATURE = "edge-receipt-record-v1"
_ACTIVITY_RECORD_FEATURE = "edge-activity-record-v1"
_PRE_TOOL_ACTIVITY_RECORD_FEATURE = "edge-pre-tool-activity-record-v1"
# The edge answers the Oh My Pi / Pi structured-output mediation itself when
# the envelope carries the daemon's managed-policy view.
STRUCTURED_OUTPUT_FEATURE = "edge-structured-output-v1"
_UNSUPPORTED_EVENT_CODE = "native_hook_event_unsupported"
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_LOCAL_CLI_RULE_FEATURE = "edge-local-cli-rule-v1"
# The custom extension rule is read after the review, and identifying a
# launch can take seconds. It once had its own request with this timeout;
# the edge keeps that allowance rather than spending the review's budget.
_LOCAL_CLI_RULE_SECONDS = 5.0
# The edge proves a review's policy binding, retry binding and exact-action
# token beside the custom extension rule when the rules carry the daemon's
# extension-control digest.
_REVIEW_EVIDENCE_FEATURE = "edge-review-evidence-v1"
_REVIEW_EVIDENCE_KEYS = frozenset({"policy_binding_valid", "binding", "token", "once_only_reason"})
# The edge rewrites a call it routes to the contained sink itself when the
# envelope carries the argv that starts Guard's CLI: `routed` means the
# response runs the call in the sink, `kept` that the receipt stands.
CONTAINMENT_REWRITE_FEATURE = "edge-containment-rewrite-v1"
# Cursor's route probe may name the runtime's own sink, which this daemon
# admits on `beforeShellExecution` (`cursor_shell_route`).
_CURSOR_NATIVE_SINK_FEATURE = "edge-cursor-native-sink-v1"
_CONTAINMENT_REWRITES = frozenset({"routed", "kept"})
# The resident echoes the envelope's request id verbatim and stamps the same
# id on the receipt, so an id minted here names one request and no other.
_REQUEST_BINDING_FEATURE = "edge-request-binding-v1"


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
    allowed = required | {
        "request_id",
        "harness_response",
        "containment_route",
        "containment_rewrite",
        "local_cli_rule",
        "review_evidence",
        "receipt_recorded",
        "activity_recorded",
        "exact_command_block",
    }
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
        or not isinstance(payload.get("receipt_recorded", False), bool)
        or not isinstance(payload.get("activity_recorded", False), bool)
        or not isinstance(payload.get("exact_command_block", False), bool)
    ):
        return None
    # Every resident stamps its containment route; an edge without one would
    # skip containment, so it is refused rather than read as `none`. An older
    # resident may still stamp `grant`, which nothing routes on any more.
    route = payload.get("containment_route")
    if not isinstance(route, str) or route not in {"none", "sink", "grant"}:
        return None
    rewrite = payload.get("containment_rewrite")
    if rewrite is not None and (
        route != "sink" or not isinstance(rewrite, str) or rewrite not in _CONTAINMENT_REWRITES
    ):
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
    evidence = payload.get("review_evidence")
    if evidence is not None and (
        not isinstance(evidence, dict)
        or set(evidence) != _REVIEW_EVIDENCE_KEYS
        or not isinstance(evidence["policy_binding_valid"], bool)
        or any(
            evidence[key] is not None and not isinstance(evidence[key], str)
            for key in _REVIEW_EVIDENCE_KEYS - {"policy_binding_valid"}
        )
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
    observe_local_cli: bool = False,
    record_receipt: bool = False,
    record_activity: bool = False,
    record_pre_tool_activity: bool = False,
    structured_output_config: Mapping[str, object] | None = None,
    containment_sink: Sequence[str] | None = None,
    native_sink: bool = False,
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
    if observe_local_cli:
        envelope["observe_local_cli"] = True
    if record_receipt:
        envelope["record_receipt"] = True
        if record_activity:
            envelope["record_activity"] = True
        if record_pre_tool_activity:
            envelope["record_pre_tool_activity"] = True
    if structured_output_config is not None:
        envelope["structured_output_config"] = dict(structured_output_config)
    if containment_sink is not None:
        envelope["containment_sink"] = {"sink_command": list(containment_sink)}
        if native_sink:
            envelope["containment_sink"]["native_sink"] = True
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
    observe_local_cli: bool = False,
    record_receipt: bool = False,
    structured_output_config: Mapping[str, object] | None = None,
    containment_sink: bool = False,
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
    if structured_output_config is not None:
        # A resident that cannot mediate would ignore the view and answer an
        # allow the policy never covered, so it is refused rather than trusted.
        required_features.add(STRUCTURED_OUTPUT_FEATURE)
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
                if local_cli_rules.get("exact_action_control_digest") is not None:
                    required_features.add(_REVIEW_EVIDENCE_FEATURE)
    tool_call = "git-execution-context-v1" in required_features
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
    # Bind this call's answer to this call. Without an id of its own a review
    # can only trust the stream it borrowed to have carried one request at a
    # time; with one, an answer naming a different request -- or naming none --
    # is a desynchronised stream rather than this review's verdict. The id is
    # transport identity: nothing here reads or recomputes the verdict.
    bound_request_id = request_id
    if bound_request_id is None and _REQUEST_BINDING_FEATURE in status.capabilities.features:
        bound_request_id = uuid.uuid4().hex
    deadline_monotonic, deadline_budget_ms = _capture_deadline(deadline)
    if policy_snapshot is None:
        return record_native_hook_result("native_fail_safe", None)
    snapshot = dict(policy_snapshot)
    generation = snapshot.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        return record_native_hook_result("native_fail_safe", None)
    sink_command: tuple[str, ...] | None = None
    if (
        containment_sink
        and tool_call
        and cwd is not None
        and CONTAINMENT_REWRITE_FEATURE in status.capabilities.features
    ):
        # Without a workspace there is no snapshot to write, and the receipt
        # stands; an older resident leaves the rewrite to the hook.
        from .adapters.zcode_contained_tests import contained_sink_command_prefix

        sink_command = contained_sink_command_prefix()
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
        request_id=bound_request_id,
        recording_only=observe_mode,
        local_cli_rules=local_cli_rules,
        observe_local_cli=observe_local_cli and _LOCAL_CLI_OBSERVATION_FEATURE in status.capabilities.features,
        record_receipt=record_receipt and _RECEIPT_RECORD_FEATURE in status.capabilities.features,
        # The caller that asks for its receipt also skips a tool activity the
        # edge says it queued.
        record_activity=_ACTIVITY_RECORD_FEATURE in status.capabilities.features,
        record_pre_tool_activity=_PRE_TOOL_ACTIVITY_RECORD_FEATURE in status.capabilities.features,
        structured_output_config=structured_output_config,
        containment_sink=sink_command,
        native_sink=harness == "cursor" and _CURSOR_NATIVE_SINK_FEATURE in status.capabilities.features,
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
    if decoded is None or (
        bound_request_id is not None
        and (decoded.get("request_id") != bound_request_id or decoded["receipt"]["request_id"] != bound_request_id)
    ):
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_hook_edge_invalid_response",
        )
        return record_native_hook_result("native_fail_safe", None)
    native_record_resident_success(status.identity.sha256, guard_home)
    return record_native_hook_result("native_resident", decoded)


__all__ = ["review_raw_hook_native"]
