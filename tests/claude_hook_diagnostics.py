"""Finite diagnostics for a generated hook's synthetic regression test."""

from __future__ import annotations

import json
import math
import re
import subprocess
from typing import cast

import pytest

_DEGRADED_PREFIX = "HOL Guard could not reach the local daemon ("
_DEGRADED_SUFFIX = ") and continued this action without native review."
_REASON_SUFFIXES = (
    ("; fallback exhausted the hook deadline", "fallback_deadline_exhausted"),
    ("; fallback timed out", "fallback_timed_out"),
    ("; fallback returned malformed hook JSON", "fallback_invalid_json"),
    ("; recovered daemon returned malformed hook JSON", "recovered_daemon_invalid_json"),
)

_LIFECYCLE_REASON_CODES = frozenset(
    {
        "daemon_hook_queue_capacity",
        "daemon_hook_queue_bytes",
        "daemon_hook_deadline_exhausted",
        "daemon_hook_process_deadline_exhausted",
        "daemon_hook_process_not_ready",
        "daemon_hook_process_timeout",
        "daemon_hook_process_failed",
        "daemon_hook_process_invalid_request",
        "daemon_hook_process_guard_home_mismatch",
        "daemon_worker_exception",
        "native_hook_disabled",
        "native_shadow_diagnostic_disabled",
        "native_hook_event_unavailable",
        "native_hook_worker_unavailable",
        "native_hook_worker_unavailable_before_compatibility",
        "native_hook_worker_unsupported",
        "native_hook_worker_exception",
        "native_hook_compatibility_disabled",
        "python_hook_oracle_unavailable",
        "python_oracle_exception",
        "watch_recording_only",
    }
)


def _reason_category(reason: object) -> str:
    if type(reason) is not str or len(reason) > 8192:
        return "unrecognized"
    if not (reason.startswith(_DEGRADED_PREFIX) and reason.endswith(_DEGRADED_SUFFIX)):
        return "unrecognized"
    detail = reason[len(_DEGRADED_PREFIX) : -len(_DEGRADED_SUFFIX)]
    for suffix, category in _REASON_SUFFIXES:
        if detail.endswith(suffix):
            return category
    if re.search(r"; fallback exited (?:-?[0-9]{1,3}|None)$", detail):
        return "fallback_exited"
    if detail == "daemon returned malformed hook JSON":
        return "daemon_invalid_json"
    return "degraded_other"


def claude_hook_diagnostics(
    payload: object,
    *,
    returncode: object,
    elapsed_seconds: object,
) -> dict[str, str | int]:
    """Never include raw output, reason detail, paths, commands, or payloads."""

    result: dict[str, str | int] = {
        "decision": "invalid",
        "reason_category": "unrecognized",
        "returncode": "invalid",
        "elapsed_ms": "invalid",
    }
    if type(returncode) is int and -255 <= returncode <= 255:
        result["returncode"] = returncode
    if (
        (type(elapsed_seconds) is int or type(elapsed_seconds) is float)
        and 0 <= elapsed_seconds <= 600
        and math.isfinite(elapsed_seconds)
    ):
        result["elapsed_ms"] = round(elapsed_seconds * 1000)
    if type(payload) is not dict:
        return result
    raw_output = cast(dict[str, object], payload).get("hookSpecificOutput")
    if type(raw_output) is not dict:
        return result
    output = cast(dict[str, object], raw_output)
    event = output.get("hookEventName")
    if type(event) is not str or event != "PreToolUse":
        return result
    decision = output.get("permissionDecision")
    if type(decision) is str and decision in {"allow", "ask", "deny"}:
        result["decision"] = decision
    result["reason_category"] = _reason_category(output.get("permissionDecisionReason"))
    return result


def claude_prompt_diagnostics(payload: object) -> dict[str, str]:
    """Report existing finite lifecycle outcomes without copying response text."""

    result = {
        "reason_code": "absent",
        "event": "invalid",
        "policy_action": "invalid",
        "system_message": "missing",
        "additional_context": "missing",
    }
    if type(payload) is not dict:
        return result
    values = cast(dict[str, object], payload)
    reason = values.get("reason_code")
    if reason is not None:
        result["reason_code"] = (
            reason
            if type(reason) is str and len(reason) <= 64 and reason in _LIFECYCLE_REASON_CODES
            else "unrecognized"
        )
    action = values.get("policy_action")
    if (
        type(action) is str
        and len(action) <= 24
        and action in {"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"}
    ):
        result["policy_action"] = action
    if "systemMessage" in values:
        result["system_message"] = "text" if type(values["systemMessage"]) is str else "invalid"
    raw_output = values.get("hookSpecificOutput")
    if type(raw_output) is not dict:
        return result
    output = cast(dict[str, object], raw_output)
    event = output.get("hookEventName")
    if type(event) is str and event == "UserPromptSubmit":
        result["event"] = event
    if "additionalContext" in output:
        result["additional_context"] = "text" if type(output["additionalContext"]) is str else "invalid"
    return result


def assert_claude_hook_asks_for_permission(result: subprocess.CompletedProcess[str], *, elapsed_seconds: float) -> None:
    """Preserve the generated hook regression assertions with finite diagnostics."""
    __tracebackhide__ = True
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail("Claude hook returned invalid JSON", pytrace=False)
    diagnostic = claude_hook_diagnostics(payload, returncode=result.returncode, elapsed_seconds=elapsed_seconds)
    returned_successfully = result.returncode == 0
    assert returned_successfully, diagnostic
    stderr_is_empty = result.stderr == ""
    assert stderr_is_empty, diagnostic
    expected_event = payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert expected_event, diagnostic
    asks_for_permission = payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert asks_for_permission, diagnostic
