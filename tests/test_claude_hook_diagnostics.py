"""Diagnostic messages must identify finite outcomes without copying content."""

from __future__ import annotations

import io
import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.daemon.hook_worker_responses import observe_lifecycle_fail_safe_response
from tests import test_guard_surface_server as surface_tests
from tests.claude_hook_diagnostics import claude_hook_diagnostics, claude_prompt_diagnostics
from tests.test_guard_claude_adapter import (
    test_claude_daemon_hook_command_falls_back_to_native_ask_on_daemon_miss as run_original_ask_test,
)

_PRIVATE = "synthetic-person@example.invalid /synthetic/private/path token=synthetic-secret"
_INPUT = json.dumps({"hook_event_name": "PreToolUse", "private_detail": _PRIVATE})


def _diagnostics(response: str, *, elapsed_seconds: object = 9.93) -> dict[str, str | int]:
    return claude_hook_diagnostics(json.loads(response), returncode=0, elapsed_seconds=elapsed_seconds)


@pytest.mark.parametrize(
    ("detail", "category"),
    [
        (_PRIVATE + "; fallback exhausted the hook deadline", "fallback_deadline_exhausted"),
        (_PRIVATE + "; fallback timed out", "fallback_timed_out"),
        (_PRIVATE + "; fallback returned malformed hook JSON", "fallback_invalid_json"),
        (_PRIVATE + "; recovered daemon returned malformed hook JSON", "recovered_daemon_invalid_json"),
        (_PRIVATE + "; fallback exited 7", "fallback_exited"),
        (_PRIVATE + "; fallback exited -9", "fallback_exited"),
        (_PRIVATE + "; fallback exited None", "fallback_exited"),
        ("daemon returned malformed hook JSON", "daemon_invalid_json"),
        (_PRIVATE, "degraded_other"),
    ],
)
def test_actual_degraded_producer_has_only_finite_diagnostics(detail: str, category: str) -> None:
    result = _diagnostics(bridge._degraded(detail, _INPUT))
    assert result == {"decision": "allow", "reason_category": category, "returncode": 0, "elapsed_ms": 9930}
    assert _PRIVATE not in json.dumps(result)


@pytest.mark.parametrize(
    ("process_result", "category"),
    [
        (BoundedHookProcessResult(None, _PRIVATE, False, True, stderr=_PRIVATE), "fallback_timed_out"),
        (BoundedHookProcessResult(0, _PRIVATE, False, False, stderr=_PRIVATE), "fallback_invalid_json"),
        (BoundedHookProcessResult(7, _PRIVATE, False, False, stderr=_PRIVATE), "fallback_exited"),
    ],
)
def test_actual_fallback_producer_categories(
    monkeypatch: pytest.MonkeyPatch, process_result: BoundedHookProcessResult, category: str
) -> None:
    monkeypatch.setattr(bridge, "run_isolated_hook_process", lambda *_args, **_kwargs: process_result)
    response = bridge._run_local_fallback(_PRIVATE, _INPUT, ("synthetic-command",))
    assert _diagnostics(response)["reason_category"] == category
    assert _PRIVATE not in json.dumps(_diagnostics(response))


def test_actual_expired_fallback_does_not_run_a_command(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_process(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("expired fallback must not execute")

    monkeypatch.setattr(bridge, "run_isolated_hook_process", unexpected_process)
    response = bridge._run_local_fallback(_PRIVATE, _INPUT, (), deadline=time.monotonic() - 1)
    assert _diagnostics(response)["reason_category"] == "fallback_deadline_exhausted"


@pytest.mark.parametrize("response", ["", "not-json", "[]"])
def test_actual_invalid_daemon_output_has_no_raw_content(response: str) -> None:
    result = _diagnostics(
        bridge._valid_hook_json_or_degraded(response, reason="daemon returned malformed hook JSON", data=_INPUT)
    )
    assert result["reason_category"] == "daemon_invalid_json"


@pytest.mark.parametrize("decision", ["allow", "ask", "deny"])
def test_valid_decisions_and_slow_elapsed_do_not_imply_timeout(decision: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": _PRIVATE + "; fallback timed out",
        },
        "private_detail": _PRIVATE,
    }
    result = claude_hook_diagnostics(payload, returncode=0, elapsed_seconds=20)
    assert result == {"decision": decision, "reason_category": "unrecognized", "returncode": 0, "elapsed_ms": 20000}


@pytest.mark.parametrize("payload", [None, [], _PRIVATE, {}, {"hookSpecificOutput": _PRIVATE}])
def test_invalid_payloads_are_not_echoed(payload: object) -> None:
    result = claude_hook_diagnostics(payload, returncode=_PRIVATE, elapsed_seconds=_PRIVATE)
    assert result == {
        "decision": "invalid",
        "reason_category": "unrecognized",
        "returncode": "invalid",
        "elapsed_ms": "invalid",
    }


@pytest.mark.parametrize("value", [_PRIVATE, None, [], {}, True, 10**100, float("nan"), float("inf"), -1, 601])
def test_invalid_numeric_values_are_excluded(value: object) -> None:
    result = claude_hook_diagnostics({}, returncode=value, elapsed_seconds=value)
    assert result["elapsed_ms"] == "invalid"
    assert result["returncode"] == (-1 if type(value) is int and value == -1 else "invalid")


@pytest.mark.parametrize("field", ["hookEventName", "permissionDecision", "permissionDecisionReason"])
@pytest.mark.parametrize("value", [_PRIVATE, [], {}, True, None, "x" * 8193])
def test_invalid_or_sensitive_fields_are_excluded(field: str, value: object) -> None:
    output: dict[str, object] = {"hookEventName": "PreToolUse", "permissionDecision": "allow"}
    output[field] = value
    result = claude_hook_diagnostics({"hookSpecificOutput": output}, returncode=0, elapsed_seconds=1)
    assert set(result.values()) <= {"allow", "invalid", "unrecognized", 0, 1000}
    assert _PRIVATE not in json.dumps(result)


def test_terminal_suffix_is_required_for_a_known_category() -> None:
    response = bridge._degraded("synthetic; fallback timed out; " + _PRIVATE, _INPUT)
    assert _diagnostics(response)["reason_category"] == "degraded_other"


@pytest.mark.parametrize("field", ["decision", "event", "stderr", "returncode"])
def test_original_ask_assertions_only_emit_safe_diagnostics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, field: str
) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": _PRIVATE if field == "event" else "PreToolUse",
            "permissionDecision": _PRIVATE if field == "decision" else "ask",
            "permissionDecisionReason": _PRIVATE,
        }
    }
    completed = subprocess.CompletedProcess(
        args=[_PRIVATE],
        returncode=1000000 if field == "returncode" else 0,
        stdout=json.dumps(payload),
        stderr=_PRIVATE if field == "stderr" else "",
    )
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: completed)
    with pytest.raises(AssertionError) as failure:
        run_original_ask_test(tmp_path)
    message = str(failure.value)
    assert "reason_category" in message
    assert _PRIVATE not in message
    assert "1000000" not in message


def test_original_ask_invalid_json_is_not_echoed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    completed = subprocess.CompletedProcess(args=[_PRIVATE], returncode=0, stdout=_PRIVATE, stderr=_PRIVATE)
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: completed)
    with pytest.raises(pytest.fail.Exception) as failure:
        run_original_ask_test(tmp_path)
    assert str(failure.value) == "Claude hook returned invalid JSON"


@pytest.mark.parametrize(
    "reason",
    [
        "daemon_hook_queue_capacity",
        "daemon_hook_deadline_exhausted",
        "daemon_hook_process_deadline_exhausted",
        "daemon_hook_process_not_ready",
        "daemon_hook_process_timeout",
        "daemon_hook_process_failed",
        "daemon_worker_exception",
        "native_hook_worker_unsupported",
        "python_oracle_exception",
    ],
)
def test_actual_lifecycle_failure_producer_retains_only_finite_reason(reason: str) -> None:
    payload = observe_lifecycle_fail_safe_response("claude-code", event_name="UserPromptSubmit", reason_code=reason)
    assert claude_prompt_diagnostics(payload) == {
        "reason_code": reason,
        "event": "UserPromptSubmit",
        "policy_action": "allow",
        "system_message": "missing",
        "additional_context": "missing",
    }


@pytest.mark.parametrize(
    "field", ["reason_code", "policy_action", "systemMessage", "hookEventName", "additionalContext"]
)
@pytest.mark.parametrize("value", [_PRIVATE, _PRIVATE * 400, [], {}, True, None])
def test_prompt_diagnostics_exclude_invalid_or_sensitive_values(field: str, value: object) -> None:
    output: dict[str, object] = {"hookEventName": "UserPromptSubmit"}
    payload: dict[str, object] = {"hookSpecificOutput": output}
    if field in {"hookEventName", "additionalContext"}:
        output[field] = value
    else:
        payload[field] = value
    result = claude_prompt_diagnostics(payload)
    assert set(result.values()) <= {"absent", "unrecognized", "invalid", "missing", "text", "UserPromptSubmit"}
    assert _PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("payload", [None, [], _PRIVATE, {"hookSpecificOutput": _PRIVATE}])
def test_invalid_prompt_response_is_not_echoed(payload: object) -> None:
    assert claude_prompt_diagnostics(payload) == {
        "reason_code": "absent",
        "event": "invalid",
        "policy_action": "invalid",
        "system_message": "missing",
        "additional_context": "missing",
    }


def _invoke_original_prompt_assertions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: object) -> None:
    class Daemon:
        port: int = 321
        _server: SimpleNamespace = SimpleNamespace(auth_token="synthetic-token")

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

    def response(_daemon: object, _request: object, *, timeout: int) -> io.BytesIO:
        assert timeout == 5
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr(surface_tests, "GuardDaemonServer", Daemon)
    monkeypatch.setattr(surface_tests, "open_authenticated_claude_request", response)
    surface_tests.TestGuardSurfaceServer().test_guard_daemon_claude_hook_endpoint_brands_overridable_user_prompt_submit_without_blocking(
        tmp_path
    )


@pytest.mark.parametrize("field", ["missing", "message", "event", "context"])
def test_original_prompt_assertions_emit_only_safe_diagnostics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, field: str
) -> None:
    payload: dict[str, object] = {
        "reason_code": "daemon_hook_process_failed",
        "private_detail": _PRIVATE,
        "systemMessage": _PRIVATE if field == "message" else "HOL Guard intercepted this prompt",
        "hookSpecificOutput": {
            "hookEventName": _PRIVATE if field == "event" else "UserPromptSubmit",
            "additionalContext": _PRIVATE
            if field == "context"
            else "HOL Guard will intercept Claude's next attempt to access local secrets",
        },
    }
    if field == "missing":
        del payload["systemMessage"]
    with pytest.raises(AssertionError) as failure:
        _invoke_original_prompt_assertions(monkeypatch, tmp_path, payload)
    message = str(failure.value)
    assert "daemon_hook_process_failed" in message
    assert _PRIVATE not in message


def test_original_prompt_positive_predicates_remain_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _invoke_original_prompt_assertions(
        monkeypatch,
        tmp_path,
        {
            "systemMessage": "HOL Guard intercepted this prompt because it asks for synthetic content.",
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": "HOL Guard will intercept Claude's next attempt to access local secrets",
            },
        },
    )
