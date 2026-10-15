from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_bridge_failure_reason as failure_reason
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge_flow as bridge_flow
from codex_plugin_scanner.guard.adapters.codex_daemon_dead_fastpath import (
    DEAD_DAEMON_REASON_CODE,
    NATIVE_RUNTIME_DEAD_REASON,
    NATIVE_RUNTIME_DEAD_REASON_CODE,
)
from tests.codex_daemon_hook_bridge_fixtures import _bridge_config


@pytest.mark.parametrize(
    "reason_code",
    sorted(failure_reason.UNANSWERED_DAEMON_CODES),
)
def test_unanswered_daemon_asks_for_retry_not_repair(reason_code: str) -> None:
    causes = [{"stage": "daemon_request", "reason_code": reason_code}]

    reason = failure_reason.daemon_failure_reason(causes, daemon_overloaded=False)

    assert reason == failure_reason.DAEMON_UNAVAILABLE_REASON
    assert "authenticate" not in reason


@pytest.mark.parametrize(
    "reason_code",
    [
        "daemon_authenticated_http_error",
        "daemon_response_unauthenticated",
        "daemon_token_binding_mismatch",
        "daemon_state_or_response_invalid",
        "daemon_http_invalid",
        "daemon_transport_failure",
        "daemon_worker_failed",
    ],
)
def test_answered_but_untrusted_daemon_keeps_repair_message(reason_code: str) -> None:
    causes = [
        {"stage": "daemon_request", "reason_code": "daemon_transport_timeout"},
        {"stage": "daemon_retry", "reason_code": reason_code},
    ]

    reason = failure_reason.daemon_failure_reason(causes, daemon_overloaded=False)

    assert reason == failure_reason.AUTHENTICATION_FAILED_REASON
    assert failure_reason.daemon_failure_reason([], daemon_overloaded=False) == reason


def test_dead_daemon_and_overload_take_precedence() -> None:
    dead = [{"stage": "daemon_dead_fast", "reason_code": DEAD_DAEMON_REASON_CODE}]
    native_dead = [{"stage": "daemon_dead_fast", "reason_code": NATIVE_RUNTIME_DEAD_REASON_CODE}]
    overloaded = [{"stage": "daemon_request", "reason_code": "daemon_authenticated_http_error"}]

    assert failure_reason.daemon_failure_reason(dead, daemon_overloaded=True) == failure_reason.DAEMON_DEAD_REASON
    assert failure_reason.daemon_failure_reason(native_dead, daemon_overloaded=False) == NATIVE_RUNTIME_DEAD_REASON
    assert failure_reason.daemon_failure_reason(overloaded, daemon_overloaded=True) == failure_reason.OVERLOAD_REASON


def test_bridge_timeout_denies_with_retry_message_and_reports_causes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    # A live pid keeps the dead-daemon fast path out of this slow-daemon case.
    (guard_home / "daemon-state.json").write_text(json.dumps({"pid": os.getpid(), "port": 1}), encoding="utf-8")

    def slow_daemon(**kwargs: object) -> dict[str, object]:
        del kwargs
        raise TimeoutError("timed out")

    monkeypatch.setattr(bridge_flow, "_daemon_response", slow_daemon)
    monkeypatch.setattr(bridge_flow, "_run_daemon_start", lambda *args, **kwargs: False)
    config = _bridge_config(guard_home, 1)
    config["fallback_command"] = [sys.executable, "-c", "import sys; sys.exit(3)"]
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    assert bridge.main(**config) == 0

    captured = capsys.readouterr()
    output = json.loads(captured.out)["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert output["permissionDecisionReason"] == failure_reason.DAEMON_UNAVAILABLE_REASON
    diagnostic = json.loads(captured.err.strip().splitlines()[-1])
    assert diagnostic["schema"] == "hol-guard.codex-bridge-failure.v1"
    assert {"stage": "daemon_request", "reason_code": "daemon_transport_timeout"} in diagnostic["causes"]


@pytest.mark.parametrize(
    ("state_text", "reason_code"), [(None, "daemon_state_missing"), ("{}", "daemon_state_stopped")]
)
def test_missing_or_stopped_daemon_state_is_not_an_authentication_failure(
    tmp_path: Path, state_text: str | None, reason_code: str
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    key = guard_home / "daemon-discovery-key"
    key.write_text("00" * 32, encoding="utf-8")
    key.chmod(0o600)
    state = guard_home / "daemon-state.json"
    if state_text is not None:
        state.write_text(state_text, encoding="utf-8")
        state.chmod(0o600)

    with pytest.raises(ValueError) as raised:
        bridge_flow._daemon_response(state_path=state, query="", data="{}", timeout_seconds=1.0)

    assert bridge_flow._daemon_failure_reason(raised.value) == reason_code
    causes = [{"stage": "daemon_request", "reason_code": reason_code}]
    assert failure_reason.daemon_failure_reason(causes, daemon_overloaded=False) == (
        failure_reason.DAEMON_UNAVAILABLE_REASON
    )


def test_a_home_whose_daemon_never_started_is_not_an_authentication_failure(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    state = guard_home / "daemon-state.json"

    with pytest.raises(ValueError) as raised:
        bridge_flow._daemon_response(state_path=state, query="", data="{}", timeout_seconds=1.0)

    assert bridge_flow._daemon_failure_reason(raised.value) == "daemon_state_missing"


def test_state_without_its_discovery_key_still_fails_authentication(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    state = guard_home / "daemon-state.json"
    state.write_text('{"pid": 1}', encoding="utf-8")
    state.chmod(0o600)

    with pytest.raises(ValueError) as raised:
        bridge_flow._daemon_response(state_path=state, query="", data="{}", timeout_seconds=1.0)

    reason_code = bridge_flow._daemon_failure_reason(raised.value)
    assert reason_code not in failure_reason.UNANSWERED_DAEMON_CODES
    causes = [{"stage": "daemon_request", "reason_code": reason_code}]
    assert failure_reason.daemon_failure_reason(causes, daemon_overloaded=False) == (
        failure_reason.AUTHENTICATION_FAILED_REASON
    )
