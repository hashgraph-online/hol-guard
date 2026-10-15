"""Fail-fast tests for the Codex bridge when the Guard daemon is provably dead."""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_bridge_failure_reason as failure_reason
from codex_plugin_scanner.guard.adapters import codex_daemon_dead_fastpath as fastpath
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge_flow as bridge_flow
from tests.codex_daemon_hook_bridge_fixtures import _bridge_config

_DEAD_PID = 2**22 + 12345


def _state(guard_home: Path, pid: int | None) -> Path:
    path = guard_home / "daemon-state.json"
    if pid is not None:
        path.write_text(json.dumps({"pid": pid, "port": 1}), encoding="utf-8")
    return path


def _dead_pid() -> int:
    pid = _DEAD_PID
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return pid
        except OSError:
            pass
        pid += 1


def test_missing_state_and_dead_pid_are_provably_dead(tmp_path: Path) -> None:
    assert fastpath.daemon_provably_dead(tmp_path / "daemon-state.json")
    assert fastpath.daemon_provably_dead(_state(tmp_path, _dead_pid()))


def test_tombstone_state_is_provably_dead(tmp_path: Path) -> None:
    state = tmp_path / "daemon-state.json"
    state.write_text("{}", encoding="utf-8")
    assert fastpath.daemon_provably_dead(state)
    state.write_text(json.dumps({"state": {}}), encoding="utf-8")
    assert fastpath.daemon_provably_dead(state)
    fastpath.record_start_failure(state)
    assert fastpath.should_fail_fast(state)


def test_live_pid_and_unreadable_state_are_not_provably_dead(tmp_path: Path) -> None:
    assert not fastpath.daemon_provably_dead(_state(tmp_path, os.getpid()))
    (tmp_path / "daemon-state.json").write_text("{not json", encoding="utf-8")
    assert not fastpath.daemon_provably_dead(tmp_path / "daemon-state.json")


def test_pidless_state_with_other_fields_is_not_provably_dead(tmp_path: Path) -> None:
    state = tmp_path / "daemon-state.json"
    for payload in ({"port": 1234}, {"pid": 0, "port": 1234}, {"state": {"port": 1234}}):
        state.write_text(json.dumps(payload), encoding="utf-8")
        fastpath.record_start_failure(state)
        assert not fastpath.daemon_provably_dead(state)
        assert not fastpath.should_fail_fast(state)


def test_marker_window_expires_and_clears(tmp_path: Path) -> None:
    state = _state(tmp_path, None)
    assert not fastpath.should_fail_fast(state)
    fastpath.record_start_failure(state)
    assert fastpath.should_fail_fast(state)
    later = time.time() + fastpath.FAILED_START_WINDOW_SECONDS + 1
    assert not fastpath.should_fail_fast(state, now=later)
    fastpath.clear_start_failure(state)
    assert not fastpath.should_fail_fast(state)


def test_marker_alone_does_not_fail_fast_when_daemon_is_alive(tmp_path: Path) -> None:
    state = _state(tmp_path, os.getpid())
    fastpath.record_start_failure(state)
    assert not fastpath.should_fail_fast(state)


def _failing_flow(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def dead_daemon(**kwargs: object) -> dict[str, object]:
        del kwargs
        calls.append("request")
        raise ConnectionRefusedError("daemon down")

    def start_daemon(command: tuple[str, ...], *, timeout_seconds: float, failure_kind: str) -> bool:
        del command, timeout_seconds, failure_kind
        calls.append("start")
        return False

    monkeypatch.setattr(bridge_flow, "_daemon_response", dead_daemon)
    monkeypatch.setattr(bridge_flow, "_run_daemon_start", start_daemon)
    return calls


def _run_main(guard_home: Path, monkeypatch: pytest.MonkeyPatch, event: str) -> dict[str, object]:
    config = _bridge_config(guard_home, 1)
    config["fallback_command"] = [sys.executable, "-c", "import sys; sys.exit(3)"]
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": event})))
    assert bridge.main(**config) == 0
    return {}


def test_second_hook_after_failed_start_denies_fast_with_repair_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    calls = _failing_flow(monkeypatch)

    _run_main(guard_home, monkeypatch, "PreToolUse")
    first = json.loads(capsys.readouterr().out)
    assert first["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert (guard_home / fastpath.FAILED_START_MARKER).exists()
    first_reason = first["hookSpecificOutput"]["permissionDecisionReason"]
    assert "hol-guard repair" in first_reason
    assert "hol-guard daemon repair" not in first_reason
    assert first_reason == failure_reason.DAEMON_DEAD_REASON

    calls.clear()
    started = time.monotonic()
    _run_main(guard_home, monkeypatch, "PreToolUse")
    elapsed = time.monotonic() - started
    second = json.loads(capsys.readouterr().out)

    assert calls == ["request"]
    assert elapsed < 2.0
    output = second["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert "hol-guard repair" in output["permissionDecisionReason"]


def test_daemon_reporting_refused_native_respawn_denies_fast_without_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    calls: list[str] = []
    refusal = json.dumps(
        {"error": "native_route_policy_unavailable", "reason_code": "native_resident_restart_circuit_open"}
    )

    def refusing_daemon(**kwargs: object) -> dict[str, object]:
        del kwargs
        calls.append("request")
        raise bridge_flow._DaemonResponseError(503, refusal, authenticated=False)

    def no_fallback(*args: object, **kwargs: object) -> None:
        raise AssertionError("the local fallback must not run")

    monkeypatch.setattr(bridge_flow, "_daemon_response", refusing_daemon)
    monkeypatch.setattr(bridge_flow, "_fallback_response", no_fallback)
    monkeypatch.setattr(bridge_flow, "_run_daemon_start", no_fallback)

    started = time.monotonic()
    _run_main(guard_home, monkeypatch, "PreToolUse")
    assert time.monotonic() - started < 2.0
    output = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert calls == ["request"]
    assert output["permissionDecision"] == "deny"
    assert "native runtime" in output["permissionDecisionReason"]
    assert "hol-guard repair" in output["permissionDecisionReason"]


def test_other_unauthenticated_503_still_uses_the_fallback(tmp_path: Path) -> None:
    plain = bridge_flow._DaemonResponseError(503, '{"error": "native_route_policy_unavailable"}', authenticated=False)
    refused = bridge_flow._DaemonResponseError(
        503, '{"error": "x", "reason_code": "native_resident_restart_circuit_open"}', authenticated=False
    )
    wrong_status = bridge_flow._DaemonResponseError(
        500, '{"reason_code": "native_resident_restart_circuit_open"}', authenticated=False
    )
    assert not fastpath.native_runtime_refused(plain)
    assert not fastpath.native_runtime_refused(wrong_status)
    assert not fastpath.native_runtime_refused(ValueError("nope"))
    assert not fastpath.native_runtime_refused(bridge_flow._DaemonResponseError(503, "{nope", authenticated=False))
    assert fastpath.native_runtime_refused(refused)


def test_tombstone_state_after_failed_restart_records_marker_and_fails_fast(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-state.json").write_text("{}", encoding="utf-8")
    calls = _failing_flow(monkeypatch)

    _run_main(guard_home, monkeypatch, "PreToolUse")
    capsys.readouterr()
    assert (guard_home / fastpath.FAILED_START_MARKER).exists()

    calls.clear()
    _run_main(guard_home, monkeypatch, "PreToolUse")
    second = json.loads(capsys.readouterr().out)

    assert calls == ["request"]
    assert "hol-guard repair" in second["hookSpecificOutput"]["permissionDecisionReason"]


def test_permission_request_still_fails_closed_on_fast_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    fastpath.record_start_failure(guard_home / "daemon-state.json")
    _failing_flow(monkeypatch)

    _run_main(guard_home, monkeypatch, "PermissionRequest")
    output = json.loads(capsys.readouterr().out)

    assert "allow" not in json.dumps(output)
    assert "hol-guard repair" in json.dumps(output)


def test_non_blocking_event_continues_with_repair_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    fastpath.record_start_failure(guard_home / "daemon-state.json")
    _failing_flow(monkeypatch)

    _run_main(guard_home, monkeypatch, "PostToolUse")
    output = json.loads(capsys.readouterr().out)

    assert "permissionDecision" not in json.dumps(output)
    assert "hol-guard repair" in json.dumps(output)


def test_successful_daemon_response_clears_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state = guard_home / "daemon-state.json"
    fastpath.record_start_failure(state)
    monkeypatch.setattr(bridge_flow, "_daemon_response", lambda **_: {"hookSpecificOutput": {}})

    response, overloaded, integrity_failed = bridge_flow.bridge_review_response(
        state_path=state,
        fallback_command=[sys.executable, "-c", "pass"],
        start_command=[sys.executable, "-c", "pass"],
        query="",
        data="{}",
        deadline=time.monotonic() + 5,
        manifest_path=None,
        config_json=None,
    )

    assert response is not None
    assert (overloaded, integrity_failed) == (False, False)
    assert not (guard_home / fastpath.FAILED_START_MARKER).exists()


def test_refusal_on_the_post_start_retry_denies_fast_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    refusal = json.dumps(
        {"error": "native_route_policy_unavailable", "reason_code": "native_resident_restart_circuit_open"}
    )
    errors: list[Exception] = [
        ConnectionRefusedError("daemon down"),
        bridge_flow._DaemonResponseError(503, refusal, authenticated=False),
    ]

    def daemon(**kwargs: object) -> dict[str, object]:
        del kwargs
        raise errors.pop(0)

    def no_fallback(*args: object, **kwargs: object) -> None:
        raise AssertionError("the local fallback must not run")

    monkeypatch.setattr(bridge_flow, "_daemon_response", daemon)
    monkeypatch.setattr(bridge_flow, "_trusted_launch_for_fallback", lambda **_: (None, False))
    monkeypatch.setattr(bridge_flow, "_daemon_start_succeeded", lambda **_: True)
    monkeypatch.setattr(bridge_flow, "_fallback_response", no_fallback)
    causes: list[bridge_flow.BridgeFailureCause] = []

    result = bridge_flow.bridge_review_response(
        state_path=guard_home / "daemon-state.json",
        fallback_command=[sys.executable, "-c", "pass"],
        start_command=[sys.executable, "-c", "pass"],
        query="",
        data="{}",
        deadline=time.monotonic() + 5,
        manifest_path=None,
        config_json=None,
        failure_causes=causes,
    )

    assert result == (None, False, False)
    assert errors == []
    assert any(cause.get("reason_code") == fastpath.NATIVE_RUNTIME_DEAD_REASON_CODE for cause in causes)
