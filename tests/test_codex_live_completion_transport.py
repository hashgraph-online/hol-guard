"""Live approvals survive slow/lost responses without accepting unproven decisions."""

from __future__ import annotations

import http.client
import threading
import time
from contextlib import suppress
from http.server import HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from typing_extensions import override

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_resume as resume
from tests.codex_daemon_hook_bridge_fixtures import _ResumeDaemonHandler, _write_authenticated_daemon_files


def test_slow_authenticated_completion_reaches_original_hook(tmp_path: Path) -> None:
    class SlowCompletion(_ResumeDaemonHandler):
        resolution: ClassVar[str | None] = "allow"
        policy_action: ClassVar[str] = "review"
        approve_after: ClassVar[float] = 0.0
        started_at: ClassVar[float] = time.monotonic()
        finalize_count: ClassVar[int] = 0
        finalize_completed: ClassVar[bool] = True

        @override
        def _write_json(self, payload: dict[str, object], *, status: int = 200, keep_alive: bool = False) -> None:
            if payload.get("completed") is True:
                time.sleep(1.8)
            with suppress(BrokenPipeError):
                super()._write_json(payload, status=status, keep_alive=keep_alive)

    daemon = HTTPServer(("127.0.0.1", 0), SlowCompletion)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    guard_home = tmp_path / "guard-home"
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    SlowCompletion.guard_home = guard_home
    thread.start()
    try:
        response = resume.apply_browser_approval_wait(
            {
                "guardApprovalRequestId": SlowCompletion.request_id,
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
            },
            event_name="PreToolUse",
            hook_input='{"hook_event_name":"PreToolUse","tool_name":"Read"}',
            state_path=guard_home / "daemon-state.json",
            deadline=time.monotonic() + 5,
        )
    finally:
        daemon.shutdown()
        daemon.server_close()
        thread.join(timeout=5)
    assert response == resume.allow_pretool_response()
    assert SlowCompletion.finalize_count == 1


@pytest.mark.parametrize("failure", [TimeoutError(), http.client.IncompleteRead(b""), ConnectionResetError()])
def test_lost_completion_retries_same_bound_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    calls: list[dict[str, object]] = []

    def post(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        if len(calls) == 1:
            raise failure
        return {"completed": True, "action": "allow", "replayed": True}

    monkeypatch.setattr(resume, "_daemon_json_post", post)
    result = resume._complete_resolution(
        request_id="abcd1234ef567890",
        action="allow",
        hook_input='{"tool_name":"Read"}',
        state_path=tmp_path / "daemon-state.json",
        deadline=time.monotonic() + 15,
    )
    assert result == "allow"
    assert len(calls) == 2
    for key in ("path", "payload", "state_path"):
        assert calls[0][key] == calls[1][key]


@pytest.mark.parametrize(
    "response",
    [None, {}, {"completed": False}, {"completed": True, "action": "block"}],
)
def test_unproven_or_changed_decision_does_not_retry_or_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: dict[str, object] | None
) -> None:
    calls = 0

    def post(**_kwargs: object) -> dict[str, object] | None:
        nonlocal calls
        calls += 1
        return response

    monkeypatch.setattr(resume, "_daemon_json_post", post)
    assert (
        resume._complete_resolution(
            request_id="abcd1234ef567890",
            action="allow",
            hook_input="{}",
            state_path=tmp_path / "daemon-state.json",
            deadline=time.monotonic() + 15,
        )
        is None
    )
    assert calls == 1


def test_authentication_failure_is_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def post(**_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise ValueError("authenticated response rejected")

    monkeypatch.setattr(resume, "_daemon_json_post", post)
    assert (
        resume._complete_resolution(
            request_id="abcd1234ef567890",
            action="allow",
            hook_input="{}",
            state_path=tmp_path / "daemon-state.json",
            deadline=time.monotonic() + 15,
        )
        is None
    )
    assert calls == 1


@pytest.mark.parametrize("budget", [0.1, 0.6, 100.0])
def test_transport_failure_is_bounded_by_attempts_and_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: float
) -> None:
    clock = [0.0]
    timeouts: list[float] = []

    def post(**kwargs: object) -> None:
        timeout = kwargs["timeout_seconds"]
        assert isinstance(timeout, float)
        assert 0 < timeout <= budget - clock[0]
        timeouts.append(timeout)
        clock[0] += timeout
        raise TimeoutError()

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(resume, "_daemon_json_post", post)
    assert (
        resume._complete_resolution(
            request_id="abcd1234ef567890",
            action="allow",
            hook_input="{}",
            state_path=tmp_path / "daemon-state.json",
            deadline=budget,
        )
        is None
    )
    assert clock[0] <= budget
    assert len(timeouts) == (0 if budget < 0.2 else 1 if budget < 1 else 3)
