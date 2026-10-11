"""Codex PreToolUse live-hook deferral bounds after browser approval."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_resume as resume
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import local_approval_continuation as continuation
from codex_plugin_scanner.guard.live_process_identity import current_process_identity
from codex_plugin_scanner.guard.store import GuardStore
from tests.daemon_control_patching import patch_daemon_global
from tests.test_guard_codex_resume_endpoints import _post_json, _request, _seed_codex_operation

_FROZEN_NOW = "2026-05-19T10:00:00+00:00"


def test_pretool_bridge_wait_matches_codex_hook_hold_formula(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    (store.guard_home / "config.toml").write_text("approval_wait_timeout_seconds = 1\n", encoding="utf-8")
    process_identity = current_process_identity()
    assert process_identity is not None
    operation = {
        "created_at": _FROZEN_NOW,
        "status": "waiting_on_approval",
        "updated_at": _FROZEN_NOW,
        "metadata": {
            "codex_browser_wait_process": process_identity,
            "hook_event_name": "PreToolUse",
        },
    }
    assert resume._pretool_bridge_wait_is_active(store, operation, now="2026-05-19T10:00:04+00:00")
    assert not resume._pretool_bridge_wait_is_active(store, operation, now="2026-05-19T10:00:05+00:00")


def test_codex_approve_pretooluse_defers_within_bridge_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    codex_home = tmp_path / "codex-home"
    workspace.mkdir()
    codex_home.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-pretool"), _FROZEN_NOW)
    _seed_codex_operation(
        store,
        request_id="req-pretool",
        socket_path=None,
        thread_id="pretool-session-1",
        workspace=str(workspace),
        codex_home=str(codex_home),
        command_text="npm install minimist@1.2.8",
        hook_event_name="PreToolUse",
        waits_for_browser_approval=True,
        browser_wait_deadline_at="2026-05-19T10:00:05+00:00",
        status="waiting_on_approval",
    )
    patch_daemon_global(monkeypatch, "_now", lambda: _FROZEN_NOW)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-pretool/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert payload["codexResume"]["status"] == "pending"
    assert payload["codexResume"]["reason"] == "live_hook_waiting"
    assert "original Codex action continue" in payload["codexResume"]["message"]


def test_codex_approve_stale_pretooluse_requires_app_server_socket(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    codex_home = tmp_path / "codex-home"
    workspace.mkdir()
    codex_home.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-pretool-stale"), _FROZEN_NOW)
    _seed_codex_operation(
        store,
        request_id="req-pretool-stale",
        socket_path=None,
        thread_id="pretool-stale-session-1",
        workspace=str(workspace),
        codex_home=str(codex_home),
        command_text="npm install minimist@1.2.8",
        hook_event_name="PreToolUse",
        waits_for_browser_approval=False,
        status="waiting_on_approval",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-pretool-stale/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert payload["codexResume"]["status"] == "failed"
    assert payload["codexResume"]["reason"] == "socket_not_available"
    assert payload["codexResume"]["strategy"] == "codex-app-server-thread"


def test_codex_approve_pretooluse_uses_configured_wait_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    codex_home = tmp_path / "codex-home"
    workspace.mkdir()
    codex_home.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    (store.guard_home / "config.toml").write_text("approval_wait_timeout_seconds = 1\n", encoding="utf-8")
    store.add_approval_request(_request("req-pretool-short"), _FROZEN_NOW)
    _seed_codex_operation(
        store,
        request_id="req-pretool-short",
        socket_path=None,
        thread_id="pretool-short-session-1",
        workspace=str(workspace),
        codex_home=str(codex_home),
        command_text="npm install minimist@1.2.8",
        hook_event_name="PreToolUse",
        waits_for_browser_approval=False,
        status="waiting_on_approval",
    )
    patch_daemon_global(monkeypatch, "_now", lambda: "2026-05-19T10:00:06+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-pretool-short/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert payload["codexResume"]["status"] == "failed"
    assert payload["codexResume"]["reason"] == "socket_not_available"


def test_live_hook_defer_refuses_when_the_resident_gives_no_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def _operation(request_id: str) -> dict[str, object]:
        assert request_id == "req-live"
        return {
            "harness": "codex",
            "status": "waiting_on_approval",
            "metadata": {"hook_event_name": "PreToolUse"},
        }

    monkeypatch.setattr(store, "get_guard_operation_for_approval_request", _operation)
    monkeypatch.setattr(resume, "_live_hook_wait_is_active", lambda **kwargs: True)
    monkeypatch.setattr(resume, "_resume_call", lambda *args, **kwargs: None)

    with pytest.raises(resume.ResumeUnavailableError, match="resume_unavailable"):
        resume.defer_request_resume_to_live_hook(
            store,
            request_id="req-live",
            action="allow",
            now=_FROZEN_NOW,
        )


@pytest.mark.parametrize("error_type", [TimeoutError, OSError])
def test_resume_call_returns_none_when_the_storage_gate_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    repaired: list[str] = []

    def _gate(*, exclusive: bool) -> None:
        raise error_type("storage gate failed")

    def _repair() -> None:
        repaired.append("repaired")

    def _resident(*args: object, **kwargs: object) -> dict[str, object]:
        raise AssertionError("the resident must not run without the storage gate")

    monkeypatch.setattr(resume, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(resume, "_resident_request", _resident)
    monkeypatch.setattr(store, "_hold_storage_gate", _gate)
    monkeypatch.setattr(store, "_repair_store_permissions", _repair)

    assert resume._resume_call(store, call="status", request_id="req-live", now=_FROZEN_NOW) is None
    assert repaired == []


def test_resume_call_lets_a_nested_storage_gate_error_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def _gate(*, exclusive: bool) -> None:
        raise RuntimeError("nested exclusive upgrade")

    monkeypatch.setattr(resume, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(store, "_hold_storage_gate", _gate)

    with pytest.raises(RuntimeError, match="nested exclusive upgrade"):
        resume._resume_call(store, call="retry", request_id="req-live", now=_FROZEN_NOW)


def test_codex_continuation_stops_when_defer_cannot_reach_the_resident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    calls: list[str] = []

    def _defer(*args: object, **kwargs: object) -> dict[str, object]:
        raise resume.ResumeUnavailableError()

    def _retry(*args: object, **kwargs: object) -> dict[str, object]:
        calls.append("retry")
        raise AssertionError("a failed defer must not send another continuation")

    monkeypatch.setattr(continuation, "defer_request_resume_to_live_hook", _defer)
    monkeypatch.setattr(continuation, "retry_request_resume", _retry)

    result = continuation._codex_continuation(
        store=store,
        request_id="req-live",
        action="allow",
        request={"request_id": "req-live"},
        now=lambda: _FROZEN_NOW,
    )

    assert result == {"status": "failed", "reason": "resume_unavailable"}
    assert calls == []


def test_codex_continuation_reports_a_failed_retry_without_another_continuation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_guard_operation_for_approval_request", lambda request_id: None)

    def _defer(*args: object, **kwargs: object) -> None:
        return None

    def _retry(*args: object, **kwargs: object) -> dict[str, object]:
        raise resume.ResumeUnavailableError()

    def _continue(*args: object, **kwargs: object) -> dict[str, object]:
        raise AssertionError("a failed retry must not start another continuation")

    monkeypatch.setattr(continuation, "defer_request_resume_to_live_hook", _defer)
    monkeypatch.setattr(continuation, "retry_request_resume", _retry)
    monkeypatch.setattr(continuation, "continue_request_after_application", _continue)

    result = continuation._codex_continuation(
        store=store,
        request_id="req-live",
        action="allow",
        request={"request_id": "req-live"},
        now=lambda: _FROZEN_NOW,
    )

    assert result == {"status": "failed", "reason": "resume_unavailable"}
