"""Codex PreToolUse live-hook deferral bounds after browser approval."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_resume as resume
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_codex_resume_endpoints import _post_json, _request, _seed_codex_operation

_FROZEN_NOW = "2026-05-19T10:00:00+00:00"


def test_pretool_bridge_wait_matches_codex_hook_hold_formula(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    (store.guard_home / "config.toml").write_text("approval_wait_timeout_seconds = 1\n", encoding="utf-8")
    operation = {"created_at": _FROZEN_NOW, "updated_at": _FROZEN_NOW, "metadata": {}}
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
        waits_for_browser_approval=False,
        status="waiting_on_approval",
    )
    monkeypatch.setattr(daemon_server, "_now", lambda: _FROZEN_NOW)
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
    monkeypatch.setattr(daemon_server, "_now", lambda: "2026-05-19T10:00:06+00:00")
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
