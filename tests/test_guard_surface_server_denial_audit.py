"""Denial-path behavior when audit persistence is unavailable."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_guard_daemon_hook_path_denial_survives_audit_timeout(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    def timeout(*_args, **_kwargs):
        raise TimeoutError("audit storage timed out")

    monkeypatch.setattr(daemon._server.store, "add_event", timeout)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?workspace=relative-workspace",
            data=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": daemon._server.auth_token,
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
    finally:
        daemon.stop()

    assert error.value.code == 400
    payload = json.loads(error.value.read().decode("utf-8"))
    assert payload["error"] == "invalid_hook_workspace_path"
    assert store.list_events(event_name="daemon.hook.path_rejected") == []


def test_guard_daemon_query_token_denial_survives_audit_timeout(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    def timeout(*_args, **_kwargs):
        raise TimeoutError("audit storage timed out")

    monkeypatch.setattr(daemon._server.store, "add_event", timeout)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/events/stream?token={daemon._server.auth_token}",
            method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
    finally:
        daemon.stop()

    assert error.value.code == 401
    payload = json.loads(error.value.read().decode("utf-8"))
    assert payload["error"] == "unauthorized"
    assert store.list_events(event_name="daemon.auth.query_token_rejected") == []
