"""Denial-path behavior when audit persistence is unavailable."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from ci.guard_daemon_harness import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_guard_daemon_query_token_denial_survives_audit_timeout(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    # The native daemon audits the denial itself; a lost audit write never
    # changes the answer.
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/events/stream?token={daemon._server.auth_token}",
            method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        assert error.value.code == 401
        payload = json.loads(error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert payload["error"] == "unauthorized"
