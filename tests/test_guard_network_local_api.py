from __future__ import annotations

import json
import urllib.error
import urllib.request
from http.client import HTTPResponse
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_authenticated_network_status_is_privacy_safe_and_no_store(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = load_guard_daemon_auth_token(guard_home)
        assert token is not None
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/network/status",
            headers={"X-Guard-Token": token},
            method="GET",
        )
        with cast(HTTPResponse, urllib.request.urlopen(request, timeout=5)) as response:
            payload = cast(dict[str, object], json.loads(response.read().decode("utf-8")))
            cache_control = response.headers["Cache-Control"]
    finally:
        daemon.stop()

    assert payload["schema"] == "guard.network-status.v1"
    supervisor = cast(dict[str, object], payload["supervisor"])
    assert supervisor["phase"] == "unavailable"
    assert supervisor["effective_grade"] == "unavailable"
    assert supervisor["permits_enforcement"] is False
    assert cache_control == "no-store"
    assert str(tmp_path) not in json.dumps(payload, sort_keys=True)


def test_network_status_rejects_missing_token(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/network/status",
            method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=5)
    finally:
        daemon.stop()

    assert error.value.code == 401
