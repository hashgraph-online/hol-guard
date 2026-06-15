from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("POST", "/v1/apps/connect", {"harness": "codex", "operation": "install"}),
        (
            "POST",
            "/v1/supply-chain/package-shims/install",
            {"harness": "codex", "operation": "install"},
        ),
        ("POST", "/v1/policy/sync", {"harness": "codex", "operation": "policy_sync"}),
        (
            "POST",
            "/v1/requests/remote-once",
            {"harness": "codex", "operation": "remote_once"},
        ),
        ("GET", "/v1/requests", None),
    ],
)
def test_hosted_dashboard_origin_rejects_legacy_cloud_control_paths(
    tmp_path: Path,
    method: str,
    path: str,
    payload: dict[str, object] | None,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        request = _request(
            daemon.port,
            path,
            method=method,
            payload=payload,
            token=token,
            origin="https://hol.org",
        )
        with pytest.raises(urllib.error.HTTPError) as error_info:
            urllib.request.urlopen(request)
    finally:
        daemon.stop()

    assert error_info.value.code == 403


def test_hosted_dashboard_origin_keeps_supported_connect_state_path(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/connect/state",
                method="GET",
                origin="https://hol.org",
                token=token,
            )
        )
    finally:
        daemon.stop()

    assert status == 410
    assert payload["error"] == "legacy_pairing_disabled"
