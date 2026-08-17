from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.store import GuardStore


def _request(
    daemon: GuardDaemonServer,
    path: str,
    *,
    session_token: str | None = None,
    root_token: str | None = None,
    origin: str | None = None,
    payload: dict[str, object] | None = None,
) -> urllib.request.Request:
    headers: dict[str, str] = {}
    if session_token is not None:
        headers["X-Guard-Dashboard-Session"] = session_token
    if root_token is not None:
        headers["X-Guard-Token"] = root_token
    if origin is not None:
        headers["Origin"] = origin
    data = None
    method = "GET"
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    return urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=data,
        headers=headers,
        method=method,
    )


def test_dashboard_session_authorizes_new_extension_control_routes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    session_token = build_local_dashboard_session_token(
        auth_token=daemon._server.auth_token,
        surface="dashboard",
    )
    command = "git reset --hard HEAD~1"
    local_origin = f"http://127.0.0.1:{daemon.port}"

    try:
        with urllib.request.urlopen(
            _request(
                daemon,
                "/v1/extension-controls/test",
                session_token=session_token,
                origin=local_origin,
                payload={"extension_id": "command.git", "command": command},
            ),
            timeout=5,
        ) as response:
            test_payload = json.loads(response.read().decode("utf-8"))

        # A brand-new authority store has no validated history anchor yet, so this
        # route may legitimately return 409. The important auth regression is that
        # a valid signed dashboard session reaches the API instead of being rejected
        # with 401 by the daemon's dashboard-session path allowlist.
        with pytest.raises(urllib.error.HTTPError) as history_error:
            urllib.request.urlopen(
                _request(
                    daemon,
                    "/v1/extension-controls/history",
                    session_token=session_token,
                    origin=local_origin,
                ),
                timeout=5,
            )
        assert history_error.value.code == 409

        # A healthy fresh authority is not in degraded mode. Reaching this 409 also
        # proves the signed session was accepted for the new acknowledge route.
        with pytest.raises(urllib.error.HTTPError) as acknowledge_error:
            urllib.request.urlopen(
                _request(
                    daemon,
                    "/v1/extension-controls/acknowledge-degraded",
                    session_token=session_token,
                    origin=local_origin,
                    payload={},
                ),
                timeout=5,
            )
        assert acknowledge_error.value.code == 409

        with urllib.request.urlopen(
            _request(
                daemon,
                "/v1/extension-controls/test",
                root_token=daemon._server.auth_token,
                payload={"extension_id": "command.git", "command": command},
            ),
            timeout=5,
        ) as response:
            root_payload = json.loads(response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert test_payload["schema_version"] == "guard.daemon.extension-control-test.v1"
    assert "command" not in test_payload
    assert command not in json.dumps(test_payload, sort_keys=True)
    assert root_payload["schema_version"] == "guard.daemon.extension-control-test.v1"

    for path in (
        "/v1/extension-controls/history",
        "/v1/extension-controls/test",
        "/v1/extension-controls/acknowledge-degraded",
        "/v1/local-clis",
        "/v1/local-clis/preview",
        "/v1/local-clis/apply",
        "/v1/local-clis/recognize",
    ):
        assert daemon_server_module._GuardDaemonHandler._is_hosted_dashboard_api_path(
            path,
            [part for part in path.split("/") if part],
        )
    assert not daemon_server_module._GuardDaemonHandler._is_hosted_dashboard_api_path(
        "/v1/extension-controls/not-real",
        ["v1", "extension-controls", "not-real"],
    )


def test_dashboard_session_rejects_forged_expired_and_foreign_origin_test_lab_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    command_payload = {"extension_id": "command.git", "command": "git status"}
    local_origin = f"http://127.0.0.1:{daemon.port}"
    valid = build_local_dashboard_session_token(
        auth_token=daemon._server.auth_token,
        surface="dashboard",
    )
    forged = f"{valid[:-1]}{'A' if valid[-1] != 'A' else 'B'}"
    expired = build_local_dashboard_session_token(
        auth_token=daemon._server.auth_token,
        surface="dashboard",
        expires_in_seconds=1,
    )

    try:
        with pytest.raises(urllib.error.HTTPError) as forged_error:
            urllib.request.urlopen(
                _request(
                    daemon,
                    "/v1/extension-controls/test",
                    session_token=forged,
                    origin=local_origin,
                    payload=command_payload,
                ),
                timeout=5,
            )
        assert forged_error.value.code == 401

        original_time = daemon_server_module.time.time()
        monkeypatch.setattr(daemon_server_module.time, "time", lambda: original_time + 5)
        with pytest.raises(urllib.error.HTTPError) as expired_error:
            urllib.request.urlopen(
                _request(
                    daemon,
                    "/v1/extension-controls/test",
                    session_token=expired,
                    origin=local_origin,
                    payload=command_payload,
                ),
                timeout=5,
            )
        assert expired_error.value.code == 401

        with pytest.raises(urllib.error.HTTPError) as origin_error:
            urllib.request.urlopen(
                _request(
                    daemon,
                    "/v1/extension-controls/test",
                    session_token=valid,
                    origin="https://example.invalid",
                    payload=command_payload,
                ),
                timeout=5,
            )
        assert origin_error.value.code == 403
    finally:
        daemon.stop()
