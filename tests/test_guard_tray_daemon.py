"""Tests for tray daemon endpoints (/v1/tray/status, /v1/tray/start, etc.).

Verifies that the daemon server correctly routes tray requests to the tray
lifecycle service and returns redacted JSON payloads. No tokens or secrets
should appear in any response.

Note: /v1/tray/start and /v1/tray/restart are NOT tested via real HTTP because
they block the daemon thread for up to PROCESS_START_TIMEOUT_SECONDS=15s
waiting for subprocess readiness, which exceeds the urllib timeout. The
routing is verified by the safe endpoints (status, stop, repair) which do
not spawn subprocesses.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def _json_request(
    port: int,
    token: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _with_daemon(guard_home: Path) -> tuple[GuardStore, GuardDaemonServer]:
    guard_home.mkdir(parents=True, exist_ok=True)
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    return store, daemon


class TestTrayDaemonStatus:
    """GET /v1/tray/status returns capability + state without tokens."""

    def test_status_returns_supported_state(self, tmp_path: Path) -> None:
        _store, daemon = _with_daemon(tmp_path / "guard-home")
        try:
            status, payload = _json_request(
                daemon.port,
                daemon._server.auth_token,
                "/v1/tray/status",
                method="GET",
            )
            assert status == 200
            assert "state" in payload
            assert "capability" in payload
            assert "locator" in payload
            assert payload["capability"]["supported"] in (True, False)
        finally:
            daemon.stop()

    def test_status_requires_auth(self, tmp_path: Path) -> None:
        _store, daemon = _with_daemon(tmp_path / "guard-home")
        try:
            status, payload = _json_request(
                daemon.port,
                "wrong-token",
                "/v1/tray/status",
                method="GET",
            )
            assert status == 401
            assert "error" in payload
        finally:
            daemon.stop()

    def test_status_payload_has_no_secrets(self, tmp_path: Path) -> None:
        """The status payload must never contain auth tokens or secrets."""
        _store, daemon = _with_daemon(tmp_path / "guard-home")
        try:
            _status, payload = _json_request(
                daemon.port,
                daemon._server.auth_token,
                "/v1/tray/status",
                method="GET",
            )
            payload_str = json.dumps(payload)
            # The daemon's own auth token must not leak into the response
            assert daemon._server.auth_token not in payload_str
            # No common secret field names
            for secret_key in ("token", "secret", "password", "auth_token", "bearer"):
                assert secret_key not in payload_str.lower(), f"Found '{secret_key}' in payload"
        finally:
            daemon.stop()


class TestTrayDaemonActions:
    """POST /v1/tray/{stop,repair} — safe actions that don't spawn subprocesses."""

    def test_stop_when_not_running_returns_ok(self, tmp_path: Path) -> None:
        """Stopping when no tray is running should return ok=True (idempotent)."""
        _store, daemon = _with_daemon(tmp_path / "guard-home")
        try:
            status, payload = _json_request(
                daemon.port,
                daemon._server.auth_token,
                "/v1/tray/stop",
                method="POST",
                payload={},
            )
            assert status == 200
            assert "ok" in payload
            assert "state" in payload
        finally:
            daemon.stop()

    def test_repair_returns_ok(self, tmp_path: Path) -> None:
        """Repair should always succeed (resets crash state)."""
        _store, daemon = _with_daemon(tmp_path / "guard-home")
        try:
            status, payload = _json_request(
                daemon.port,
                daemon._server.auth_token,
                "/v1/tray/repair",
                method="POST",
                payload={},
            )
            assert status == 200
            assert payload["ok"] is True
        finally:
            daemon.stop()

    def test_actions_require_auth(self, tmp_path: Path) -> None:
        _store, daemon = _with_daemon(tmp_path / "guard-home")
        try:
            status, _payload = _json_request(
                daemon.port,
                "",
                "/v1/tray/stop",
                method="POST",
                payload={},
            )
            assert status == 401
        finally:
            daemon.stop()

    def test_action_payload_has_no_secrets(self, tmp_path: Path) -> None:
        """Action response payloads must not leak the daemon auth token."""
        _store, daemon = _with_daemon(tmp_path / "guard-home")
        try:
            _status, payload = _json_request(
                daemon.port,
                daemon._server.auth_token,
                "/v1/tray/repair",
                method="POST",
                payload={},
            )
            payload_str = json.dumps(payload)
            assert daemon._server.auth_token not in payload_str
        finally:
            daemon.stop()
