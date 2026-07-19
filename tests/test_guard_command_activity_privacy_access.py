"""Authentication and approval-gate coverage for command-activity privacy routes."""

# pyright: reportAny=false, reportArgumentType=false, reportImplicitStringConcatenation=false
# pyright: reportMissingImports=false, reportUnusedCallResult=false
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import socket
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.approval_gate import update_settings as update_approval_gate_settings
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity_privacy import (
    COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION,
)
from tests.guard_command_activity_api_support import json_request, seed

_PASSWORD = "correct horse battery staple"


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)


def _enable_gate(store: GuardStore) -> None:
    update_approval_gate_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
    )


def _dashboard_token(daemon: GuardDaemonServer) -> str:
    return build_local_dashboard_session_token(
        auth_token=daemon._server.auth_token,
        surface="dashboard",
    )


def test_diagnostics_export_requires_dashboard_auth_and_hosted_allowlist(tmp_path: Path) -> None:
    store = _store(tmp_path)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        unauthenticated = json_request(daemon, "/v1/command-activity/diagnostics")
        allowed = json_request(
            daemon,
            "/v1/command-activity/diagnostics",
            token=_dashboard_token(daemon),
            origin="https://hol.org",
        )
        forbidden = json_request(
            daemon,
            "/v1/command-activity/diagnostics",
            token=_dashboard_token(daemon),
            origin="https://attacker.example",
        )
    finally:
        daemon.stop()

    assert unauthenticated[0] == 401
    assert allowed[0] == 200
    assert allowed[1]["schema_version"] == COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION
    assert allowed[2]["Access-Control-Allow-Origin"] == "https://hol.org"
    assert forbidden[:2] == (403, {"error": "forbidden_origin"})


def test_delete_route_requires_confirmation_and_high_risk_gate(tmp_path: Path) -> None:
    store = _store(tmp_path)
    seed(store)
    _enable_gate(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    token = _dashboard_token(daemon)
    try:
        missing_confirmation = json_request(
            daemon,
            "/v1/command-activity",
            method="DELETE",
            token=token,
            payload={},
        )
        missing_gate = json_request(
            daemon,
            "/v1/command-activity",
            method="DELETE",
            token=token,
            payload={"confirm": "clear-command-activity"},
        )
        wrong_gate = json_request(
            daemon,
            "/v1/command-activity",
            method="DELETE",
            token=token,
            payload={"confirm": "clear-command-activity", "approval_password": "incorrect password"},
        )
        assert store.count_command_activities() == 3
        cleared = json_request(
            daemon,
            "/v1/command-activity",
            method="DELETE",
            token=token,
            payload={"confirm": "clear-command-activity", "approval_password": _PASSWORD},
        )
    finally:
        daemon.stop()

    assert missing_confirmation[:2] == (
        400,
        {"error": "confirmation_required", "confirm": "clear-command-activity"},
    )
    assert missing_gate[0] == 403
    assert missing_gate[1]["error"] == "approval_gate_required"
    assert wrong_gate[0] == 403
    assert wrong_gate[1]["error"] == "approval_gate_invalid_password"
    assert cleared[0] == 200
    deleted = cast(dict[str, object], cleared[1]["deleted"])
    assert deleted["activities"] == 3
    assert store.count_command_activities() == 0


def test_delete_rejects_unauthenticated_headers_before_reading_body(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(_store(tmp_path), host="127.0.0.1", port=0)
    daemon.start()
    try:
        with socket.create_connection(("127.0.0.1", daemon.port), timeout=1) as client:
            client.settimeout(1)
            client.sendall(
                b"DELETE /v1/command-activity HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 100\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = client.recv(512)
    finally:
        daemon.stop()

    assert response.startswith(b"HTTP/1.0 401")
