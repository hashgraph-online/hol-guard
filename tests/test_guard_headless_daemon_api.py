"""Headless daemon API contract for Guard Cloud app actions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.store import GuardStore


def _read_json_response(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _request(
    port: int,
    path: str,
    *,
    method: str = "POST",
    payload: dict[str, object] | None = None,
    token: str | None = None,
    origin: str = "https://hol.org",
) -> urllib.request.Request:
    data = json.dumps(payload or {}).encode("utf-8") if method != "GET" else None
    headers = {
        "Content-Type": "application/json",
        "Origin": origin,
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-Guard-Dashboard-Session"] = token
    return urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers=headers,
        method=method,
    )


def _dashboard_token(auth_token: str) -> str:
    payload_json = json.dumps(
        {
            "version": "guard-local-daemon-session.v1",
            "expires_at": datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat(),
        },
        separators=(",", ":"),
    )
    payload = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"gld1.{payload}.{encoded_signature}"


def _dashboard_token_for(store: GuardStore) -> str:
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    assert auth_token is not None
    return _dashboard_token(auth_token)


def test_headless_capabilities_endpoint_reports_safe_action_contract(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(daemon.port, "/v1/capabilities", method="GET", token=token),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["auth_state"] == "dashboard_session"
    assert payload["headless_api"]["operations"] == [
        "install",
        "repair",
        "remove",
        "status",
        "scan",
        "policy_sync",
    ]
    assert "codex" in payload["supported_harnesses"]
    assert payload["safe_failure_reasons"]["unsupported"] == "Harness is not supported by this daemon."


def test_headless_app_operations_write_receipts_without_cli_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        for path, operation in (
            ("/v1/apps/connect", "install"),
            ("/v1/apps/repair", "repair"),
            ("/v1/apps/status", "status"),
            ("/v1/apps/test", "scan"),
            ("/v1/apps/disconnect", "remove"),
        ):
            status, payload = _read_json_response(
                _request(
                    daemon.port,
                    path,
                    token=token,
                    payload={
                        "harness": "opencode",
                        "operation": operation,
                        "workspace_id": "workspace-1",
                        "confirmation_phrase": "disconnect-opencode",
                    },
                ),
            )
            assert status == 200
            assert payload["receipt"]["status"] == "completed"
            assert payload["receipt"]["operation"] == operation
            assert "npx" not in json.dumps(payload)
    finally:
        daemon.stop()

    receipts = store.list_receipts(limit=20, harness="opencode")
    receipt_operations = {receipt["artifact_name"] for receipt in receipts}
    assert {
        "Headless install",
        "Headless repair",
        "Headless status",
        "Headless scan",
        "Headless remove",
    }.issubset(receipt_operations)


def test_headless_policy_sync_persists_policy_and_receipt(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "workspace_id": "workspace-1",
                    "policy_memory": json.dumps(
                        {
                            "scope": "harness",
                            "action": "review",
                            "reason": "Cloud policy memory",
                        }
                    ),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["receipt"]["operation"] == "policy_sync"
    decisions = store.list_policy_decisions(harness="codex")
    assert decisions[0]["scope"] == "harness"
    assert decisions[0]["action"] == "review"
    assert store.list_receipts(limit=5, harness="codex")


def test_headless_policy_sync_rejects_global_allow_and_missing_scope_targets(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        global_status, global_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "policy_memory": json.dumps({"scope": "global", "action": "allow"}),
                },
            ),
        )
        workspace_status, workspace_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "policy_memory": json.dumps({"scope": "workspace", "action": "review"}),
                },
            ),
        )
    finally:
        daemon.stop()

    assert global_status == 400
    assert global_payload["error"] == "broad_allow_requires_narrow_scope"
    assert workspace_status == 400
    assert workspace_payload["error"] == "missing_scope_target"
    assert store.list_policy_decisions(harness="codex") == []


def test_headless_api_rejects_missing_auth_and_bad_harness(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        auth_status, auth_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/status",
                payload={"harness": "codex", "operation": "status"},
                token=None,
            ),
        )
        bad_status, bad_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/status",
                token=token,
                payload={"harness": "not-real", "operation": "status"},
            ),
        )
    finally:
        daemon.stop()

    assert auth_status == 401
    assert auth_payload["error"] == "unauthorized"
    assert bad_status == 404
    assert bad_payload["error"] == "unknown_harness"


def test_headless_api_rejects_forged_dashboard_session_token(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/status",
                payload={"harness": "codex", "operation": "status"},
                token="gld1.abcdefghijklmnop.qrstuvwxyz123456",
            ),
        )
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"


def test_headless_api_does_not_read_env_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    env_path = home / ".agents" / "skills" / "x" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("SECRET=value\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: home)
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path.name == ".env":
            raise AssertionError("headless daemon API must not read .env files")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/test",
                token=token,
                payload={"harness": "codex", "operation": "scan"},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["receipt"]["operation"] == "scan"
