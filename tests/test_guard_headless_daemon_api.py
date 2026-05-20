"""Headless daemon API contract for Guard Cloud app actions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import _headless_action_error_payload
from codex_plugin_scanner.guard.store import GuardStore


def _read_json_response(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _read_redirect_response(request: urllib.request.Request) -> tuple[int, str]:
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, response.headers.get("Location", "")
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Location", "")


def _read_text_response(request: urllib.request.Request) -> tuple[int, str]:
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, response.read().decode("utf-8")


def _request(
    port: int,
    path: str,
    *,
    method: str = "POST",
    payload: dict[str, object] | None = None,
    token: str | None = None,
    authorization_token: str | None = None,
    dashboard_session_token: str | None = None,
    origin: str | None = "https://hol.org",
    referer: str | None = None,
) -> urllib.request.Request:
    data = json.dumps(payload or {}).encode("utf-8") if method != "GET" else None
    headers = {
        "Content-Type": "application/json",
    }
    if origin is not None:
        headers["Origin"] = origin
    if referer is not None:
        headers["Referer"] = referer
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-Guard-Dashboard-Session"] = token
    if authorization_token is not None:
        headers["Authorization"] = f"Bearer {authorization_token}"
    if dashboard_session_token is not None:
        headers["X-Guard-Dashboard-Session"] = dashboard_session_token
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
    codex_item = next(item for item in payload["items"] if item["harness"] == "codex")
    assert codex_item["display_name"] == "Codex"
    assert codex_item["headless_actions"] == ["install", "repair", "remove", "status", "scan"]
    assert codex_item["status"] in {"inactive", "observed", "protected"}


def test_cloud_app_handoff_serves_token_authenticated_local_action_page(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        status, body = _read_text_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud?action=connect",
                method="GET",
                origin=None,
                referer="https://hol.org/guard/apps/codex",
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert "HOL Guard local handoff" in body
    assert f"http://127.0.0.1:{daemon.port}" in body
    assert "/v1/apps/${data.harness}/cloud/complete" in body
    assert "handoffToken" in body
    assert auth_token not in body


def test_cloud_app_handoff_completion_runs_scoped_action_without_daemon_auth_token(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        status, body = _read_text_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud?action=connect",
                method="GET",
                origin=None,
                referer="https://hol.org/guard/apps/codex",
            ),
        )
        assert status == 200
        match = re.search(
            r'<script id="guard-handoff-data" type="application/json">([^<]+)</script>',
            body,
        )
        assert match is not None
        handoff_token = json.loads(match.group(1))["handoffToken"]
        action_status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud/complete",
                payload={"handoff_token": handoff_token},
                token=None,
                origin=f"http://127.0.0.1:{daemon.port}",
            )
        )
    finally:
        daemon.stop()

    assert action_status == 200
    assert payload["status"] == "completed"
    assert payload["state"]["app_status"] == "protected"
    assert payload["receipt"]["operation"] == "install"


def test_cloud_app_handoff_redirects_to_guard_cloud_without_side_effect_when_untrusted(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        status, location = _read_redirect_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud?action=connect",
                method="GET",
                origin=None,
            ),
        )
    finally:
        daemon.stop()

    assert status == 302
    parsed = urlparse(location)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://hol.org/guard/apps/codex"
    assert parse_qs(parsed.query)["guardDaemon"] == [f"http://127.0.0.1:{daemon.port}"]
    assert "guardLocalAction" not in parse_qs(parsed.query)
    fragment = parse_qs(parsed.fragment)
    assert fragment["guardDaemon"] == [f"http://127.0.0.1:{daemon.port}"]
    assert "guard-token" not in fragment


def test_cloud_app_handoff_rejects_confirmation_required_actions(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, location = _read_redirect_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud?action=disconnect",
                method="GET",
                origin=None,
                referer="https://hol.org/guard/apps/codex",
            ),
        )
    finally:
        daemon.stop()

    assert status == 302
    parsed = urlparse(location)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://hol.org/guard/apps/codex"
    assert "guardLocalAction" not in parse_qs(parsed.query)


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
            assert payload["state"]["receipt_summary"]["id"] == payload["receipt"]["id"]
            assert payload["state"]["receipt_summary"]["operation"] == operation
            assert "npx" not in json.dumps(payload)
            if operation == "install":
                assert payload["state"]["outcome"] == "app_connected"
                assert payload["state"]["app_status"] == "protected"
            if operation == "remove":
                assert payload["state"]["outcome"] == "app_disconnected"
                assert payload["state"]["app_status"] == "inactive"
            if operation == "scan":
                assert payload["state"]["outcome"] == "proof_passed"
                assert payload["state"]["proof_status"] == "passed"
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
                            "expires_at": "2099-01-01T00:00:00Z",
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
    assert decisions[0]["expires_at"] == "2099-01-01T00:00:00+00:00"
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
        cloud_workspace_status, cloud_workspace_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "workspace_id": "cloud-workspace-id",
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
    assert cloud_workspace_status == 400
    assert cloud_workspace_payload["error"] == "missing_scope_target"
    assert store.list_policy_decisions(harness="codex") == []


def test_headless_policy_sync_rejects_empty_policy_memory(tmp_path: Path) -> None:
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
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "missing_policy_memory"
    assert store.list_policy_decisions(harness="codex") == []


def test_headless_policy_sync_requires_explicit_scope_and_action(tmp_path: Path) -> None:
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
                    "policy_memory": json.dumps({"reason": "missing scope and action"}),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "missing_policy_fields"
    assert store.list_policy_decisions(harness="codex") == []


def test_headless_policy_sync_rejects_malformed_expiry(tmp_path: Path) -> None:
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
                    "policy_memory": json.dumps(
                        {
                            "scope": "harness",
                            "action": "review",
                            "expires_at": "9",
                        }
                    ),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "invalid_policy_expiry"
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
    assert bad_payload["status"] == "failed"
    assert bad_payload["error"]["code"] == "unknown_harness"
    assert bad_payload["error"]["retryable"] is False


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


def test_headless_api_uses_valid_bearer_session_when_session_header_is_bad(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/status",
                payload={"harness": "codex", "operation": "status"},
                authorization_token=token,
                dashboard_session_token="gld1.abcdefghijklmnop.qrstuvwxyz123456",
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["receipt"]["operation"] == "status"


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
    assert payload["state"]["outcome"] == "proof_failed"
    assert payload["state"]["proof_status"] == "failed"


def test_headless_api_rejects_missing_harness_with_structured_error(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/connect",
                token=token,
                payload={"operation": "install"},
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["status"] == "failed"
    assert payload["error"]["code"] == "missing_harness"
    assert payload["error"]["retryable"] is False


def test_headless_generic_action_error_omits_unstructured_detail() -> None:
    status, payload = _headless_action_error_payload(
        operation="repair",
        error_code="unexpected daemon blowup",
    )

    assert status == 400
    assert payload == {
        "status": "failed",
        "error": {
            "code": "repair_failed",
            "message": "Guard could not finish the repair.",
            "retryable": True,
        },
    }
