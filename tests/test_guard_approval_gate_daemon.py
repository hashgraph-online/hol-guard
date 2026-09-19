"""Daemon approval-gate enforcement and TOTP routes."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.totp import totp_code_at_counter
from tests.guard_approval_gate_support import (
    PASSWORD,
    _add_request,
    _approve,
    _counter,
    _enable_gate,
    _post_daemon_json,
    _store,
    _trust_local_policy_rows,
)
from tests.guard_approval_gate_support import (
    _clear_agent_env_markers as _clear_agent_env_markers,
)
from tests.guard_approval_gate_support import (
    _default_store_platform as _default_store_platform,
)


def test_approval_gate_clear_review_queue_route_requires_proof_and_preserves_history(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-pending")
    _add_request(store, "req-resolved")
    _approve(store, "req-resolved", gate_input=ApprovalGateInput(password=PASSWORD))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as missing_error:
            _post_daemon_json(daemon, "/v1/requests/clear", {"status": "pending"})
        missing_body = json.loads(missing_error.value.read().decode("utf-8"))
        with pytest.raises(urllib.error.HTTPError) as expired_error:
            _post_daemon_json(daemon, "/v1/requests/clear", {"status": "expired"})
        expired_body = json.loads(expired_error.value.read().decode("utf-8"))

        clear_body = _post_daemon_json(
            daemon,
            "/v1/requests/clear",
            {"status": "pending", "approval_gate": {"password": PASSWORD}},
        )
    finally:
        daemon.stop()

    assert missing_error.value.code == 403
    assert missing_body["error"] == "approval_gate_required"
    assert expired_error.value.code == 400
    assert expired_body["error"] == "invalid_status"

    assert clear_body["cleared"] == 1
    assert clear_body["status"] == "pending"
    assert store.count_approval_requests(status="pending") == 0
    assert store.count_approval_requests(status="resolved") == 1


def test_approval_gate_daemon_totp_routes_round_trip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        enroll_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/approval-gate/totp/enroll",
            data=json.dumps(
                {
                    "device_label": "dashboard-device",
                    "approval_gate": {"password": PASSWORD},
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with urllib.request.urlopen(enroll_request, timeout=5) as enroll_response:
            enroll_body = json.loads(enroll_response.read().decode("utf-8"))

        secret = str(enroll_body["enrollment"]["manual_key"])
        verify_counter = _counter(datetime.now(timezone.utc).isoformat())
        verify_code = totp_code_at_counter(secret=secret, counter=verify_counter)
        verify_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/approval-gate/totp/verify",
            data=json.dumps(
                {
                    "approval_gate": {"password": PASSWORD},
                    "approval_totp_code": verify_code,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with urllib.request.urlopen(verify_request, timeout=5) as verify_response:
            verify_body = json.loads(verify_response.read().decode("utf-8"))

        disable_code = totp_code_at_counter(secret=secret, counter=verify_counter + 1)
        disable_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/approval-gate/totp/disable",
            data=json.dumps(
                {
                    "approval_totp_code": disable_code,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with urllib.request.urlopen(disable_request, timeout=5) as disable_response:
            disable_body = json.loads(disable_response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert enroll_body["settings"]["approval_gate"]["totp_pending"] is True
    assert verify_body["settings"]["approval_gate"]["totp_enabled"] is True
    assert disable_body["settings"]["approval_gate"]["totp_enabled"] is False


def test_approval_gate_daemon_api_cannot_bypass_password(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-daemon")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        approval_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/requests/req-daemon/approve",
            data=json.dumps({"scope": "artifact"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as approval_error:
            urllib.request.urlopen(approval_request, timeout=5)
        approval_body = json.loads(approval_error.value.read().decode("utf-8"))

        policy_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
            data=json.dumps(
                {
                    "harness": "codex",
                    "scope": "artifact",
                    "action": "allow",
                    "artifact_id": "codex:project:policy-api",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as policy_error:
            urllib.request.urlopen(policy_request, timeout=5)
        policy_body = json.loads(policy_error.value.read().decode("utf-8"))

        sync_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/policy/sync",
            data=json.dumps(
                {
                    "harness": "codex",
                    "policy_memory": {
                        "scope": "artifact",
                        "action": "allow",
                        "artifact_id": "codex:project:sync-api",
                    },
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as sync_error:
            urllib.request.urlopen(sync_request, timeout=5)
        sync_body = json.loads(sync_error.value.read().decode("utf-8"))

        reset_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings/reset",
            data=json.dumps({"confirm": "reset-local-settings"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as reset_error:
            urllib.request.urlopen(reset_request, timeout=5)
        reset_body = json.loads(reset_error.value.read().decode("utf-8"))

        revoke_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/approval-gate/cooldown/revoke",
            data=json.dumps({"approval_gate": {"password": PASSWORD}}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as revoke_error:
            urllib.request.urlopen(revoke_request, timeout=5)
        revoke_body = json.loads(revoke_error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert approval_error.value.code == 403
    assert policy_error.value.code == 403
    assert sync_error.value.code == 403
    assert reset_error.value.code == 403
    assert revoke_error.value.code == 401
    assert approval_body["error"] == "approval_gate_required"
    assert policy_body["error"] == "approval_gate_required"
    assert sync_body["error"] == "approval_gate_required"
    assert reset_body["error"] == "approval_gate_required"
    assert revoke_body["error"] == "unauthorized"
    assert store.get_approval_request("req-daemon")["status"] == "pending"
    assert store.list_policy_decisions("codex") == []


def test_daemon_approval_defaults_artifact_scope_to_one_time(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _add_request(store, "req-daemon-once")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        body = _post_daemon_json(daemon, "/v1/requests/req-daemon-once/approve", {"scope": "artifact"})
    finally:
        daemon.stop()

    assert body["resolved"] is True
    assert store.get_approval_request("req-daemon-once")["status"] == "resolved"
    assert store.list_policy_decisions("codex") == []


def test_daemon_approval_narrows_legacy_unsupported_request_scope(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _add_request(store, "req-daemon-global")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        payload = _post_daemon_json(
            daemon,
            "/v1/requests/req-daemon-global/approve",
            {"scope": "global"},
        )
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert payload["applied_scope"] == "artifact"
    assert payload["scope_warning"] == "legacy_scope_narrowed_to_artifact"


@pytest.mark.parametrize("field_name", ["remember", "persist_policy"])
def test_daemon_approval_false_artifact_scope_still_allows_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field_name: str,
) -> None:
    _trust_local_policy_rows(monkeypatch)
    store = _store(tmp_path)
    request_id = f"req-daemon-false-{field_name.replace('_', '-')}"
    _add_request(store, request_id)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        body = _post_daemon_json(
            daemon,
            f"/v1/requests/{request_id}/approve",
            {"scope": "artifact", field_name: False},
        )
    finally:
        daemon.stop()

    assert body["resolved"] is True
    assert store.list_policy_decisions("codex") == []
    assert (
        store.resolve_policy(
            "codex",
            f"codex:project:{request_id}",
            f"hash-{request_id}",
            now="2026-04-11T00:02:00+00:00",
        )
        == "allow"
    )
    assert (
        store.resolve_policy(
            "codex",
            f"codex:project:{request_id}",
            f"hash-{request_id}",
            now="2026-04-11T00:03:00+00:00",
        )
        is None
    )


def test_daemon_reapproval_cannot_remember_exact_artifact_scope(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _add_request(store, "req-daemon-remember")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        body = _post_daemon_json(
            daemon,
            "/v1/requests/req-daemon-remember/approve",
            {"scope": "artifact", "remember": True},
        )
    finally:
        daemon.stop()

    assert body["resolved"] is True
    assert body["applied_scope"] == "artifact"
    assert store.list_policy_decisions("codex") == []
