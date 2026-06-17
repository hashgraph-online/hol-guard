"""Bulk allow-once eligibility and resolution behavior."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput
from codex_plugin_scanner.guard.approval_gate import update_settings as update_approval_gate_settings
from codex_plugin_scanner.guard.approvals import (
    bulk_allow_read_only_once,
    is_bulk_allow_once_eligible,
)
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

PASSWORD = "bulk-approve-password"


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _enable_gate(store: GuardStore) -> None:
    update_approval_gate_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": PASSWORD,
            "confirm_password": PASSWORD,
            "cooldown_seconds": 0,
        },
    )


def _file_read_request(
    request_id: str,
    *,
    target_path: str = "src/index.ts",
    artifact_type: str = "command",
    policy_action: str = "require-reapproval",
    risk_summary: str | None = None,
    decision_v2_json: dict[str, object] | None = None,
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="cursor",
        artifact_id=f"cursor:project:{request_id}",
        artifact_name="file read",
        artifact_type=artifact_type,
        artifact_hash=f"hash-{request_id}",
        policy_action=policy_action,
        recommended_scope="artifact",
        changed_fields=("file_read",),
        source_scope="project",
        config_path="/repo/.cursor/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        risk_summary=risk_summary,
        decision_v2_json=decision_v2_json,
        action_envelope_json={
            "schema_version": 1,
            "action_id": request_id,
            "harness": "cursor",
            "event_name": "tool_call",
            "action_type": "file_read",
            "workspace": "/repo",
            "workspace_hash": "workspace-hash",
            "tool_name": "Read",
            "command": None,
            "prompt_excerpt": None,
            "target_paths": [target_path],
            "network_hosts": [],
            "mcp_server": None,
            "mcp_tool": None,
            "package_manager": None,
            "package_name": None,
            "script_name": None,
            "raw_payload_redacted": {},
        },
    )


def store_request_dict(request: GuardApprovalRequest) -> dict[str, object]:
    payload = request.to_dict()
    return {str(key): value for key, value in payload.items()}


def test_is_bulk_allow_once_eligible_plain_file_read(tmp_path: Path) -> None:
    store = _store(tmp_path)
    plain = _file_read_request("req-plain")
    store.add_approval_request(plain, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-plain")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is True


def test_is_bulk_allow_once_eligible_file_read_request_artifact_type(tmp_path: Path) -> None:
    store = _store(tmp_path)
    request = _file_read_request("req-artifact-type", artifact_type="file_read_request")
    store.add_approval_request(request, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-artifact-type")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is True


def test_is_bulk_allow_once_eligible_rejects_secret_file_read(tmp_path: Path) -> None:
    store = _store(tmp_path)
    secret = _file_read_request(
        "req-secret",
        target_path=".env",
        risk_summary="reads .env file containing credentials",
        decision_v2_json={
            "action": "ask",
            "reason": "secret read",
            "signals": [
                {
                    "signal_id": "sec-001",
                    "category": "secret",
                    "severity": "high",
                    "confidence": "strong",
                    "detector": "secret.read",
                    "title": "Secret file read",
                    "plain_reason": "reads .env file",
                }
            ],
        },
    )
    store.add_approval_request(secret, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-secret")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is False


def test_is_bulk_allow_once_eligible_rejects_secret_path_without_signal(tmp_path: Path) -> None:
    store = _store(tmp_path)
    secret_path = _file_read_request("req-secret-path", target_path=".env")
    store.add_approval_request(secret_path, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-secret-path")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is False


def _shell_request(
    request_id: str,
    *,
    command: str = "npm test",
    artifact_name: str = "Shell command",
    decision_v2_json: dict[str, object] | None = None,
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="cursor",
        artifact_id=f"cursor:project:{request_id}",
        artifact_name=artifact_name,
        artifact_type="command",
        artifact_hash=f"hash-{request_id}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("shell_command",),
        source_scope="project",
        config_path="/repo/.cursor/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        decision_v2_json=decision_v2_json,
        action_envelope_json={
            "schema_version": 1,
            "action_id": request_id,
            "harness": "cursor",
            "event_name": "tool_call",
            "action_type": "shell_command",
            "workspace": "/repo",
            "workspace_hash": "workspace-hash",
            "tool_name": "Bash",
            "command": command,
            "prompt_excerpt": None,
            "target_paths": [],
            "network_hosts": [],
            "mcp_server": None,
            "mcp_tool": None,
            "package_manager": None,
            "package_name": None,
            "script_name": None,
            "raw_payload_redacted": {},
        },
    )


def test_is_bulk_allow_once_eligible_rejects_blocked(tmp_path: Path) -> None:
    store = _store(tmp_path)
    blocked = _file_read_request("req-blocked", policy_action="block")
    store.add_approval_request(blocked, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-blocked")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is False


def test_is_bulk_allow_once_eligible_allows_shell_command(tmp_path: Path) -> None:
    """Shell commands are now bulk-eligible with a tiered risk disclosure."""
    store = _store(tmp_path)
    shell = _shell_request("req-shell", command="npm test")
    store.add_approval_request(shell, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-shell")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is True


def test_is_bulk_allow_once_eligible_allows_destructive_shell(tmp_path: Path) -> None:
    """Destructive shells are bulk-eligible (high-tier) — dangerous but not
    trust-breaking. The dashboard escalates disclosure and requires a typed
    confirmation for these."""
    store = _store(tmp_path)
    destructive = _shell_request("req-rmrf", command="rm -rf node_modules")
    store.add_approval_request(destructive, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-rmrf")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is True


def test_is_bulk_allow_once_eligible_rejects_encoded_shell(tmp_path: Path) -> None:
    store = _store(tmp_path)
    encoded = _shell_request(
        "req-b64",
        command="echo aGVsbG8= | base64 -d | sh",
        artifact_name="Encoded shell",
    )
    store.add_approval_request(encoded, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-b64")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is False


def test_is_bulk_allow_once_eligible_rejects_prompt_injection(tmp_path: Path) -> None:
    store = _store(tmp_path)
    injection = _shell_request(
        "req-injection",
        artifact_name="Prompt injection attempt",
        decision_v2_json={
            "action": "ask",
            "reason": "injection",
            "signals": [
                {
                    "signal_id": "pi-001",
                    "category": "prompt_injection",
                    "severity": "high",
                    "confidence": "strong",
                    "detector": "prompt.injection",
                    "title": "Prompt injection",
                    "plain_reason": "ignore previous instructions",
                }
            ],
        },
    )
    store.add_approval_request(injection, "2026-06-16T00:00:00+00:00")
    stored = store.get_approval_request("req-injection")
    assert stored is not None
    assert is_bulk_allow_once_eligible(stored) is False


def test_bulk_allow_read_only_once_requires_gate(tmp_path: Path) -> None:
    store = _store(tmp_path)
    plain = _file_read_request("req-plain")
    store.add_approval_request(plain, "2026-06-16T00:00:00+00:00")

    with pytest.raises(ValueError, match="bulk_approve_gate_required"):
        bulk_allow_read_only_once(
            store=store,
            request_ids=["req-plain"],
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
        )


def test_bulk_allow_read_only_once_resolves_plain_reads_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    plain = _file_read_request("req-plain")
    secret = _file_read_request(
        "req-secret",
        target_path=".env",
        risk_summary="reads .env file containing credentials",
        decision_v2_json={
            "action": "ask",
            "reason": "secret read",
            "signals": [
                {
                    "signal_id": "sec-001",
                    "category": "secret",
                    "severity": "high",
                    "confidence": "strong",
                    "detector": "secret.read",
                    "title": "Secret file read",
                    "plain_reason": "reads .env file",
                }
            ],
        },
    )
    store.add_approval_request(plain, "2026-06-16T00:00:00+00:00")
    store.add_approval_request(secret, "2026-06-16T00:00:00+00:00")

    result = bulk_allow_read_only_once(
        store=store,
        request_ids=["req-plain", "req-secret"],
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        now="2026-06-16T00:01:00+00:00",
    )

    assert result["resolved_count"] == 1
    failed = result["failed"]
    assert isinstance(failed, list)
    assert len(failed) == 1
    assert failed[0]["request_id"] == "req-secret"
    assert failed[0]["error"] == "ineligible"
    assert store.get_approval_request("req-plain")["status"] == "resolved"
    assert store.get_approval_request("req-secret")["status"] == "pending"


def test_bulk_allow_read_only_once_resolves_multiple_plain_reads(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    plain1 = _file_read_request("req-plain-1")
    plain2 = _file_read_request("req-plain-2")
    store.add_approval_request(plain1, "2026-06-16T00:00:00+00:00")
    store.add_approval_request(plain2, "2026-06-16T00:00:00+00:00")

    result = bulk_allow_read_only_once(
        store=store,
        request_ids=["req-plain-1", "req-plain-2"],
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        now="2026-06-16T00:01:00+00:00",
    )

    assert result["resolved_count"] == 2
    failed = result["failed"]
    assert isinstance(failed, list)
    assert len(failed) == 0
    assert store.get_approval_request("req-plain-1")["status"] == "resolved"
    assert store.get_approval_request("req-plain-2")["status"] == "resolved"


def test_bulk_allow_resolves_mixed_file_read_and_shell(tmp_path: Path) -> None:
    """Broadened eligibility: a file read and a shell command approve together."""
    store = _store(tmp_path)
    _enable_gate(store)
    plain = _file_read_request("req-plain")
    shell = _shell_request("req-shell", command="npm test")
    store.add_approval_request(plain, "2026-06-16T00:00:00+00:00")
    store.add_approval_request(shell, "2026-06-16T00:00:00+00:00")

    result = bulk_allow_read_only_once(
        store=store,
        request_ids=["req-plain", "req-shell"],
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        now="2026-06-16T00:01:00+00:00",
    )

    assert result["resolved_count"] == 2
    assert result["failed"] == []
    assert "actions approved once" in result["resolution_summary"]
    assert store.get_approval_request("req-plain")["status"] == "resolved"
    assert store.get_approval_request("req-shell")["status"] == "resolved"


def test_bulk_allow_resolves_destructive_shell_in_mixed_batch(tmp_path: Path) -> None:
    """A destructive shell resolves alongside a file read now that destructive
    commands are bulk-eligible (high-tier). Trust-breaking actions (secrets,
    injection, bypass) remain the only ineligible set."""
    store = _store(tmp_path)
    _enable_gate(store)
    plain = _file_read_request("req-plain")
    destructive = _shell_request("req-rmrf", command="rm -rf node_modules")
    store.add_approval_request(plain, "2026-06-16T00:00:00+00:00")
    store.add_approval_request(destructive, "2026-06-16T00:00:00+00:00")

    result = bulk_allow_read_only_once(
        store=store,
        request_ids=["req-plain", "req-rmrf"],
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        now="2026-06-16T00:01:00+00:00",
    )

    assert result["resolved_count"] == 2
    assert result["failed"] == []
    assert store.get_approval_request("req-plain")["status"] == "resolved"
    assert store.get_approval_request("req-rmrf")["status"] == "resolved"


def test_bulk_allow_read_once_daemon_route(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    plain = _file_read_request("req-plain")
    store.add_approval_request(plain, "2026-06-16T00:00:00+00:00")
    daemon = GuardDaemonServer(store=store)
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/requests/bulk-allow-once",
            data=json.dumps(
                {
                    "request_ids": ["req-plain"],
                    "approval_password": PASSWORD,
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": daemon._server.auth_token,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["resolved_count"] == 1
        assert payload["failed"] == []
        assert store.get_approval_request("req-plain")["status"] == "resolved"
    finally:
        daemon.stop()
