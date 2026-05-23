"""Approval password gate behavior and bypass protections."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    public_config,
    revoke_cooldown,
)
from codex_plugin_scanner.guard.approval_gate import (
    update_settings as update_approval_gate_settings,
)
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.approval_commands import run_approval_command
from codex_plugin_scanner.guard.cli.commands import (
    _persist_claude_native_permission_policy,
    _queue_claude_native_approval_gate_fallback,
    run_guard_command,
)
from codex_plugin_scanner.guard.config import editable_guard_settings, load_guard_config, reset_guard_settings
from codex_plugin_scanner.guard.consumer.service import record_policy
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.mcp_tool_calls import allow_tool_call
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore

PASSWORD = "correct-password"
WRONG_PASSWORD = "wrong-password"


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _enable_gate(store: GuardStore, *, cooldown_seconds: int = 0, strict_all_decisions: bool = False) -> None:
    update_approval_gate_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": PASSWORD,
            "confirm_password": PASSWORD,
            "cooldown_seconds": cooldown_seconds,
            "strict_all_decisions": strict_all_decisions,
        },
    )


def _request(request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Shell command",
        artifact_type="tool_action_request",
        artifact_hash=f"hash-{request_id}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("shell_command",),
        source_scope="project",
        config_path="/repo/.codex/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/approvals/{request_id}",
    )


def _add_request(store: GuardStore, request_id: str) -> None:
    store.add_approval_request(_request(request_id), "2026-04-11T00:00:00+00:00")


def _approve(
    store: GuardStore,
    request_id: str,
    *,
    gate_input: ApprovalGateInput | None = None,
    now: str = "2026-04-11T00:01:00+00:00",
) -> dict[str, object]:
    return apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed",
        now=now,
        approval_gate_input=gate_input,
    )


def test_approval_gate_missing_password_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-missing")

    with pytest.raises(ApprovalGateError, match="Approval password is required"):
        _approve(store, "req-missing")

    assert store.get_approval_request("req-missing")["status"] == "pending"
    assert store.list_policy_decisions("codex") == []


def test_approval_gate_wrong_password_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-wrong")

    with pytest.raises(ApprovalGateError) as error:
        _approve(store, "req-wrong", gate_input=ApprovalGateInput(password=WRONG_PASSWORD))

    assert error.value.code == "approval_gate_invalid_password"
    assert store.get_approval_request("req-wrong")["status"] == "pending"
    assert store.list_policy_decisions("codex") == []


def test_approval_gate_correct_password_succeeds(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-correct")

    resolved = _approve(store, "req-correct", gate_input=ApprovalGateInput(password=PASSWORD))

    assert resolved["status"] == "resolved"
    policy = store.list_policy_decisions("codex")[0]
    assert policy["action"] == "allow"
    assert policy["artifact_id"] == "codex:project:req-correct"


def test_approval_gate_cooldown_works_expires_and_revokes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=900)
    _add_request(store, "req-cooldown-start")

    _approve(
        store,
        "req-cooldown-start",
        gate_input=ApprovalGateInput(password=PASSWORD, use_cooldown=True),
        now="2026-04-11T00:00:00+00:00",
    )
    assert public_config(store.guard_home, now="2026-04-11T00:10:00+00:00").cooldown_active is True

    _add_request(store, "req-cooldown-active")
    _approve(store, "req-cooldown-active", now="2026-04-11T00:10:00+00:00")

    _add_request(store, "req-cooldown-expired")
    with pytest.raises(ApprovalGateError) as expired:
        _approve(store, "req-cooldown-expired", now="2026-04-11T00:16:00+00:00")
    assert expired.value.code == "approval_gate_required"

    _approve(
        store,
        "req-cooldown-expired",
        gate_input=ApprovalGateInput(password=PASSWORD, use_cooldown=True),
        now="2026-04-11T00:16:01+00:00",
    )
    revoke_cooldown(store.guard_home, now="2026-04-11T00:16:02+00:00")
    _add_request(store, "req-cooldown-revoked")
    with pytest.raises(ApprovalGateError) as revoked:
        _approve(store, "req-cooldown-revoked", now="2026-04-11T00:16:03+00:00")
    assert revoked.value.code == "approval_gate_required"


def test_approval_gate_cooldown_opt_out_does_not_start_session(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=900)
    _add_request(store, "req-no-cooldown")

    _approve(
        store,
        "req-no-cooldown",
        gate_input=ApprovalGateInput(password=PASSWORD, use_cooldown=False),
        now="2026-04-11T00:00:00+00:00",
    )

    assert public_config(store.guard_home, now="2026-04-11T00:01:00+00:00").cooldown_active is False


def test_approval_gate_cli_noninteractive_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-cli")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    payload = run_approval_command(
        SimpleNamespace(
            approvals_command="approve",
            request_id="req-cli",
            approval_action="allow",
            scope="artifact",
            reason=None,
        ),
        store=store,
        workspace=None,
    )

    assert payload["error"] == "approval_gate_interactive_required"
    assert payload["exit_code"] == 4
    assert store.get_approval_request("req-cli")["status"] == "pending"


def test_approval_gate_cli_noninteractive_uses_active_cooldown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=900)
    _add_request(store, "req-cooldown-prime")
    _approve(
        store,
        "req-cooldown-prime",
        gate_input=ApprovalGateInput(password=PASSWORD, use_cooldown=True),
        now=datetime.now(timezone.utc).isoformat(),
    )
    _add_request(store, "req-cli-cooldown")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    payload = run_approval_command(
        SimpleNamespace(
            approvals_command="approve",
            request_id="req-cli-cooldown",
            approval_action="allow",
            scope="artifact",
            reason=None,
        ),
        store=store,
        workspace=None,
    )

    assert payload["resolved"] is True
    assert store.get_approval_request("req-cli-cooldown")["status"] == "resolved"


def test_approval_gate_cli_noninteractive_block_without_strict_mode_does_not_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-cli-block")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    payload = run_approval_command(
        SimpleNamespace(
            approvals_command="approve",
            request_id="req-cli-block",
            approval_action="block",
            scope="artifact",
            reason=None,
        ),
        store=store,
        workspace=None,
    )

    assert payload["resolved"] is True
    assert store.get_approval_request("req-cli-block")["status"] == "resolved"


def test_approval_gate_cli_deny_policy_write_without_strict_mode_does_not_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    exit_code = run_guard_command(
        SimpleNamespace(
            guard_command="deny",
            guard_home=str(store.guard_home),
            home=str(tmp_path / "home"),
            workspace=str(workspace),
            harness="codex",
            scope="artifact",
            artifact_id="codex:project:deny-cli",
            policy_action="block",
            publisher=None,
            reason=None,
            owner=None,
            expires_in_hours=None,
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )

    assert exit_code == 0
    policy = GuardStore(store.guard_home).list_policy_decisions("codex")[0]
    assert policy["action"] == "block"
    assert policy["artifact_id"] == "codex:project:deny-cli"


def test_approval_gate_settings_import_and_reset_cannot_disable_without_password(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)

    with pytest.raises(ApprovalGateError):
        update_approval_gate_settings(store.guard_home, {"enabled": False})
    with pytest.raises(ApprovalGateError):
        reset_guard_settings(store.guard_home)

    gate = public_config(store.guard_home)
    assert gate.enabled is True


def test_approval_gate_corrupt_cooldown_loads_safe_default(tmp_path: Path) -> None:
    store = _store(tmp_path)
    (store.guard_home / "approval-gate.json").write_text(
        json.dumps({"enabled": True, "cooldown_seconds": 123, "failed_attempts": 2}),
        encoding="utf-8",
    )

    gate = public_config(store.guard_home)

    assert gate.enabled is True
    assert gate.cooldown_seconds == 0


def test_approval_gate_invalid_cooldown_error_names_allowed_seconds(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(ApprovalGateError) as error:
        update_approval_gate_settings(
            store.guard_home,
            {
                "enabled": True,
                "new_password": PASSWORD,
                "confirm_password": PASSWORD,
                "cooldown_seconds": 123,
            },
        )

    assert "0 (every approval), 900 (15 minutes), or 3600 (1 hour) seconds" in str(error.value)


def test_approval_gate_settings_update_rejects_invalid_gate_payload_atomically(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        settings_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings",
            data=json.dumps(
                {
                    "settings": {
                        "approval_wait_timeout_seconds": 7,
                        "approval_gate": {
                            "enabled": True,
                            "current_password": PASSWORD,
                            "cooldown_seconds": 123,
                        },
                    }
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as settings_error:
            urllib.request.urlopen(settings_request, timeout=5)
        body = json.loads(settings_error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert settings_error.value.code == 403
    assert body["error"] == "approval_gate_invalid_cooldown"
    assert load_guard_config(store.guard_home).approval_wait_timeout_seconds == 120
    assert public_config(store.guard_home).cooldown_seconds == 0


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


def test_approval_gate_direct_lower_layers_cannot_bypass(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    decision = PolicyDecision(
        harness="codex",
        scope="artifact",
        action="allow",
        artifact_id="codex:project:direct",
        artifact_hash="hash-direct",
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-call",
        name="dangerous tool",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/repo/.codex/config.toml",
    )

    with pytest.raises(ApprovalGateError):
        store.upsert_policy(decision, "2026-04-11T00:00:00+00:00")
    with pytest.raises(ApprovalGateError):
        store.replace_remote_policies([decision], "2026-04-11T00:00:00+00:00")
    with pytest.raises(ApprovalGateError):
        record_policy(store, "codex", "allow", "artifact", "codex:project:record", None)
    with pytest.raises(ApprovalGateError):
        allow_tool_call(
            store=store,
            artifact=artifact,
            artifact_hash="hash-tool",
            decision_source="inline-approved",
            now="2026-04-11T00:00:00+00:00",
            signals=(),
            remember=True,
        )

    assert store.list_policy_decisions("codex") == []


def test_approval_gate_background_remote_policy_sync_fails_closed_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "guard-live-token",
        "2026-04-19T00:00:00+00:00",
    )
    monkeypatch.setattr(
        guard_runner_module,
        "_guard_device_metadata",
        lambda _store: ("device-1", "MacBook Pro"),
    )
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store: 0)
    monkeypatch.setattr(guard_runner_module, "sync_guard_events", lambda _store: 0)

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "syncedAt": "2026-04-19T00:00:10+00:00",
                    "exceptions": [
                        {
                            "scope": "artifact",
                            "harness": "codex",
                            "artifactId": "codex:project:cloud-allow",
                            "action": "allow",
                        }
                    ],
                }
            ).encode("utf-8")

    def _urlopen(_request, timeout):
        return _Response()

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _urlopen)

    payload = guard_runner_module.sync_receipts(store)

    assert payload["remote_policies_stored"] == 0
    assert payload["remote_policy_sync_blocked"] is True
    assert store.list_policy_decisions("codex") == []
    events = store.list_events(event_name="approval_gate/remote_policy_sync_blocked")
    assert events[0]["payload"]["error"] == "approval_gate_required"


def test_approval_gate_runtime_mcp_remembered_inline_allow_queues_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=store.guard_home,
    )
    artifact = GuardArtifact(
        artifact_id="codex:mcp:dangerous-tool",
        name="dangerous-tool",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path="/repo/.mcp.json",
        metadata={"tool_name": "dangerous-tool"},
    )
    proxy = RuntimeMcpGuardProxy(
        harness="codex",
        server_name="danger-server",
        command=["node", "server.js"],
        context=context,
        store=store,
        config=load_guard_config(store.guard_home),
        source_scope="project",
        config_path="/repo/.mcp.json",
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:5474")

    response, event = proxy._allow_and_forward(
        message={"id": 1},
        child_stdin=io.StringIO(),
        child_stdout=io.StringIO(),
        client_input=None,
        server_output=None,
        artifact=artifact,
        artifact_hash="hash-mcp",
        decision_source="inline-approved",
        signals=("mcp_dangerous_tool",),
        risk_categories=("mcp",),
        params={"name": "dangerous-tool", "arguments": {"path": ".env"}},
        remember=True,
    )

    assert event["decision"] == "queue-approval"
    assert response["error"]["message"].startswith("HOL Guard stopped tool call dangerous-tool")
    assert len(store.list_approval_requests(limit=10)) == 1
    assert store.list_policy_decisions("codex") == []


def test_approval_gate_native_permission_persistence_cannot_bypass(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)

    saved = _persist_claude_native_permission_policy(
        store=store,
        artifact_id="claude:project:tool",
        artifact_hash="hash-native",
        action="allow",
        reason="native approval",
        now="2026-04-11T00:00:00+00:00",
    )

    assert saved is False
    assert store.list_policy_decisions("claude-code") == []


def test_approval_gate_native_permission_failure_queues_guard_fallback(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    artifact = GuardArtifact(
        artifact_id="claude-code:runtime:bash:dangerous",
        name="Bash",
        harness="claude-code",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/repo/.claude/settings.json",
        command="echo MALICIOUS > marker",
    )

    saved = _persist_claude_native_permission_policy(
        store=store,
        artifact_id=artifact.artifact_id,
        artifact_hash="hash-native",
        action="allow",
        reason="native approval",
        now="2026-04-11T00:00:00+00:00",
    )
    queued = _queue_claude_native_approval_gate_fallback(
        store=store,
        harness="claude-code",
        artifact=artifact,
        artifact_digest="hash-native",
        approval_center_url="http://127.0.0.1:5474",
    )

    pending = store.list_approval_requests(limit=10)
    assert saved is False
    assert len(queued) == 1
    assert len(pending) == 1
    assert pending[0]["policy_action"] == "require-reapproval"
    assert pending[0]["approval_url"].startswith("http://127.0.0.1:5474/approvals/")
    assert "approval_gate_required" in pending[0]["risk_signals"]
    assert store.list_policy_decisions("claude-code") == []


def test_approval_gate_password_material_stays_out_of_public_payloads(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=3600)
    _add_request(store, "req-redaction")
    _approve(store, "req-redaction", gate_input=ApprovalGateInput(password=PASSWORD, use_cooldown=True))

    config_payload = editable_guard_settings(load_guard_config(store.guard_home))
    public_payload = public_config(store.guard_home).to_dict()
    events_payload = store.list_events()
    gate_state_text = (store.guard_home / "approval-gate.json").read_text(encoding="utf-8")
    combined_public = json.dumps(
        {
            "config": config_payload,
            "public_gate": public_payload,
            "events": events_payload,
        },
        sort_keys=True,
    )

    assert PASSWORD not in combined_public
    assert PASSWORD not in gate_state_text
    assert "approval_password" not in combined_public
