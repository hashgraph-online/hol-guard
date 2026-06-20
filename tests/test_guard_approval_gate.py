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
from urllib.parse import parse_qs, urlparse

import pytest
from rich.console import Console

from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    disable_totp,
    public_config,
    revoke_cooldown,
)
from codex_plugin_scanner.guard.approval_gate import (
    update_settings as update_approval_gate_settings,
)
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli import prompt as guard_prompt_module
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
from codex_plugin_scanner.guard.policy_integrity import PolicyIntegrityVerificationResult
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.totp import TotpSecretStore, _temporary_atomic_path, totp_code_at_counter


@pytest.fixture(autouse=True)
def _default_store_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux")


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


PASSWORD = "correct-password"
WRONG_PASSWORD = "wrong-password"


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _trust_local_policy_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    def _valid_policy_row(
        self: GuardStore,
        row,
        *,
        mode: str,
        key: bytes | None,
        key_id: str | None,
        trusted_generation: int | None = None,
    ) -> PolicyIntegrityVerificationResult:
        return PolicyIntegrityVerificationResult(status="valid")

    monkeypatch.setattr(GuardStore, "_policy_integrity_result_for_row", _valid_policy_row)


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
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
    )


def _add_request(store: GuardStore, request_id: str) -> None:
    store.add_approval_request(_request(request_id), "2026-04-11T00:00:00+00:00")


def _post_daemon_json(
    daemon: GuardDaemonServer,
    path: str,
    payload: dict[str, object],
) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


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


def _counter(value: str) -> int:
    return int(datetime.fromisoformat(value).timestamp() // 30)


def _extract_secret(otpauth_uri: str) -> str:
    parsed = urlparse(otpauth_uri)
    query_values = parse_qs(parsed.query)
    values = query_values.get("secret")
    if values is None or len(values) == 0:
        raise AssertionError("otpauth URI did not include a secret")
    return values[0]


def _enable_totp(store: GuardStore, *, now: str) -> str:
    enrollment = begin_totp_enrollment(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        device_label="test-device",
        now=now,
    )
    secret = _extract_secret(str(enrollment["otpauth_uri"]))
    code = totp_code_at_counter(secret=secret, counter=_counter(now))
    confirm_totp_enrollment(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code=code),
        now=now,
    )
    return secret


def test_totp_atomic_temp_paths_are_random(tmp_path: Path) -> None:
    target_path = tmp_path / "guard-home" / "totp-secrets" / "seed.secret"
    first = _temporary_atomic_path(target_path)
    second = _temporary_atomic_path(target_path)
    try:
        assert first != second
        assert first.parent == target_path.parent
        assert second.parent == target_path.parent
        assert first.name != f"{target_path.name}.tmp"
        assert second.name != f"{target_path.name}.tmp"
    finally:
        if first.exists():
            first.unlink()
        if second.exists():
            second.unlink()


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


def test_approval_gate_approve_once_does_not_persist_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_local_policy_rows(monkeypatch)
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-once")

    resolved = _approve(store, "req-once", gate_input=ApprovalGateInput(password=PASSWORD))

    assert resolved["status"] == "resolved"
    assert store.list_policy_decisions("codex") == []
    first_retry = store.resolve_policy_decision(
        "codex",
        "codex:project:req-once",
        "hash-req-once",
        now="2026-04-11T00:02:00+00:00",
    )
    assert first_retry is not None
    assert first_retry["action"] == "allow"
    assert (
        store.resolve_policy_decision(
            "codex",
            "codex:project:req-once",
            "hash-req-once",
            now="2026-04-11T00:03:00+00:00",
        )
        is None
    )
    once_events = store.list_events(limit=20, event_name="approval.once")
    assert any(event["payload"]["request_id"] == "req-once" for event in once_events)
    assert store.list_policy_decisions("codex") == []


def test_approval_gate_artifact_remember_persists_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_local_policy_rows(monkeypatch)
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-remember")

    resolved = apply_approval_resolution(
        store=store,
        request_id="req-remember",
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed",
        now="2026-04-11T00:01:00+00:00",
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        persist_policy=True,
    )

    assert resolved["status"] == "resolved"
    policy = store.list_policy_decisions("codex")[0]
    assert policy["action"] == "allow"
    assert policy["artifact_id"] == "codex:project:req-remember"
    first_retry = store.resolve_policy_decision(
        "codex",
        "codex:project:req-remember",
        "hash-req-remember",
        now="2026-04-11T00:02:00+00:00",
    )
    second_retry = store.resolve_policy_decision(
        "codex",
        "codex:project:req-remember",
        "hash-req-remember",
        now="2026-04-11T00:03:00+00:00",
    )
    assert first_retry is not None
    assert second_retry is not None
    assert first_retry["action"] == "allow"
    assert second_retry["action"] == "allow"
    remembered_events = store.list_events(limit=20, event_name="rule.remembered.local")
    assert any(event["payload"]["request_id"] == "req-remember" for event in remembered_events)


def test_approval_gate_workspace_scope_uses_request_workspace_without_cli_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_local_policy_rows(monkeypatch)
    store = _store(tmp_path)
    _enable_gate(store)
    workspace = tmp_path / "workspace"
    request = GuardApprovalRequest(
        request_id="req-workspace",
        harness="codex",
        artifact_id="codex:project:tool-action:req-workspace",
        artifact_name="Shell command",
        artifact_type="tool_action_request",
        artifact_hash="hash-req-workspace",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("shell_command",),
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        workspace=str(workspace),
        review_command="hol-guard approvals approve req-workspace",
        approval_url="http://127.0.0.1:5474/requests/req-workspace",
    )
    store.add_approval_request(request, "2026-04-11T00:00:00+00:00")

    resolved = apply_approval_resolution(
        store=store,
        request_id="req-workspace",
        action="allow",
        scope="workspace",
        workspace=None,
        reason="remember this project",
        now="2026-04-11T00:01:00+00:00",
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
    )

    assert resolved["status"] == "resolved"
    assert (
        store.resolve_policy_decision(
            "codex",
            "codex:project:tool-action:req-workspace",
            "hash-req-workspace",
            workspace=str(workspace),
            now="2026-04-11T00:02:00+00:00",
        )["action"]
        == "allow"
    )


def test_approval_gate_workspace_scope_rejects_tampered_workspace_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_local_policy_rows(monkeypatch)
    store = _store(tmp_path)
    _enable_gate(store)
    request = GuardApprovalRequest(
        request_id="req-workspace-mismatch",
        harness="codex",
        artifact_id="codex:project:tool-action:req-workspace-mismatch",
        artifact_name="Shell command",
        artifact_type="tool_action_request",
        artifact_hash="hash-req-workspace-mismatch",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("shell_command",),
        source_scope="project",
        config_path=str(tmp_path / "workspace-a" / ".codex" / "config.toml"),
        workspace=str(tmp_path / "workspace-a"),
        review_command="hol-guard approvals approve req-workspace-mismatch",
        approval_url="http://127.0.0.1:5474/requests/req-workspace-mismatch",
    )
    store.add_approval_request(request, "2026-04-11T00:00:00+00:00")

    with pytest.raises(ValueError, match="workspace_scope_mismatch"):
        apply_approval_resolution(
            store=store,
            request_id="req-workspace-mismatch",
            action="allow",
            scope="workspace",
            workspace=str(tmp_path / "workspace-b"),
            reason="tampered project scope",
            now="2026-04-11T00:01:00+00:00",
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
        )


def test_approval_gate_rejects_unsupported_broad_scope_for_unscoped_request(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-global")

    with pytest.raises(ValueError, match="unsupported_request_scope"):
        apply_approval_resolution(
            store=store,
            request_id="req-global",
            action="allow",
            scope="global",
            workspace=None,
            reason="too broad",
            now="2026-04-11T00:01:00+00:00",
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
        )


def test_approval_gate_rejects_unsupported_workspace_scope_without_bound_workspace(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="req-workspace-unsupported",
            harness="codex",
            artifact_id="codex:project:req-workspace-unsupported",
            artifact_name="Shell command",
            artifact_hash="hash-workspace-unsupported",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("shell_command",),
            source_scope="project",
            config_path="",
            review_command="hol-guard approvals approve req-workspace-unsupported",
            approval_url="http://127.0.0.1:5474/requests/req-workspace-unsupported",
        ),
        "2026-04-11T00:00:00+00:00",
    )

    with pytest.raises(ValueError, match="unsupported_request_scope"):
        apply_approval_resolution(
            store=store,
            request_id="req-workspace-unsupported",
            action="allow",
            scope="workspace",
            workspace=None,
            reason="too broad",
            now="2026-04-11T00:01:00+00:00",
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
        )


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


def test_approval_cli_refuses_agent_managed_self_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _add_request(store, "req-agent-cli")
    monkeypatch.setenv("HOL_GUARD_HOOK_ARGV", "codex-pretool")

    payload = run_approval_command(
        SimpleNamespace(
            approvals_command="approve",
            request_id="req-agent-cli",
            approval_action="allow",
            scope="artifact",
            reason=None,
        ),
        store=store,
        workspace=None,
    )

    assert payload["resolved"] is False
    assert payload["error"] == "approval_cli_blocked_in_agent_context"
    assert payload["exit_code"] == 4
    assert store.get_approval_request("req-agent-cli")["status"] == "pending"


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


def test_approval_gate_cli_allow_policy_write_uses_active_cooldown_without_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=900)
    _add_request(store, "req-cooldown-prime-allow")
    _approve(
        store,
        "req-cooldown-prime-allow",
        gate_input=ApprovalGateInput(password=PASSWORD, use_cooldown=True),
        now=datetime.now(timezone.utc).isoformat(),
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    exit_code = run_guard_command(
        SimpleNamespace(
            guard_command="allow",
            guard_home=str(store.guard_home),
            home=str(tmp_path / "home"),
            workspace=str(workspace),
            harness="codex",
            scope="artifact",
            artifact_id="codex:project:allow-cli",
            policy_action="allow",
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
    assert policy["action"] == "allow"
    assert policy["artifact_id"] == "codex:project:allow-cli"


def test_approval_password_cli_command_family_status_enable_change_disable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    home_dir = tmp_path / "home"

    status_code = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-password",
            settings_approval_password_command="status",
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert status_code == 0
    assert public_config(store.guard_home).enabled is False

    enable_code = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-password",
            settings_approval_password_command="enable",
            new_password=PASSWORD,
            confirm_password=PASSWORD,
            cooldown_seconds=900,
            strict_all_decisions=False,
            current_password=None,
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert enable_code == 0
    assert public_config(store.guard_home).enabled is True

    change_code = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-password",
            settings_approval_password_command="change",
            current_password=PASSWORD,
            new_password="next-password",
            confirm_password="next-password",
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert change_code == 0

    disable_code = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-password",
            settings_approval_password_command="disable",
            current_password="next-password",
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert disable_code == 0
    assert public_config(store.guard_home).enabled is False


def test_approval_gate_cli_unlock_and_lock_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=3600)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_gate_prompt.getpass.getpass",
        lambda _prompt: PASSWORD,
    )

    unlock_payload = run_approval_command(
        SimpleNamespace(
            approvals_command="unlock",
            duration="15m",
        ),
        store=store,
        workspace=None,
    )
    assert unlock_payload["unlocked"] is True
    assert unlock_payload["cooldown_active"] is True
    assert public_config(store.guard_home).cooldown_seconds == 3600

    lock_payload = run_approval_command(
        SimpleNamespace(
            approvals_command="lock",
        ),
        store=store,
        workspace=None,
    )
    assert lock_payload["locked"] is True
    assert lock_payload["cooldown_active"] is False


def test_approval_gate_totp_enrollment_sets_pending_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    now = "2026-04-11T00:00:00+00:00"

    enrollment = begin_totp_enrollment(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        device_label="test-device",
        now=now,
    )

    assert enrollment["pending"] is True
    assert str(enrollment["otpauth_uri"]).startswith("otpauth://totp/HOL%20Guard:test-device?")
    assert "issuer=HOL%20Guard" in str(enrollment["otpauth_uri"])
    gate = public_config(store.guard_home, now=now)
    assert gate.totp_pending is True
    assert gate.totp_enabled is False


def test_approval_gate_totp_invalid_code_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    now = "2026-04-11T00:00:00+00:00"
    begin_totp_enrollment(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        now=now,
    )

    with pytest.raises(ApprovalGateError) as error:
        confirm_totp_enrollment(
            store.guard_home,
            approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code="000000"),
            now=now,
        )

    assert error.value.code == "approval_gate_totp_invalid"
    gate = public_config(store.guard_home, now=now)
    assert gate.totp_pending is True
    assert gate.totp_enabled is False


def test_approval_gate_totp_replay_rejected_and_next_step_succeeds(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    enrollment_now = "2026-04-11T00:00:00+00:00"
    secret = _enable_totp(store, now=enrollment_now)
    replay_code = totp_code_at_counter(secret=secret, counter=_counter(enrollment_now))

    _add_request(store, "req-totp-replay")
    with pytest.raises(ApprovalGateError) as replay_error:
        _approve(
            store,
            "req-totp-replay",
            gate_input=ApprovalGateInput(password=PASSWORD, totp_code=replay_code),
            now="2026-04-11T00:00:01+00:00",
        )
    assert replay_error.value.code == "approval_gate_totp_invalid"

    _add_request(store, "req-totp-next-step")
    next_now = "2026-04-11T00:00:31+00:00"
    next_code = totp_code_at_counter(secret=secret, counter=_counter(next_now))
    _approve(
        store,
        "req-totp-next-step",
        gate_input=ApprovalGateInput(password=PASSWORD, totp_code=next_code),
        now=next_now,
    )
    assert store.get_approval_request("req-totp-next-step")["status"] == "resolved"


def test_approval_gate_totp_clock_skew_boundary(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")

    skew_now = "2026-04-11T00:01:01+00:00"
    previous_step_code = totp_code_at_counter(secret=secret, counter=_counter(skew_now) - 1)
    _add_request(store, "req-totp-skew-accept")
    _approve(
        store,
        "req-totp-skew-accept",
        gate_input=ApprovalGateInput(password=PASSWORD, totp_code=previous_step_code),
        now=skew_now,
    )

    old_code = totp_code_at_counter(secret=secret, counter=_counter(skew_now) - 2)
    _add_request(store, "req-totp-skew-reject")
    with pytest.raises(ApprovalGateError) as old_error:
        _approve(
            store,
            "req-totp-skew-reject",
            gate_input=ApprovalGateInput(password=PASSWORD, totp_code=old_code),
            now=skew_now,
        )
    assert old_error.value.code == "approval_gate_totp_invalid"


def test_approval_gate_totp_manual_key_accepts_readability_dashes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    dashed_secret = "-".join(secret[index : index + 4] for index in range(0, len(secret), 4))

    assert totp_code_at_counter(secret=dashed_secret, counter=_counter("2026-04-11T00:01:00+00:00"))


def test_approval_gate_disable_totp_requires_password_and_totp(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")

    with pytest.raises(ApprovalGateError) as missing_totp:
        disable_totp(
            store.guard_home,
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
            now="2026-04-11T00:00:31+00:00",
        )
    assert missing_totp.value.code == "approval_gate_totp_required"

    with pytest.raises(ApprovalGateError) as invalid_totp:
        disable_totp(
            store.guard_home,
            approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code="000000"),
            now="2026-04-11T00:00:31+00:00",
        )
    assert invalid_totp.value.code == "approval_gate_totp_invalid"

    disable_now = "2026-04-11T00:01:31+00:00"
    disable_code = totp_code_at_counter(secret=secret, counter=_counter(disable_now))
    gate = disable_totp(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code=disable_code),
        now=disable_now,
    )
    assert gate.totp_enabled is False


def test_approval_gate_password_disable_requires_totp_when_enabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    home_dir = tmp_path / "home"
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")

    disable_without_totp = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-password",
            settings_approval_password_command="disable",
            current_password=PASSWORD,
            totp_code=None,
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert disable_without_totp == 4

    disable_now = datetime.now(timezone.utc).isoformat()
    disable_code = totp_code_at_counter(secret=secret, counter=_counter(disable_now))
    disable_with_totp = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-password",
            settings_approval_password_command="disable",
            current_password=PASSWORD,
            totp_code=disable_code,
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert disable_with_totp == 0
    assert public_config(store.guard_home).enabled is False


def test_approval_gate_cli_totp_commands_round_trip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    home_dir = tmp_path / "home"

    enroll_code = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-totp",
            settings_approval_totp_command="enroll",
            current_password=PASSWORD,
            device_label="cli-device",
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert enroll_code == 0
    assert public_config(store.guard_home).totp_pending is True

    state = json.loads((store.guard_home / "approval-gate.json").read_text(encoding="utf-8"))
    pending_secret_id = str(state["totp_pending_secret_id"])
    secret = TotpSecretStore(store.guard_home).get_secret(pending_secret_id)
    assert secret is not None

    verify_counter = _counter(datetime.now(timezone.utc).isoformat())
    verify_code = totp_code_at_counter(secret=secret, counter=verify_counter)
    verify_exit = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-totp",
            settings_approval_totp_command="verify",
            current_password=PASSWORD,
            code=verify_code,
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert verify_exit == 0
    assert public_config(store.guard_home).totp_enabled is True

    disable_code = totp_code_at_counter(secret=secret, counter=verify_counter + 1)
    disable_exit = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-totp",
            settings_approval_totp_command="disable",
            current_password=PASSWORD,
            code=disable_code,
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert disable_exit == 0
    assert public_config(store.guard_home).totp_enabled is False


def test_approval_gate_unlock_is_blocked_when_totp_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=900)
    _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_gate_prompt.getpass.getpass",
        lambda _prompt: PASSWORD,
    )

    unlock_payload = run_approval_command(
        SimpleNamespace(
            approvals_command="unlock",
            duration="15m",
        ),
        store=store,
        workspace=None,
    )
    assert unlock_payload["unlocked"] is False
    assert unlock_payload["error"] == "approval_gate_totp_required"


def test_approval_gate_settings_import_and_reset_cannot_disable_without_password(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)

    with pytest.raises(ApprovalGateError):
        update_approval_gate_settings(store.guard_home, {"enabled": False})
    with pytest.raises(ApprovalGateError):
        reset_guard_settings(store.guard_home)

    gate = public_config(store.guard_home)
    assert gate.enabled is True


def test_approval_gate_settings_import_and_reset_require_totp_when_enabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        import_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings/import",
            data=json.dumps(
                {
                    "settings": {
                        "approval_wait_timeout_seconds": 90,
                        "approval_gate": {"current_password": PASSWORD},
                    }
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as import_error:
            urllib.request.urlopen(import_request, timeout=5)
        import_body = json.loads(import_error.value.read().decode("utf-8"))

        reset_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings/reset",
            data=json.dumps(
                {
                    "confirm": "reset-local-settings",
                    "approval_gate": {"password": PASSWORD},
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as reset_error:
            urllib.request.urlopen(reset_request, timeout=5)
        reset_body = json.loads(reset_error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert import_error.value.code == 403
    assert reset_error.value.code == 403
    assert import_body["error"] == "approval_gate_totp_required"
    assert reset_body["error"] == "approval_gate_totp_required"


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

        clear_body = _post_daemon_json(
            daemon,
            "/v1/requests/clear",
            {"status": "pending", "approval_gate": {"password": PASSWORD}},
        )
    finally:
        daemon.stop()

    assert missing_error.value.code == 403
    assert missing_body["error"] == "approval_gate_required"
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
                    "approval_gate": {"password": PASSWORD},
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


def test_approval_gate_cooldown_revoke_requires_totp_when_enabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=900)
    _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        revoke_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/approval-gate/cooldown/revoke",
            data=json.dumps({"approval_gate": {"password": PASSWORD}}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as revoke_error:
            urllib.request.urlopen(revoke_request, timeout=5)
        revoke_body = json.loads(revoke_error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert revoke_error.value.code == 403
    assert revoke_body["error"] == "approval_gate_totp_required"


def test_approval_gate_corrupt_cooldown_loads_safe_default(tmp_path: Path) -> None:
    store = _store(tmp_path)
    (store.guard_home / "approval-gate.json").write_text(
        json.dumps({"enabled": True, "cooldown_seconds": 123, "failed_attempts": 2}),
        encoding="utf-8",
    )

    gate = public_config(store.guard_home)

    assert gate.enabled is True
    assert gate.cooldown_seconds == 0


def test_approval_gate_malformed_cooldown_timestamp_does_not_unlock(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=900)
    state_path = store.guard_home / "approval-gate.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["cooldown_expires_at"] = "not-a-timestamp"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    _add_request(store, "req-malformed-cooldown")

    with pytest.raises(ApprovalGateError) as error:
        _approve(store, "req-malformed-cooldown")

    assert error.value.code == "approval_gate_required"
    assert public_config(store.guard_home).cooldown_active is False
    assert store.get_approval_request("req-malformed-cooldown")["status"] == "pending"


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


def test_daemon_approval_rejects_unsupported_request_scope(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _add_request(store, "req-daemon-global")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/requests/req-daemon-global/approve",
            data=json.dumps({"scope": "global"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            payload = json.loads(error.read().decode("utf-8"))
            status = error.code
        else:
            raise AssertionError("expected HTTPError for unsupported request scope")
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "unsupported_request_scope"


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


def test_daemon_approval_can_remember_exact_artifact_scope(tmp_path: Path) -> None:
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
    policy = store.list_policy_decisions("codex")[0]
    assert policy["artifact_id"] == "codex:project:req-daemon-remember"


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


def test_approval_gate_allow_once_requires_password_prompt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    prompt_calls = 0

    def _approval_gate_input(_guard_home: Path) -> ApprovalGateInput:
        nonlocal prompt_calls
        prompt_calls += 1
        return ApprovalGateInput(password=PASSWORD)

    monkeypatch.setattr(guard_prompt_module, "prompt_for_approval_gate", _approval_gate_input)

    artifact = guard_prompt_module.PromptArtifact(
        harness="codex",
        artifact_id="codex:project:allow-once",
        artifact_name="dangerous tool call",
        artifact_hash="hash-allow-once",
        policy_action="review",
        changed_fields=("runtime_tool_call",),
        provenance_summary="project artifact",
        recommendation="review",
        publisher=None,
        config_path="/repo/.codex/config.toml",
        source_scope="project",
        artifact_type="tool_action_request",
        command="curl https://example.com",
        transport="stdio",
        metadata={},
        current_snapshot=None,
        removed=False,
    )
    evaluation = {
        "artifacts": [
            {
                "artifact_id": artifact.artifact_id,
                "policy_action": "review",
            }
        ]
    }

    resolved = guard_prompt_module.resolve_interactive_decisions(
        store,
        evaluation,
        [artifact],
        workspace=None,
        now="2026-05-27T05:00:00+00:00",
        console=Console(file=io.StringIO(), force_terminal=False),
        input_func=lambda _prompt: "1",
    )

    assert prompt_calls == 1
    assert resolved["blocked"] is False
    artifact_payload = resolved["artifacts"][0]
    assert artifact_payload["policy_action"] == "allow"
    assert artifact_payload["user_override"] == "allow-once"
    receipts = store.list_receipts(limit=5)
    assert any(item.get("user_override") == "allow-once" for item in receipts)


def test_approval_gate_background_remote_policy_sync_fails_closed_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _seed_guard_cloud(store, workspace_id=None)
    monkeypatch.setattr(
        guard_runner_module,
        "_guard_device_metadata",
        lambda _store: ("device-1", "MacBook Pro"),
    )
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(guard_runner_module, "sync_guard_events", lambda _store, auth_context=None: 0)

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

    auth_context = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "demo-token",
        "dpop_key_material": None,
    }
    payload = guard_runner_module.sync_receipts(store, auth_context=auth_context)

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
    opened_urls: list[str] = []
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:5474")
    monkeypatch.setattr(runtime_mcp_module, "load_guard_daemon_auth_token", lambda _guard_home: "secret-token")
    monkeypatch.setattr(runtime_mcp_module.webbrowser, "open", lambda url: opened_urls.append(url) or True)

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
    assert response["error"]["data"]["reviewUrl"].startswith("http://127.0.0.1:5474/requests/")
    assert response["error"]["data"]["reviewUrl"] in response["error"]["message"]
    assert opened_urls == []
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
    assert pending[0]["approval_url"].startswith("http://127.0.0.1:5474/requests/")
    assert "approval_gate_required" in pending[0]["risk_signals"]
    assert store.list_policy_decisions("claude-code") == []


def test_approval_gate_password_material_stays_out_of_public_payloads(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=3600)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    approve_now = "2026-04-11T00:00:31+00:00"
    approve_code = totp_code_at_counter(secret=secret, counter=_counter(approve_now))
    _add_request(store, "req-redaction")
    _approve(
        store,
        "req-redaction",
        gate_input=ApprovalGateInput(password=PASSWORD, totp_code=approve_code, use_cooldown=True),
        now=approve_now,
    )

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
    assert secret not in combined_public
    assert secret not in gate_state_text
    assert approve_code not in combined_public
    assert "approval_password" not in combined_public
    assert "approval_totp_code" not in combined_public
    assert "otpauth://" not in combined_public
