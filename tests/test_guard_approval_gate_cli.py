"""Approval CLI proof prompts, agent refusal and password commands."""

from __future__ import annotations

import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, public_config
from codex_plugin_scanner.guard.cli.approval_commands import run_approval_command
from codex_plugin_scanner.guard.cli.commands import run_guard_command
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.totp import TotpSecretStore, totp_code_at_counter
from tests.guard_approval_gate_support import (
    PASSWORD,
    _add_request,
    _approve,
    _counter,
    _enable_gate,
    _enable_totp,
    _store,
)
from tests.guard_approval_gate_support import (
    _clear_agent_env_markers as _clear_agent_env_markers,
)
from tests.guard_approval_gate_support import (
    _default_store_platform as _default_store_platform,
)


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


def test_approval_gate_cli_policy_write_requires_totp_when_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    now = datetime.now(timezone.utc).isoformat()
    code = totp_code_at_counter(secret=secret, counter=_counter(now))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    responses = iter(("000000", code))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_gate_prompt.getpass.getpass",
        lambda _prompt: next(responses),
    )
    args = SimpleNamespace(
        guard_command="allow",
        guard_home=str(store.guard_home),
        home=str(tmp_path / "home"),
        workspace=str(workspace),
        harness="codex",
        scope="artifact",
        artifact_id="codex:project:two-factor-cli",
        policy_action="allow",
        publisher=None,
        reason=None,
        owner=None,
        expires_in_hours=None,
        json=True,
        cisco_mode="off",
    )

    rejected = run_guard_command(args, output_stream=io.StringIO())
    accepted = run_guard_command(args, output_stream=io.StringIO())

    assert rejected == 4
    assert accepted == 0
    policy = GuardStore(store.guard_home).list_policy_decisions("codex")[0]
    assert policy["artifact_id"] == "codex:project:two-factor-cli"


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
