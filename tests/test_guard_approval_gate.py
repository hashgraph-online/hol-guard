"""Approval passwords, scope narrowing and cooldown validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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
from codex_plugin_scanner.guard.config import editable_guard_settings, load_guard_config
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.totp import totp_code_at_counter
from tests.guard_approval_gate_support import (
    PASSWORD,
    WRONG_PASSWORD,
    _add_request,
    _approve,
    _counter,
    _enable_gate,
    _enable_totp,
    _store,
    _trust_local_policy_rows,
)
from tests.guard_approval_gate_support import (
    _clear_agent_env_markers as _clear_agent_env_markers,
)
from tests.guard_approval_gate_support import (
    _default_store_platform as _default_store_platform,
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


def test_approval_gate_artifact_remember_stays_one_time_for_reapproval(
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
    assert store.list_policy_decisions("codex") == []
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
    assert first_retry["action"] == "allow"
    assert second_retry is None
    once_events = store.list_events(limit=20, event_name="approval.once")
    assert any(event["payload"]["request_id"] == "req-remember" for event in once_events)


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
        action="block",
        scope="workspace",
        workspace=None,
        reason="block this project",
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
        == "block"
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
            action="block",
            scope="workspace",
            workspace=str(tmp_path / "workspace-b"),
            reason="tampered project scope",
            now="2026-04-11T00:01:00+00:00",
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
        )


def test_approval_gate_narrows_legacy_broad_allow_for_unscoped_request(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _add_request(store, "req-global")

    resolved = apply_approval_resolution(
        store=store,
        request_id="req-global",
        action="allow",
        scope="global",
        workspace=None,
        reason="too broad",
        now="2026-04-11T00:01:00+00:00",
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
    )

    assert resolved["resolution_scope"] == "artifact"
    assert resolved["scope_warning"] == "legacy_scope_narrowed_to_artifact"


def test_approval_gate_narrows_legacy_workspace_scope_without_bound_workspace(tmp_path: Path) -> None:
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

    resolved = apply_approval_resolution(
        store=store,
        request_id="req-workspace-unsupported",
        action="allow",
        scope="workspace",
        workspace=None,
        reason="too broad",
        now="2026-04-11T00:01:00+00:00",
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
    )

    assert resolved["resolution_scope"] == "artifact"
    assert resolved["scope_warning"] == "legacy_scope_narrowed_to_artifact"


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
