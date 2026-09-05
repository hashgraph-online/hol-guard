"""Temporal persistence regressions for exact OMP shell approvals."""

from __future__ import annotations

import argparse
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals as approvals_module
from codex_plugin_scanner.guard import store_policy as store_policy_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import (
    commands_hook,
    commands_hook_generic,
    commands_hook_runtime_eval,
    commands_hook_runtime_finish,
    commands_hook_runtime_review,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_approval_precedence_generic_stdio import (
    _GENERIC_ARTIFACT_ID,
    _generic_payload,
    _run_generic_hook,
)
from tests.test_guard_manifest_install_firewall import _review_package_evaluation


@pytest.mark.parametrize(
    ("persist_policy", "durable"),
    ((True, True), (None, False)),
    ids=("always-allow", "approve-once"),
)
def test_exact_omp_shell_approval_temporal_reuse_after_store_restart(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    persist_policy: bool | None,
    durable: bool,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = f"rm {workspace / 'obsolete.py'}"
    payload = {
        **_generic_payload(),
        "hook_event_name": "PreToolUse",
        "permission_mode": "ask",
        "tool_name": "bash",
        "tool_input": {"command": command},
    }
    action_envelope = normalize_harness_payload(
        "omp",
        "PreToolUse",
        payload,
        workspace=workspace,
        home_dir=tmp_path,
    )
    assert action_envelope.harness == "omp"
    assert action_envelope.action_type == "shell_command"

    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="require-reapproval",
    )
    resolved_at = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    clock = {"now": resolved_at.isoformat()}
    monkeypatch.setattr(commands_hook_generic, "_now", lambda: clock["now"])
    monkeypatch.setattr(store_policy_module, "_now", lambda: clock["now"])

    first_rc, _first_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
        harness="omp",
        action_envelope=action_envelope,
    )
    assert first_rc == 2
    pending = store.list_approval_requests(limit=10)
    assert len(pending) == 1
    artifact_hash = str(pending[0]["artifact_hash"])
    original_request_id = str(pending[0]["request_id"])
    approvals_module.apply_approval_resolution(
        store=store,
        request_id=original_request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="always allow exact action",
        now=clock["now"],
        persist_policy=persist_policy,
        scope_contract_version=str(pending[0]["scope_contract_version"]),
        scope_contract_digest=str(pending[0]["scope_contract_digest"]),
    )

    restarted = GuardStore(store.guard_home)
    persisted = restarted.list_policy_decisions()
    if durable:
        assert len(persisted) == 1
        assert persisted[0]["source"] == "approval-gate"
        assert persisted[0]["expires_at"] is None
    else:
        assert persisted == []
        before_expiry = restarted.resolve_policy_decision(
            "omp",
            _GENERIC_ARTIFACT_ID,
            artifact_hash=artifact_hash,
            workspace=str(workspace),
            now=(resolved_at + timedelta(minutes=14)).isoformat(),
            consume_one_shot=False,
        )
        assert before_expiry is not None
        assert before_expiry["expires_at"] == (resolved_at + timedelta(minutes=15)).isoformat(timespec="microseconds")

    after_expiry = (resolved_at + timedelta(minutes=16)).isoformat()
    clock["now"] = after_expiry
    if not durable:
        assert (
            restarted.resolve_policy_decision(
                "omp",
                _GENERIC_ARTIFACT_ID,
                artifact_hash=artifact_hash,
                workspace=str(workspace),
                now=after_expiry,
                consume_one_shot=False,
            )
            is None
        )
    retry_rc, retry_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=restarted,
        workspace=workspace,
        harness="omp",
        action_envelope=action_envelope,
    )
    if not durable:
        assert retry_rc == 2
        assert retry_output["decision"] == "deny"
        expired_pending = restarted.list_approval_requests(limit=10)
        assert len(expired_pending) == 1
        assert expired_pending[0]["policy_action"] == "require-reapproval"
    else:
        assert retry_rc == 0, str(retry_output)
        assert retry_output["policy_action"] == "allow"
        assert retry_output["approval_reuse"]["reason_code"] == "approval_reuse_accepted"

    changed_payload = {
        **payload,
        "tool_input": {"command": f"rm {workspace / 'different.py'}"},
    }
    changed_envelope = normalize_harness_payload(
        "omp",
        "PreToolUse",
        changed_payload,
        workspace=workspace,
        home_dir=tmp_path,
    )
    changed_rc, changed_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=changed_payload,
        store=restarted,
        workspace=workspace,
        harness="omp",
        action_envelope=changed_envelope,
    )
    assert changed_rc == 2
    assert changed_output["decision"] == "deny"
    changed_pending = restarted.list_approval_requests(limit=10)
    assert any(
        item["artifact_hash"] != artifact_hash and item["policy_action"] == "require-reapproval"
        for item in changed_pending
    )


@pytest.mark.parametrize(
    ("persist_policy", "durable"),
    ((True, True), (None, False)),
    ids=("always-allow", "approve-once"),
)
def test_exact_omp_npx_approval_survives_store_restart_after_fifteen_minutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persist_policy: bool | None,
    durable: bool,
) -> None:
    """Exercise the NPX package artifact through the OMP hook envelope and a reopened store."""

    monkeypatch.setattr(
        commands_hook_runtime_eval,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    monkeypatch.setattr(
        commands_hook_runtime_review,
        "schedule_guard_daemon_ensure",
        lambda *_args, **_kwargs: "http://127.0.0.1:5474",
    )

    def unavailable_daemon(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("synthetic approval center unavailable")

    monkeypatch.setattr(commands_hook_runtime_review, "load_guard_surface_daemon_client", unavailable_daemon)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        json.dumps(
            {
                "name": "omp-package-fixture",
                "dependencies": {"@modelcontextprotocol/server-memory": "latest"},
            }
        ),
        encoding="utf-8",
    )
    (workspace / "bun.lock").write_text('"@modelcontextprotocol/server-memory": "latest"\n', encoding="utf-8")
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    manager_dir = tmp_path / "manager-bin"
    manager_dir.mkdir()
    manager = manager_dir / "npx"
    manager.write_text("#!/bin/sh\n# synthetic npx manager\n", encoding="utf-8")
    manager.chmod(0o755)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("PATH", str(manager_dir))

    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        # The post-claim public route reloads this isolated home. Keep the
        # injected first-pass config aligned with that reload's default.
        default_action="warn",
        approval_wait_timeout_seconds=0,
    )
    command = "npx -y @modelcontextprotocol/server-memory"
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "permission_mode": "ask",
        "tool_name": "bash",
        "tool_input": {"command": command},
        "source_scope": "project",
    }
    envelope = normalize_harness_payload(
        "omp",
        "PreToolUse",
        payload,
        workspace=workspace,
        home_dir=home_dir,
    )
    assert envelope.action_type == "shell_command"
    assert envelope.package_manager == "npx"
    assert envelope.package_name == "@modelcontextprotocol/server-memory"

    resolved_at = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    clock = {"now": resolved_at.isoformat()}
    for module in (
        commands_hook_runtime_eval,
        commands_hook_runtime_finish,
        commands_hook_runtime_review,
        store_policy_module,
    ):
        monkeypatch.setattr(module, "_now", lambda clock=clock: clock["now"])
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace, guard_home=guard_home)
    args = argparse.Namespace(
        artifact_id=None,
        artifact_name=None,
        event_file=None,
        harness="omp",
        json=True,
        policy_action=None,
        runtime_harness=None,
    )

    def run_hook(current_store: GuardStore, current_payload: dict[str, object]) -> int:
        return commands_hook._run_guard_hook_command(
            args,
            guard_home=guard_home,
            workspace=workspace,
            context=context,
            store=current_store,
            config=config,
            input_text=json.dumps(current_payload),
            output_stream=io.StringIO(),
        )

    first_rc = run_hook(store, payload)
    assert first_rc == 2
    pending = store.list_approval_requests(limit=10)
    assert len(pending) == 1
    request = pending[0]
    assert request["artifact_type"] == "package_request"
    queued_envelope = request["action_envelope_json"]
    assert isinstance(queued_envelope, dict)
    assert queued_envelope["action_type"] == "shell_command"
    assert queued_envelope["package_manager"] == "npx"
    assert queued_envelope["package_name"] == "@modelcontextprotocol/server-memory"
    artifact_id = str(request["artifact_id"])
    artifact_hash = str(request["artifact_hash"])
    resolution = approvals_module.apply_approval_resolution(
        store=store,
        request_id=str(request["request_id"]),
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed exact OMP NPX package action",
        now=clock["now"],
        persist_policy=persist_policy,
        scope_contract_version=str(request["scope_contract_version"]),
        scope_contract_digest=str(request["scope_contract_digest"]),
    )
    assert resolution["status"] == "resolved"

    restarted = GuardStore(guard_home)
    if durable:
        policies = restarted.list_policy_decisions("omp")
        assert len(policies) == 1
        assert policies[0]["source"] == "approval-gate"
        assert policies[0]["expires_at"] is None
    else:
        assert restarted.list_policy_decisions("omp") == []
        before_expiry = restarted.resolve_policy_decision(
            "omp",
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=None,
            now=(resolved_at + timedelta(minutes=14)).isoformat(),
            consume_one_shot=False,
        )
        assert before_expiry is not None
        assert before_expiry["expires_at"] == (resolved_at + timedelta(minutes=15)).isoformat(timespec="microseconds")

    clock["now"] = (resolved_at + timedelta(minutes=16)).isoformat()
    if not durable:
        assert (
            restarted.resolve_policy_decision(
                "omp",
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=None,
                now=clock["now"],
                consume_one_shot=False,
            )
            is None
        )
    retry_rc = run_hook(restarted, payload)
    if durable:
        assert retry_rc == 0
        assert restarted.list_receipts(limit=1)[0]["policy_decision"] == "allow"
    else:
        assert retry_rc == 2
        assert restarted.list_receipts(limit=1)[0]["policy_decision"] == "review"

    changed_payload = {
        **payload,
        "tool_input": {"command": "npx -y @modelcontextprotocol/server-filesystem"},
    }
    changed_envelope = normalize_harness_payload(
        "omp",
        "PreToolUse",
        changed_payload,
        workspace=workspace,
        home_dir=home_dir,
    )
    assert changed_envelope.package_name == "@modelcontextprotocol/server-filesystem"
    changed_rc = run_hook(restarted, changed_payload)
    assert changed_rc == 2
    changed_pending = restarted.list_approval_requests(limit=10)
    assert any(
        item["artifact_hash"] != artifact_hash
        and item["artifact_type"] == "package_request"
        and item["policy_action"] == "review"
        for item in changed_pending
    )
