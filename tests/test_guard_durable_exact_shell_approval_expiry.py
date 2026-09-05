"""Temporal persistence regressions for exact OMP shell approvals."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals as approvals_module
from codex_plugin_scanner.guard import store_policy as store_policy_module
from codex_plugin_scanner.guard.cli import commands_hook_generic
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_approval_precedence_generic_stdio import (
    _GENERIC_ARTIFACT_ID,
    _generic_payload,
    _run_generic_hook,
)


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
