# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownLambdaType=false, reportUnusedCallResult=false

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

import codex_plugin_scanner.guard.approvals as approvals_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.commands_hook_github_workflow import claimed_approval_request_id
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact
from codex_plugin_scanner.guard.runtime.approval_context import approval_context_tokens_validation_reason
from codex_plugin_scanner.guard.runtime.command_decision_adapter import effect_decision_to_dict
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.github_capability_interaction import GITHUB_MAINTENANCE_ACTION_CLASS
from codex_plugin_scanner.guard.runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from codex_plugin_scanner.guard.runtime.github_workflow_runtime import (
    _capability_id,
    claim_resolved_github_workflow_authorization,
    issue_resolved_github_workflow_capability,
    resolved_github_workflow_capability_preflight,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import canonical_framed_payload, format_utc_timestamp
from tests.test_guard_github_workflow_runtime import _COMMAND, _descriptor, _seed_resolved_request

_ISSUED = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def fixed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GuardStore,
        "_policy_integrity_secret_material",
        lambda _store, *, create: (b"r" * 32, "guard-policy-integrity-key:github-runtime-eval-test"),
    )
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: format_utc_timestamp(_ISSUED))


def _descriptor_for_workspace(workspace: Path):
    descriptor = _descriptor()
    return replace(
        descriptor,
        binding_context=replace(
            descriptor.binding_context,
            workspace_sha256=hashlib.sha256(
                canonical_framed_payload("github-workspace", str(workspace.resolve()))
            ).hexdigest(),
        ),
    )


def test_approval_resolution_implicit_timestamp_issues_claimable_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    descriptor = _descriptor()
    _ = _seed_resolved_request(store, descriptor, resolved=False)
    monkeypatch.setattr(approvals_module, "_now", lambda: _ISSUED.isoformat())

    resolved = apply_approval_resolution(
        store=store,
        request_id="request-github-1",
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed exact maintenance task",
    )

    assert resolved["resolved_at"] == _ISSUED.isoformat()
    authorization = claim_resolved_github_workflow_authorization(store, "request-github-1", descriptor)
    assert authorization is not None
    signed = store.lookup_workflow_capability(_capability_id("request-github-1"))
    assert signed is not None
    assert signed.claim.issued_at == format_utc_timestamp(_ISSUED)


def test_claimed_workflow_authorization_preserves_command_floor_approval_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_plugin_scanner.guard.cli.commands_hook_github_workflow as workflow_hook
    import codex_plugin_scanner.guard.cli.commands_support_runtime_policy as runtime_policy

    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    descriptor = _descriptor()
    preauthorization = evaluate_command(
        _COMMAND,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:github",
        name="Bash GitHub maintenance",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=_COMMAND,
        metadata={
            "action_class": GITHUB_MAINTENANCE_ACTION_CLASS,
            "command_action_floor": preauthorization.decision_plane.action,
            "command_decision_plane": effect_decision_to_dict(preauthorization.decision_plane),
        },
    )
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
        risk_actions={"destructive_shell": "allow", "network_egress": "allow"},
    )
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=guard_home)
    monkeypatch.setattr(workflow_hook, "_runtime_github_workflow_descriptor", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(runtime_policy, "_runtime_hook_executable_identity", lambda *_args, **_kwargs: {"stable": True})

    def evaluate(*, claimed_hash: str | None = None, request_id: str | None = None):
        return _evaluate_runtime_artifact_hook(
            args,
            action_envelope=None,
            config=config,
            context=context,
            data_flow_signals=(),
            guard_home=guard_home,
            payload={"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            runtime_artifact=artifact,
            runtime_workspace=workspace,
            store=store,
            _claimed_saved_allow_hash=claimed_hash,
            _claimed_approval_request_id=request_id,
            _claim_saved_approval=claimed_hash is None,
        )

    initial = evaluate()
    assert not isinstance(initial, int)
    assert initial.policy_action == "review"
    request = _seed_resolved_request(store, descriptor)
    assert issue_resolved_github_workflow_capability(store, request, resolved_at=format_utc_timestamp(_ISSUED))

    result = evaluate(claimed_hash=initial.runtime_artifact_hash, request_id="request-github-1")

    assert not isinstance(result, int)
    assert (
        approval_context_tokens_validation_reason(initial.runtime_artifact_hash, result.runtime_artifact_hash) is None
    )
    assert result.policy_action == "allow", result.response_payload.get("approval_reuse")
    reuse = cast(Mapping[str, object], result.response_payload["approval_reuse"])
    assert reuse["reason_code"] == "approval_reuse_current_action_not_review"
    assert reuse["status"] == "not-applicable"


def test_exact_workflow_capability_satisfies_require_reapproval_on_normal_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_plugin_scanner.guard.cli.commands_hook_github_workflow as workflow_hook
    import codex_plugin_scanner.guard.cli.commands_hook_runtime_eval as runtime_eval
    import codex_plugin_scanner.guard.cli.commands_support_runtime_policy as runtime_policy
    import codex_plugin_scanner.guard.store_policy as store_policy

    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    descriptor = _descriptor_for_workspace(workspace)
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:github",
        name="Bash GitHub maintenance",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=_COMMAND,
        metadata={
            "action_class": GITHUB_MAINTENANCE_ACTION_CLASS,
            "raw_command_text": _COMMAND,
        },
    )
    config = GuardConfig(guard_home=guard_home, workspace=workspace, default_action="require-reapproval")
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=guard_home)
    monkeypatch.setattr(workflow_hook, "_runtime_github_workflow_descriptor", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(runtime_eval, "_now", lambda: format_utc_timestamp(_ISSUED))
    monkeypatch.setattr(runtime_policy, "_runtime_hook_executable_identity", lambda *_args, **_kwargs: {"stable": True})
    monkeypatch.setattr(store_policy, "_now", lambda: format_utc_timestamp(_ISSUED))

    def evaluate():
        return _evaluate_runtime_artifact_hook(
            args,
            action_envelope=None,
            config=config,
            context=context,
            data_flow_signals=(),
            guard_home=guard_home,
            payload={"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            runtime_artifact=artifact,
            runtime_workspace=workspace,
            store=store,
        )

    initial = evaluate()
    assert not isinstance(initial, int)
    assert initial.policy_action == "require-reapproval"
    request = GuardApprovalRequest(
        request_id="request-github-1",
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        artifact_hash=initial.runtime_artifact_hash,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        workspace=str(workspace),
        artifact_type=artifact.artifact_type,
        review_command="hol-guard approvals approve request-github-1",
        approval_url="http://127.0.0.1/requests/request-github-1",
        scanner_evidence=(
            {
                "source": "github_workflow_approval_record",
                "record": GitHubWorkflowApprovalRecord.from_descriptor(descriptor).to_dict(),
            },
        ),
        raw_command_text=_COMMAND,
    )
    store.add_approval_request(request, format_utc_timestamp(_ISSUED))
    session = store.upsert_guard_session(
        session_id="session-github-1",
        harness=artifact.harness,
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-hook",
        client_title=None,
        client_version=None,
        workspace=str(workspace),
        capabilities=["approval-resolution"],
        now=format_utc_timestamp(_ISSUED),
    )
    _ = store.upsert_guard_operation(
        operation_id="operation-github-1",
        session_id=str(session["session_id"]),
        harness=artifact.harness,
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request.request_id],
        resume_token="resume-token",
        metadata={"command_text": _COMMAND, "hook_event_name": "PreToolUse", "workspace": str(workspace)},
        now=format_utc_timestamp(_ISSUED),
    )
    _ = apply_approval_resolution(
        store=store,
        request_id=request.request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed exact maintenance task",
        now=format_utc_timestamp(_ISSUED),
    )
    assert resolved_github_workflow_capability_preflight(store, "request-github-1", descriptor)
    lookup = store.resolve_policy_decision_lookup(
        artifact.harness,
        artifact.artifact_id,
        artifact_hash=initial.runtime_artifact_hash,
        workspace=str(workspace),
        publisher=None,
        now=format_utc_timestamp(_ISSUED),
        consume_one_shot=False,
    )
    decision = cast(Mapping[str, object], lookup["decision"])
    assert claimed_approval_request_id(decision) == "request-github-1"

    result = evaluate()

    assert not isinstance(result, int)
    assert result.runtime_artifact_hash == initial.runtime_artifact_hash
    reuse = cast(Mapping[str, object], result.response_payload["approval_reuse"])
    assert reuse["reason_code"] == "approval_reuse_accepted", reuse
    assert result.policy_action == "allow"
    composition = cast(Mapping[str, object], result.response_payload["policy_composition"])
    assert composition["approval_reuse_source"] == "claimed_github_workflow_capability"
    assert len(store.list_events(event_name="workflow_capability.claimed")) == 1

    replay = evaluate()
    assert not isinstance(replay, int)
    assert replay.policy_action == "require-reapproval"
