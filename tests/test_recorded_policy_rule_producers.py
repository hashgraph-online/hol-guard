"""Real selected-rule provenance survives each supported review producer."""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from codex_plugin_scanner.guard.cli.commands_hook_runtime_state import (
    RuntimeArtifactHookState,
    set_runtime_artifact_hook_final_action,
)
from codex_plugin_scanner.guard.cli.protect_approvals import _protect_approval_item
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    _package_evaluation_with_current_policy_action,
    apply_stored_package_policy_override,
)
from codex_plugin_scanner.guard.mcp_tool_calls import evaluate_tool_call, resolve_tool_call_policy_action
from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy, _tool_decision_after_runtime_allow
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import PackageRequestEvaluation, SupplyChainUserCopy
from tests.test_canonical_policy_row_authority import _ARTIFACT, _NOW, _activated_store
from tests.test_guard_consumer_approval_precedence import _artifact, _detection
from tests.test_guard_protect_approval_decision import _response
from tests.test_guard_temporary_mcp_approvals import _artifact as _mcp_artifact

_IDENTITY = {"policyId": "synthetic.policy", "ruleId": "synthetic.rule", "policyVersion": "8"}


def _package_evaluation() -> PackageRequestEvaluation:
    return PackageRequestEvaluation(
        decision="allow",
        policy_action="allow",
        enforcement="local",
        entitlement_state="free",
        cache_status="miss",
        package_intent_hash="synthetic-hash",
        policy_version="local:none",
        bundle_version=None,
        workspace_fingerprint=None,
        reasons=(),
        packages=(),
        risk_summary="Synthetic request",
        user_copy=SupplyChainUserCopy("Synthetic request", "Synthetic request", None, None, "Synthetic request"),
    )


def test_actual_package_lookup_preserves_provenance_without_caching_it(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="review")
    artifact = replace(_artifact(tmp_path), artifact_id=_ARTIFACT, artifact_type="package_request")
    evaluation = apply_stored_package_policy_override(
        _package_evaluation(),
        store=store,
        artifact=artifact,
        artifact_hash="synthetic-hash",
        workspace_dir=tmp_path / "workspace",
        now=_NOW,
        current_action="allow",
        claim_saved_approval=False,
    )
    assert evaluation.policy_action == "review"
    assert evaluation.policy_rule_identity.to_dict() == _IDENTITY
    assert not any(key in evaluation.to_cache_dict() for key in _IDENTITY)
    assert {key: evaluation.to_dict()[key] for key in _IDENTITY} == _IDENTITY
    response = _response(verdict_action="review")
    response["supply_chain_evaluation"] = evaluation.to_dict()
    item = _protect_approval_item(response, workspace=tmp_path, artifact=artifact)
    assert item is not None
    assert {key: item["decision_v2_json"][key] for key in _IDENTITY} == _IDENTITY
    proxy = RuntimeMcpGuardProxy._package_decision_v2(evaluation, "review")
    assert {key: proxy[key] for key in _IDENTITY} == _IDENTITY
    stronger = _package_evaluation_with_current_policy_action(evaluation, current_action="block")
    assert stronger.policy_rule_identity is None
    assert "policyId" not in RuntimeMcpGuardProxy._package_decision_v2(evaluation, "block")


def test_real_mcp_winner_reaches_queue_and_runtime_override_clears_provenance(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="review")
    artifact = replace(_mcp_artifact(tool_name="get_status"), artifact_id=_ARTIFACT)
    config = GuardConfig(guard_home=store.guard_home, workspace=tmp_path, default_action="allow")
    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash="synthetic-hash",
        arguments={},
        claim_saved_approval=False,
    )
    assert decision.current_action == "allow" and decision.action == "review"
    assert decision.policy_rule_identity is not None and decision.policy_rule_identity.to_dict() == _IDENTITY
    proxy = RuntimeMcpGuardProxy(
        harness="codex",
        server_name="synthetic-server",
        command=[],
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=store.guard_home),
        store=store,
        config=config,
        source_scope="project",
        config_path="synthetic.json",
    )
    item = proxy._build_artifact_payload(
        artifact,
        "synthetic-hash",
        "get_status",
        {"arguments": {}},
        decision.signals,
        policy_action=resolve_tool_call_policy_action(decision),
        approval_decision=decision,
    )
    queued = queue_blocked_approvals(
        detection=_detection(artifact),
        evaluation={"artifacts": [item]},
        store=store,
        approval_center_url="http://localhost",
        now=_NOW,
        notify=False,
    )
    assert len(queued) == 1
    request = store.get_approval_request(queued[0]["request_id"])
    assert request is not None
    assert {key: request["decision_v2_json"][key] for key in _IDENTITY} == _IDENTITY
    assert _tool_decision_after_runtime_allow(decision, source="native-approved").policy_rule_identity is None
    stronger = evaluate_tool_call(
        store=store,
        config=replace(config, default_action="block"),
        artifact=artifact,
        artifact_hash="synthetic-hash",
        arguments={},
        claim_saved_approval=False,
    )
    assert stronger.action == "block" and stronger.policy_rule_identity is None


def test_real_runtime_hook_projection_keeps_selected_rule(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="review")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = replace(
        _artifact(tmp_path),
        artifact_id=_ARTIFACT,
        command="printf",
        args=("synthetic",),
        metadata={"guard_default_action": "allow"},
    )
    config = GuardConfig(
        guard_home=store.guard_home, workspace=workspace, default_action="allow", security_level="custom"
    )
    state = _evaluate_runtime_artifact_hook(
        argparse.Namespace(harness="codex"),
        action_envelope=None,
        config=config,
        context=HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=store.guard_home),
        data_flow_signals=(),
        guard_home=store.guard_home,
        payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "printf synthetic"}},
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
        _claim_saved_approval=False,
    )
    assert isinstance(state, RuntimeArtifactHookState)
    assert state.policy_action == "review"
    assert {key: state.decision_v2_payload.get(key) for key in _IDENTITY} == _IDENTITY
    set_runtime_artifact_hook_final_action(state, "review")
    assert {key: state.decision_v2_payload.get(key) for key in _IDENTITY} == _IDENTITY
    set_runtime_artifact_hook_final_action(state, "allow", approval_source="browser")
    assert "policyId" not in state.decision_v2_payload and "ruleId" not in state.decision_v2_payload
