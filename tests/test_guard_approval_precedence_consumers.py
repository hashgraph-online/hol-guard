"""Cross-consumer regressions for saved-approval precedence (P44)."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
import codex_plugin_scanner.guard.runtime.supply_chain_package_eval as package_eval_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash
from codex_plugin_scanner.guard.local_supply_chain import (
    apply_stored_package_policy_override,
    package_request_policy_hash,
)
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    build_tool_call_hash,
    claim_deferred_tool_call_approval,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.package_execution_context import build_package_execution_context
from codex_plugin_scanner.guard.proxy._env import _build_scrubbed_env
from codex_plugin_scanner.guard.proxy.stdio import StdioGuardProxy, build_sensitive_read_approval_hash
from codex_plugin_scanner.guard.runtime.approval_context import (
    build_approval_context_token,
    build_configured_environment_hash,
    build_runtime_launch_identity,
)
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.package_intent import PackageIntent, build_package_request_artifact
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_file_read_request_artifact,
    extract_sensitive_file_read_request,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)
from codex_plugin_scanner.guard.store import GuardStore

_EXACT_PACKAGE_CONTEXT_TOKEN = build_approval_context_token(
    identity={"package": "guard-proof"},
    content={"digest": "package-content"},
    capabilities={"operation": "install"},
    policy={"version": "policy-v2"},
    sandbox={"analysis": "off"},
)


def _package_evaluation(action: GuardAction) -> PackageRequestEvaluation:
    decision = "block" if action == "block" else "ask" if action not in {"allow", "warn"} else action
    return PackageRequestEvaluation(
        decision=decision,
        policy_action=action,
        enforcement="local",
        entitlement_state="active",
        cache_status="fresh",
        package_intent_hash="intent-hash",
        policy_version="policy-v2",
        bundle_version="bundle-v2",
        workspace_fingerprint="workspace-v2",
        reasons=({"code": "current_package_result", "message": "Current package evaluation."},),
        packages=({"name": "guard-proof", "decision": decision},),
        risk_summary="Current package evaluation.",
        user_copy=SupplyChainUserCopy(
            title="Current package result",
            summary="Current package evaluation.",
            next_step=None,
            dashboard_url=None,
            harness_message="Current package evaluation.",
        ),
    )


@pytest.mark.parametrize(
    "action",
    ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block"),
)
def test_package_protect_receipt_action_preserves_authoritative_action(action: GuardAction) -> None:
    assert local_supply_chain_module._protect_action_for_policy_action(action) == action


def _package_artifact(workspace: Path) -> GuardArtifact:
    intent = PackageIntent(
        package_manager="npm",
        intent_kind="install",
        command_tokens=("npm", "install", "guard-proof"),
        redacted_command="npm install guard-proof",
        targets=(),
        manifest_paths=(),
        lockfile_paths=(),
    )
    return build_package_request_artifact(
        "guard-cli",
        intent,
        config_path=str(workspace / "package.json"),
        source_scope="project",
    )


class _SavedPackagePolicyStore:
    def __init__(self, action: GuardAction) -> None:
        self.action = action
        self.claimed = False

    def resolve_policy_decision_lookup(self, *_args: object, **kwargs: object) -> dict[str, object]:
        assert kwargs["consume_one_shot"] is False
        return {
            "decision": {
                "action": self.action,
                "scope": "artifact",
                "source": "approval-gate",
                "decision_id": 1,
                "artifact_hash": _EXACT_PACKAGE_CONTEXT_TOKEN,
            },
            "ignored_local_integrity": None,
            "trust_status": {},
        }

    def claim_approval_reuse_decision(self, _decision: object, *, now: str | None = None) -> bool:
        assert now == "2026-07-17T00:00:00Z"
        self.claimed = True
        return True


@pytest.mark.parametrize("current_action", ["require-reapproval", "sandbox-required", "block"])
def test_package_saved_allow_never_lowers_stronger_current_action(
    tmp_path: Path,
    current_action: GuardAction,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _package_artifact(workspace)
    context = build_package_execution_context(workspace_dir=workspace, artifact=artifact, executable="npm")
    store = _SavedPackagePolicyStore("allow")

    result = apply_stored_package_policy_override(
        _package_evaluation(current_action),
        store=store,
        artifact=artifact,
        artifact_hash=_EXACT_PACKAGE_CONTEXT_TOKEN,
        workspace_dir=workspace,
        now="2026-07-17T00:00:00Z",
        execution_context=context,
    )

    assert result.policy_action == current_action
    assert result.reasons[0]["code"] in {
        "approval_reuse_reapproval_required",
        "approval_reuse_sandbox_required",
        "approval_reuse_current_block",
    }
    assert store.claimed is False


def test_package_exact_saved_allow_satisfies_only_current_review(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _package_artifact(workspace)
    context = build_package_execution_context(workspace_dir=workspace, artifact=artifact, executable="npm")
    store = _SavedPackagePolicyStore("allow")

    result = apply_stored_package_policy_override(
        _package_evaluation("review"),
        store=store,
        artifact=artifact,
        artifact_hash=_EXACT_PACKAGE_CONTEXT_TOKEN,
        workspace_dir=workspace,
        now="2026-07-17T00:00:00Z",
        execution_context=context,
    )

    assert result.policy_action == "allow"
    assert result.reasons[0]["code"] == "saved_package_approval"
    assert store.claimed is True


def test_package_reuse_uses_post_scanner_current_action_before_claim(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _package_artifact(workspace)
    context = build_package_execution_context(workspace_dir=workspace, artifact=artifact, executable="npm")
    store = _SavedPackagePolicyStore("allow")

    result = apply_stored_package_policy_override(
        _package_evaluation("review"),
        store=store,
        artifact=artifact,
        artifact_hash=_EXACT_PACKAGE_CONTEXT_TOKEN,
        workspace_dir=workspace,
        now="2026-07-17T00:00:00Z",
        execution_context=context,
        current_action="block",
    )

    assert result.policy_action == "block"
    assert result.reasons[0]["code"] == "approval_reuse_current_block"
    assert store.claimed is False


def test_package_weaker_supplied_current_action_cannot_erase_package_block(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _package_artifact(workspace)
    context = build_package_execution_context(workspace_dir=workspace, artifact=artifact, executable="npm")
    store = _SavedPackagePolicyStore("allow")

    result = apply_stored_package_policy_override(
        _package_evaluation("block"),
        store=store,
        artifact=artifact,
        artifact_hash=_EXACT_PACKAGE_CONTEXT_TOKEN,
        workspace_dir=workspace,
        now="2026-07-17T00:00:00Z",
        execution_context=context,
        current_action="review",
    )

    assert result.policy_action == "block"
    assert result.reasons[0]["code"] == "approval_reuse_current_block"
    assert store.claimed is False


def test_package_local_saved_allow_without_exact_hash_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _package_artifact(workspace)
    context = build_package_execution_context(workspace_dir=workspace, artifact=artifact, executable="npm")
    store = _SavedPackagePolicyStore("allow")
    original_lookup = store.resolve_policy_decision_lookup

    def lookup_without_hash(*args: object, **kwargs: object) -> dict[str, object]:
        result = original_lookup(*args, **kwargs)
        decision = result["decision"]
        assert isinstance(decision, dict)
        decision.pop("artifact_hash")
        return result

    store.resolve_policy_decision_lookup = lookup_without_hash  # type: ignore[method-assign]
    result = apply_stored_package_policy_override(
        _package_evaluation("review"),
        store=store,
        artifact=artifact,
        artifact_hash=_EXACT_PACKAGE_CONTEXT_TOKEN,
        workspace_dir=workspace,
        now="2026-07-17T00:00:00Z",
        execution_context=context,
    )

    assert result.policy_action == "review"
    assert result.reasons[0]["code"] == "approval_reuse_content_changed"
    assert store.claimed is False


def test_package_equal_legacy_hash_cannot_prove_complete_approval_context(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _package_artifact(workspace)
    context = build_package_execution_context(workspace_dir=workspace, artifact=artifact, executable="npm")
    store = _SavedPackagePolicyStore("allow")
    original_lookup = store.resolve_policy_decision_lookup

    def lookup_with_legacy_hash(*args: object, **kwargs: object) -> dict[str, object]:
        result = original_lookup(*args, **kwargs)
        decision = result["decision"]
        assert isinstance(decision, dict)
        decision["artifact_hash"] = "equal-legacy-package-hash"
        return result

    store.resolve_policy_decision_lookup = lookup_with_legacy_hash  # type: ignore[method-assign]
    result = apply_stored_package_policy_override(
        _package_evaluation("review"),
        store=store,
        artifact=artifact,
        artifact_hash="equal-legacy-package-hash",
        workspace_dir=workspace,
        now="2026-07-17T00:00:00Z",
        execution_context=context,
    )

    assert result.policy_action == "review"
    assert result.reasons[0]["code"] == "approval_reuse_content_changed"
    assert store.claimed is False


@pytest.mark.parametrize(
    ("changed_dimension", "expected_reason"),
    [
        ("policy", "approval_reuse_policy_changed"),
        ("sandbox", "approval_reuse_sandbox_changed"),
    ],
)
def test_package_policy_and_sandbox_context_changes_invalidate_review_approval(
    tmp_path: Path,
    changed_dimension: str,
    expected_reason: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _package_artifact(workspace)
    context = build_package_execution_context(workspace_dir=workspace, artifact=artifact, executable="npm")
    base_evaluation = _package_evaluation("review")
    current_evaluation = (
        replace(base_evaluation, policy_version="policy-v3") if changed_dimension == "policy" else base_evaluation
    )
    base_config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace, sandbox_analysis="off")
    current_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        sandbox_analysis="strict" if changed_dimension == "sandbox" else "off",
    )
    old_digest = package_request_policy_hash(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        evaluation=base_evaluation,
        execution_context=context,
        config=base_config,
    )
    store = GuardStore(tmp_path / "guard-home")
    new_digest = package_request_policy_hash(
        artifact=artifact,
        store=store,
        workspace_dir=workspace,
        evaluation=current_evaluation,
        execution_context=context,
        config=current_config,
    )
    assert old_digest != new_digest
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=old_digest,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    result = apply_stored_package_policy_override(
        current_evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=new_digest,
        workspace_dir=workspace,
        now="2026-07-17T00:00:00Z",
        execution_context=context,
    )

    assert result.policy_action == "review"
    assert result.reasons[0]["code"] == expected_reason


@pytest.mark.parametrize(("saved_action", "expected"), [("allow", False), ("block", True)])
def test_package_cache_error_probe_is_non_consuming_and_never_authorizes_saved_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    saved_action: GuardAction,
    expected: bool,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _package_artifact(workspace)

    class ProbeStore:
        def resolve_policy_decision_lookup(self, *_args: object, **kwargs: object) -> dict[str, object]:
            assert kwargs["consume_one_shot"] is False
            return {
                "decision": {
                    "action": saved_action,
                    "artifact_hash": "exact-v1-token",
                    "scope": "artifact",
                    "source": "approval-gate",
                },
                "ignored_local_integrity": None,
                "trust_status": {},
            }

    monkeypatch.setattr(
        local_supply_chain_module,
        "package_request_policy_hash",
        lambda **_kwargs: "exact-v1-token",
    )

    result = package_eval_module._cached_cloud_validation_error_has_saved_policy(
        store=ProbeStore(),
        artifact=artifact,
        evaluation=_package_evaluation("block"),
        workspace_dir=workspace,
        now="2026-07-17T00:00:00Z",
    )

    assert result is expected


def _dangerous_tool_artifact() -> GuardArtifact:
    return build_tool_call_artifact(
        harness="codex",
        server_name="global-shell",
        tool_name="shell_exec",
        source_scope="global",
        config_path="/shared/.mcp.json",
        transport="stdio",
    )


def test_tool_call_local_saved_allow_without_exact_hash_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _dangerous_tool_artifact()
    arguments = {"command": "rm relative-target"}
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace, mode="prompt")
    digest = build_tool_call_hash(artifact, arguments, workspace=workspace, config=config)
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=None,
            reason="legacy unbound allow",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=digest,
        arguments=arguments,
    )

    assert decision.action == "review"
    assert decision.approval_reuse_reason_code == "approval_reuse_content_changed"


def test_tool_call_equal_legacy_hash_cannot_prove_complete_approval_context(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _dangerous_tool_artifact()
    arguments = {"command": "rm relative-target"}
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace, mode="prompt")
    legacy_digest = build_tool_call_hash(artifact, arguments, workspace=workspace)
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=legacy_digest,
            reason="legacy digest-only allow",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=legacy_digest,
        arguments=arguments,
    )

    assert decision.action == "review"
    assert decision.approval_reuse_reason_code == "approval_reuse_content_changed"


def test_tool_call_approval_hash_is_bound_to_workspace_and_reuses_unchanged_workspace(tmp_path: Path) -> None:
    workspace_a = tmp_path / "workspace-a"
    workspace_b = tmp_path / "workspace-b"
    workspace_a.mkdir()
    workspace_b.mkdir()
    artifact = _dangerous_tool_artifact()
    arguments = {"command": "rm relative-target"}
    config_a = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace_a, mode="prompt")
    config_b = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace_b, mode="prompt")
    digest_a = build_tool_call_hash(artifact, arguments, workspace=workspace_a, config=config_a)
    digest_b = build_tool_call_hash(artifact, arguments, workspace=workspace_b, config=config_b)
    assert digest_a != digest_b
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=digest_a,
            reason="workspace A exact approval",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    unchanged = evaluate_tool_call(
        store=store,
        config=config_a,
        artifact=artifact,
        artifact_hash=digest_a,
        arguments=arguments,
    )
    changed_workspace = evaluate_tool_call(
        store=store,
        config=config_b,
        artifact=artifact,
        artifact_hash=digest_b,
        arguments=arguments,
    )

    assert unchanged.action == "allow"
    assert unchanged.approval_reuse_reason_code == "approval_reuse_accepted"
    assert changed_workspace.action == "review"


def test_tool_call_rebuilds_current_authority_after_atomic_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _dangerous_tool_artifact()
    arguments = {"command": "rm relative-target"}
    artifact_actions: dict[str, GuardAction] = {}
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        mode="prompt",
        artifact_actions=artifact_actions,
    )
    digest = build_tool_call_hash(artifact, arguments, workspace=workspace, config=config)
    store = GuardStore(tmp_path / "guard-home")
    approval_id = store.record_local_once_approval(
        request_id="tool-call-post-claim-policy-change",
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=digest,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    original_claim = store.claim_approval_reuse_decision

    def claim_then_block(decision: object, *, now: str | None = None) -> bool:
        claimed = original_claim(decision, now=now)
        if claimed:
            artifact_actions[artifact.artifact_id] = "block"
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_block)

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=digest,
        arguments=arguments,
    )

    assert decision.action == "block"
    assert decision.current_action == "block"
    assert decision.approval_reuse_status == "rejected"
    assert decision.approval_reuse_reason_code == ("approval_reuse_context_changed_after_claim")
    assert (
        store.resolve_policy_decision(
            artifact.harness,
            artifact.artifact_id,
            digest,
            str(workspace),
            consume_one_shot=False,
        )
        is None
    )


def test_tool_call_missing_post_claim_authority_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _dangerous_tool_artifact()
    arguments = {"command": "rm relative-target"}
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        mode="prompt",
    )
    digest = build_tool_call_hash(artifact, arguments, workspace=workspace, config=config)
    store = GuardStore(tmp_path / "guard-home")
    approval_id = store.record_local_once_approval(
        request_id="tool-call-missing-post-claim-authority",
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=digest,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=digest,
        arguments=arguments,
        fresh_authority_provider=lambda: None,
    )

    assert decision.action == "require-reapproval"
    assert decision.approval_reuse_status == "rejected"
    assert decision.approval_reuse_reason_code == ("approval_reuse_context_changed_after_claim")


def test_tool_call_retained_policy_deleted_after_claim_requires_reapproval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _dangerous_tool_artifact()
    arguments = {"command": "rm retained-target"}
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        mode="prompt",
    )
    digest = build_tool_call_hash(artifact, arguments, workspace=workspace, config=config)
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=digest,
            workspace=str(workspace),
            publisher=artifact.publisher,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    original_claim = store.claim_approval_reuse_decision

    def claim_then_delete_retained_row(decision, *, now: str | None = None) -> bool:
        assert store.approval_reuse_claim_disposition(decision) == "retained"
        claimed = original_claim(decision, now=now)
        if claimed:
            decision_id = decision.get("decision_id")
            assert isinstance(decision_id, int) and not isinstance(decision_id, bool)
            with store._connect() as connection:
                connection.execute("delete from policy_decisions where decision_id = ?", (decision_id,))
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_delete_retained_row)

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=digest,
        arguments=arguments,
    )

    assert decision.action == "require-reapproval"
    assert decision.post_claim_revalidated is True
    assert decision.approval_reuse_claim_disposition == "retained"
    assert decision.approval_reuse_reason_code == "approval_reuse_context_changed_after_claim"


def test_deferred_tool_claim_without_postclaim_authority_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _dangerous_tool_artifact()
    arguments = {"command": "rm deferred-target"}
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        mode="prompt",
    )
    digest = build_tool_call_hash(artifact, arguments, workspace=workspace, config=config)
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=digest,
            workspace=str(workspace),
            publisher=artifact.publisher,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    provisional = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=digest,
        arguments=arguments,
        claim_saved_approval=False,
    )

    assert provisional.action == "allow"
    assert provisional.pending_approval_reuse_decision is not None
    assert provisional.approval_reuse_claim_disposition == "retained"

    claimed = claim_deferred_tool_call_approval(store=store, decision=provisional)

    assert claimed.action == "require-reapproval"
    assert claimed.post_claim_revalidated is True
    assert claimed.approval_reuse_reason_code == "approval_reuse_context_changed_after_claim"


@pytest.mark.parametrize(
    ("changed_config_fields", "expected_reason"),
    [
        ({"managed_policy_hash": "policy-v2"}, "approval_reuse_policy_changed"),
        ({"sandbox_analysis": "strict"}, "approval_reuse_sandbox_changed"),
    ],
)
def test_tool_call_policy_and_sandbox_context_changes_invalidate_review_approval(
    tmp_path: Path,
    changed_config_fields: dict[str, object],
    expected_reason: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _dangerous_tool_artifact()
    arguments = {"command": "rm relative-target"}
    base_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        mode="prompt",
        managed_policy_hash="policy-v1",
        sandbox_analysis="off",
    )
    changed_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        mode="prompt",
        managed_policy_hash=str(changed_config_fields.get("managed_policy_hash", "policy-v1")),
        sandbox_analysis=str(changed_config_fields.get("sandbox_analysis", "off")),
    )
    old_digest = build_tool_call_hash(artifact, arguments, workspace=workspace, config=base_config)
    new_digest = build_tool_call_hash(artifact, arguments, workspace=workspace, config=changed_config)
    assert old_digest != new_digest
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=old_digest,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    decision = evaluate_tool_call(
        store=store,
        config=changed_config,
        artifact=artifact,
        artifact_hash=new_digest,
        arguments=arguments,
    )

    assert decision.action == "review"
    assert decision.approval_reuse_reason_code == expected_reason


def test_tool_call_server_capability_change_invalidates_review_approval(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace, mode="prompt")
    arguments = {"command": "rm relative-target"}
    old_identity = build_mcp_server_identity(
        config_path="/shared/.mcp.json",
        command="mcp-server",
        args=("--stdio",),
        transport="stdio",
        env_keys=("SAFE_SETTING",),
    )
    new_identity = build_mcp_server_identity(
        config_path="/shared/.mcp.json",
        command="mcp-server",
        args=("--stdio",),
        transport="stdio",
        env_keys=("SAFE_SETTING", "GITHUB_TOKEN"),
    )
    old_artifact = build_tool_call_artifact(
        harness="codex",
        server_name="global-shell",
        tool_name="shell_exec",
        source_scope="global",
        config_path="/shared/.mcp.json",
        transport="stdio",
        server_id="stable-server-id",
        server_identity=old_identity,
    )
    new_artifact = build_tool_call_artifact(
        harness="codex",
        server_name="global-shell",
        tool_name="shell_exec",
        source_scope="global",
        config_path="/shared/.mcp.json",
        transport="stdio",
        server_id="stable-server-id",
        server_identity=new_identity,
    )
    assert old_artifact.artifact_id == new_artifact.artifact_id
    old_digest = build_tool_call_hash(old_artifact, arguments, workspace=workspace, config=config)
    new_digest = build_tool_call_hash(new_artifact, arguments, workspace=workspace, config=config)
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=old_artifact.artifact_id,
            artifact_hash=old_digest,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=new_artifact,
        artifact_hash=new_digest,
        arguments=arguments,
    )

    assert decision.action == "review"
    assert decision.approval_reuse_reason_code == "approval_reuse_capability_changed"


def test_tool_call_resolved_executable_change_invalidates_review_approval(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace, mode="prompt")
    arguments = {"command": "rm relative-target"}
    artifacts = [
        build_tool_call_artifact(
            harness="codex",
            server_name="global-shell",
            tool_name="shell_exec",
            source_scope="global",
            config_path="/shared/.mcp.json",
            transport="stdio",
            server_id="stable-server-id",
            server_fingerprint={"command": ["mcp-server"], "resolved_executable": executable},
        )
        for executable in ("/opt/mcp-v1/bin/server", "/opt/mcp-v2/bin/server")
    ]
    old_digest = build_tool_call_hash(artifacts[0], arguments, workspace=workspace, config=config)
    new_digest = build_tool_call_hash(artifacts[1], arguments, workspace=workspace, config=config)
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifacts[0].artifact_id,
            artifact_hash=old_digest,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifacts[1],
        artifact_hash=new_digest,
        arguments=arguments,
    )

    assert decision.action == "review"
    assert decision.approval_reuse_reason_code == "approval_reuse_identity_changed"


def _sensitive_read_artifact(workspace: Path) -> tuple[GuardArtifact, str]:
    request = extract_sensitive_file_read_request("read_file", {"path": ".env"}, cwd=workspace)
    assert request is not None
    artifact = build_file_read_request_artifact(
        harness="codex",
        request=request,
        config_path=str(workspace / ".mcp.json"),
        source_scope="project",
    )
    return artifact, artifact_hash(artifact)


def _marker_child_command(marker: Path) -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            (
                "import json, pathlib, sys",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                f"    pathlib.Path({str(marker)!r}).write_text(json.dumps(message), encoding='utf-8')",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'ok': True}}))",
                "    sys.stdout.flush()",
            )
        ),
    ]


def _save_sensitive_read_allow(
    store: GuardStore,
    workspace: Path,
    config: GuardConfig,
    command: list[str],
) -> None:
    artifact, _legacy_digest = _sensitive_read_artifact(workspace)
    current_action = config.risk_actions["local_secret_read"] if config.risk_actions is not None else "review"
    launch_env = _build_scrubbed_env()
    digest = build_sensitive_read_approval_hash(
        artifact,
        config=config,
        cwd=workspace,
        current_action=current_action,
        server_launch_identity=build_runtime_launch_identity(
            command[0],
            args=command[1:],
            structured_command=True,
            cwd=workspace,
            launch_env=launch_env,
        ),
        configured_env_values_hash=build_configured_environment_hash(
            launch_env,
            configured_keys=(),
        ),
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=digest,
            reason="old exact approval",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )


def test_stdio_sensitive_read_exact_review_approval_is_reused_with_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    marker = tmp_path / "forwarded.json"
    command = _marker_child_command(marker)
    _save_sensitive_read_allow(store, workspace, config, command)
    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
        current_config_provider=lambda: config,
    )

    result = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": ".env"}},
            }
        ]
    )

    assert result["responses"][0]["result"]["ok"] is True
    assert marker.exists()
    assert result["events"][0]["approval_reuse_reason_code"] == "approval_reuse_accepted"
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "allow"
    receipt_evidence = receipt["scanner_evidence"]
    assert isinstance(receipt_evidence, list)
    assert isinstance(receipt_evidence[-1], dict)
    assert receipt_evidence[-1]["reason_code"] == "approval_reuse_accepted"


@pytest.mark.parametrize("current_action", ["require-reapproval", "sandbox-required", "block"])
def test_stdio_sensitive_read_saved_allow_and_payload_hint_never_lower_current_action(
    tmp_path: Path,
    current_action: GuardAction,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": current_action},
    )
    marker = tmp_path / "must-not-forward.json"
    command = _marker_child_command(marker)
    _save_sensitive_read_allow(store, workspace, config, command)
    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    result = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "policy_action": "allow",
                    "arguments": {"path": ".env"},
                },
            }
        ]
    )

    assert result["responses"][0]["error"]["code"] == -32001
    assert marker.exists() is False
    event = result["events"][0]
    assert event["approval_reuse_reason_code"] in {
        "approval_reuse_reapproval_required",
        "approval_reuse_sandbox_required",
        "approval_reuse_current_block",
    }
    approvals = store.list_approval_requests(limit=1)
    if current_action == "require-reapproval":
        approval = approvals[0]
        assert approval["policy_action"] == current_action
        approval_evidence = approval["scanner_evidence"]
        assert isinstance(approval_evidence, list)
        assert isinstance(approval_evidence[-1], dict)
        assert approval_evidence[-1]["reason_code"] == event["approval_reuse_reason_code"]
    else:
        assert approvals == []
        assert "approval_requests" not in event


@pytest.mark.parametrize(
    ("changed_config_fields", "expected_reason"),
    [
        ({"managed_policy_hash": "policy-v2"}, "approval_reuse_policy_changed"),
        ({"sandbox_analysis": "strict"}, "approval_reuse_sandbox_changed"),
    ],
)
def test_stdio_sensitive_read_policy_and_sandbox_changes_invalidate_review_approval(
    tmp_path: Path,
    changed_config_fields: dict[str, object],
    expected_reason: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    base_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
        managed_policy_hash="policy-v1",
        sandbox_analysis="off",
    )
    changed_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
        managed_policy_hash=str(changed_config_fields.get("managed_policy_hash", "policy-v1")),
        sandbox_analysis=str(changed_config_fields.get("sandbox_analysis", "off")),
    )
    marker = tmp_path / "must-not-forward.json"
    command = _marker_child_command(marker)
    _save_sensitive_read_allow(store, workspace, base_config, command)
    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=changed_config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    result = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": ".env"}},
            }
        ]
    )

    assert marker.exists() is False
    assert result["events"][0]["approval_reuse_reason_code"] == expected_reason
    approval = store.list_approval_requests(limit=1)[0]
    evidence = approval["scanner_evidence"]
    assert isinstance(evidence, list)
    assert isinstance(evidence[-1], dict)
    assert evidence[-1]["reason_code"] == expected_reason
