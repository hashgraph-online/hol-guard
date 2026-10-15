from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.local_supply_chain import (
    build_package_protect_payload,
)
from codex_plugin_scanner.guard.models import (
    GuardApprovalRequest,
    PolicyDecision,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.manifest_install_fixtures import (
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _install_fake_pnpm,
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _write_linked_git_worktrees,
    _write_pnpm_workspace,
)


def test_private_registry_package_approval_never_lowers_current_gate_or_registry_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_linked_git_worktrees(workspace_dir, tmp_path / "unused-linked")
    _install_fake_pnpm(monkeypatch, tmp_path)
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://packages.example.test/npm/")
    command = ["pnpm", "add", "private-demo@1.0.0"]

    baseline_payload, baseline_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:00:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    request = baseline_payload["request"]
    assert isinstance(receipt, dict)
    assert isinstance(request, dict)
    package_context = request["package_execution_context"]
    assert isinstance(package_context, dict)
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="req-private-registry",
            harness="guard-cli",
            artifact_id=str(receipt["artifact_id"]),
            artifact_name="pnpm add private-demo@1.0.0",
            artifact_type="package_request",
            artifact_hash=str(receipt["artifact_hash"]),
            policy_action="require-reapproval",
            recommended_scope="workspace",
            changed_fields=("package_request",),
            source_scope="project",
            config_path=str(workspace_dir / "hol-guard.toml"),
            workspace=str(workspace_dir),
            launch_target="pnpm add private-demo@1.0.0",
            review_command="hol-guard approvals approve req-private-registry",
            approval_url="http://127.0.0.1:4455/approvals/req-private-registry",
            scanner_evidence=(dict(package_context),),
        ),
        "2026-06-14T00:00:30Z",
    )
    apply_approval_resolution(
        store=store,
        request_id="req-private-registry",
        action="allow",
        scope="workspace",
        workspace=str(workspace_dir),
        reason="trusted private package and registry",
        now="2026-06-14T00:01:00Z",
    )

    same_registry_payload, same_registry_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:02:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert same_registry_rc == 2
    assert same_registry_payload["verdict"]["action"] == "require-reapproval"
    same_evaluation = same_registry_payload["supply_chain_evaluation"]
    assert isinstance(same_evaluation, dict)
    assert any(
        isinstance(reason, dict) and reason.get("code") == "approval_reuse_reapproval_required"
        for reason in same_evaluation.get("reasons", [])
    )
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in same_evaluation.get("reasons", [])
    )

    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://mirror.example.test/npm/")
    changed_registry_payload, changed_registry_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:03:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )

    assert changed_registry_rc == 2
    assert changed_registry_payload["verdict"]["action"] == "require-reapproval"
    changed_receipt = changed_registry_payload["receipt"]
    assert isinstance(changed_receipt, dict)
    assert changed_receipt["artifact_hash"] != receipt["artifact_hash"]
    changed_evaluation = changed_registry_payload["supply_chain_evaluation"]
    assert isinstance(changed_evaluation, dict)
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in changed_evaluation.get("reasons", [])
    )


def test_workspace_package_approval_still_reprompts_when_worktree_lockfile_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    worktree_dir = tmp_path / "workspace-worktree"
    workspace_dir.mkdir()
    worktree_dir.mkdir()
    _write_linked_git_worktrees(workspace_dir, worktree_dir)
    _install_fake_pnpm(monkeypatch, tmp_path)
    _write_pnpm_workspace(workspace_dir, extra_dependency="evilpkg")
    _write_pnpm_workspace(worktree_dir, extra_dependency="evilpkg")
    command = ["pnpm", "install"]

    baseline_payload, baseline_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:00:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    baseline_request = baseline_payload["request"]
    assert isinstance(baseline_request, dict)
    package_context = baseline_request["package_execution_context"]
    assert isinstance(package_context, dict)
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="req-pnpm-workspace",
            harness="guard-cli",
            artifact_id=str(receipt["artifact_id"]),
            artifact_name="pnpm install pnpm",
            artifact_type="package_request",
            artifact_hash=str(receipt["artifact_hash"]),
            policy_action="require-reapproval",
            recommended_scope="workspace",
            changed_fields=("package_request",),
            source_scope="project",
            config_path=str(workspace_dir / "hol-guard.toml"),
            workspace=str(workspace_dir),
            launch_target="pnpm install",
            review_command="hol-guard approvals approve req-pnpm-workspace",
            approval_url="http://127.0.0.1:4455/approvals/req-pnpm-workspace",
            scanner_evidence=(dict(package_context),),
        ),
        "2026-06-14T00:00:30Z",
    )
    apply_approval_resolution(
        store=store,
        request_id="req-pnpm-workspace",
        action="allow",
        scope="workspace",
        workspace=str(workspace_dir),
        reason="same dependency graph",
        now="2026-06-14T00:01:00Z",
    )
    _write_pnpm_workspace(worktree_dir, extra_dependency="otherpkg")

    retry_payload, retry_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=worktree_dir,
        dry_run=True,
        now="2026-06-14T00:02:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )

    assert retry_rc == 2
    assert retry_payload["verdict"]["action"] == "require-reapproval"
    retry_receipt = retry_payload["receipt"]
    assert isinstance(retry_receipt, dict)
    assert retry_receipt["artifact_hash"] != receipt["artifact_hash"]
    evaluation = retry_payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in evaluation.get("reasons", [])
    )


def test_build_package_protect_payload_saved_hashless_block_clear_command_omits_artifact_hash(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    command = ["pnpm", "add", "left-pad"]

    baseline_payload, baseline_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:00:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="block",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=None,
            workspace=str(workspace_dir),
            publisher=None,
            reason="keep blocked",
        ),
        "2026-06-14T00:00:00Z",
    )

    retry_payload, retry_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )

    assert retry_rc == 2
    user_copy = retry_payload["supply_chain_evaluation"]["user_copy"]
    assert "hol-guard policies clear" in user_copy["harness_message"]
    assert "--decision-id" in user_copy["next_step"]
    assert "--artifact-hash" not in user_copy["next_step"]
    assert "--artifact-id" in user_copy["next_step"]
    assert str(workspace_dir) in user_copy["next_step"]
