from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.protect_approvals import _annotate_package_execution_context_change
from codex_plugin_scanner.guard.local_supply_chain import (
    _package_policy_workspace_candidates,
    build_package_protect_payload,
)
from codex_plugin_scanner.guard.models import (
    GuardApprovalRequest,
    PolicyDecision,
)
from codex_plugin_scanner.guard.runtime.package_intent import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
from codex_plugin_scanner.guard.store import GuardStore
from tests.manifest_install_fixtures import (
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _install_fake_pnpm,
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _write_linked_git_worktrees,
    _write_pnpm_workspace,
)


def test_workspace_package_approval_cannot_lower_current_gate_across_linked_worktrees(
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
    assert retry_receipt["artifact_id"] == receipt["artifact_id"]
    assert retry_receipt["artifact_hash"] == receipt["artifact_hash"]
    evaluation = retry_payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert any(
        isinstance(reason, dict) and reason.get("code") == "approval_reuse_reapproval_required"
        for reason in evaluation.get("reasons", [])
    )
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in evaluation.get("reasons", [])
    )

    unrelated_dir = tmp_path / "unrelated-workspace"
    unrelated_dir.mkdir()
    _write_linked_git_worktrees(unrelated_dir, tmp_path / "unrelated-unused-linked")
    _write_pnpm_workspace(unrelated_dir, extra_dependency="evilpkg")
    unrelated_payload, unrelated_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=unrelated_dir,
        dry_run=True,
        now="2026-06-14T00:03:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert unrelated_rc == 2
    assert unrelated_payload["verdict"]["action"] == "require-reapproval"
    unrelated_evaluation = unrelated_payload["supply_chain_evaluation"]
    assert isinstance(unrelated_evaluation, dict)
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in unrelated_evaluation.get("reasons", [])
    )
    unrelated_request = unrelated_payload["request"]
    assert isinstance(unrelated_request, dict)
    unrelated_context = unrelated_request["package_execution_context"]
    assert isinstance(unrelated_context, dict)
    approval_item: dict[str, object] = {
        "changed_fields": [],
        "scanner_evidence": [dict(unrelated_context)],
    }
    _annotate_package_execution_context_change(
        approval_item,
        store=store,
        artifact_id=str(receipt["artifact_id"]),
    )
    evidence = approval_item["scanner_evidence"]
    assert isinstance(evidence, list)
    assert isinstance(evidence[0], dict)
    assert evidence[0]["changed_components"] == ["repository_identity"]


def test_package_policy_workspace_candidates_use_only_context_complete_v2_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_linked_git_worktrees(workspace_dir, tmp_path / "unused-linked")
    _install_fake_pnpm(monkeypatch, tmp_path)
    _write_pnpm_workspace(workspace_dir, extra_dependency="evilpkg")
    intent = parse_package_intent("pnpm install", workspace=workspace_dir)
    assert intent is not None
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )

    candidates = _package_policy_workspace_candidates(
        artifact=artifact,
        artifact_hash="hash-package",
        workspace_dir=workspace_dir,
    )

    assert len(candidates) == 1
    assert candidates[0].startswith("package-request-workspace:v2:")


def test_legacy_v1_package_workspace_approval_is_not_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_linked_git_worktrees(workspace_dir, tmp_path / "unused-linked")
    _install_fake_pnpm(monkeypatch, tmp_path)
    _write_pnpm_workspace(workspace_dir, extra_dependency="evilpkg")
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
    store.ensure_policy_integrity_ready_for_write(now="2026-06-14T00:00:30Z")
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="workspace",
            action="allow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            workspace=f"package-request-workspace:v1:{'a' * 64}",
            source="approval-gate",
        ),
        "2026-06-14T00:00:30Z",
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
    assert retry_payload["verdict"]["action"] == "require-reapproval"
    evaluation = retry_payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in evaluation.get("reasons", [])
    )
