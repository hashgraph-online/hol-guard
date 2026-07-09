"""Regression tests for manifest-only install supply-chain coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.local_supply_chain import (
    _package_policy_workspace_candidates,
    build_package_protect_payload,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest, PolicyDecision
from codex_plugin_scanner.guard.runtime.package_intent import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _fake_policy_integrity_keyring(install_fake_system_keyring) -> None:
    install_fake_system_keyring()


def _write_pnpm_workspace(workspace_dir: Path, *, extra_dependency: str | None = None) -> None:
    dependencies = {"lodash": "^4.17.21"}
    if extra_dependency is not None:
        dependencies[extra_dependency] = "^1.0.0"
    (workspace_dir / "package.json").write_text(
        json.dumps({"name": "demo", "dependencies": dependencies}, indent=2),
        encoding="utf-8",
    )
    (workspace_dir / "pnpm-lock.yaml").write_text(
        "\n".join(
            [
                "lockfileVersion: '9.0'",
                "packages:",
                "  lodash@4.17.21:",
                "    resolution: {integrity: sha256-demo}",
                "importers:",
                "  .:",
                "    dependencies:",
                "      lodash: 4.17.21",
            ]
        ),
        encoding="utf-8",
    )


def test_parse_package_intent_supports_pnpm_install_alias(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path)

    intent = parse_package_intent("pnpm i", workspace=tmp_path)

    assert intent is not None
    assert intent.package_manager == "pnpm"
    assert intent.intent_kind == "install"
    assert intent.targets == ()
    assert intent.manifest_paths == ("package.json",)
    assert intent.lockfile_paths == ("pnpm-lock.yaml",)


def test_evaluate_package_request_artifact_requires_review_for_unsynced_manifest_dependency(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_pnpm_workspace(workspace_dir, extra_dependency="evilpkg")

    intent = parse_package_intent("pnpm install", workspace=workspace_dir)
    assert intent is not None
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )

    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-06-14T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert any(
        isinstance(reason, dict) and reason.get("code") == "manifest_lockfile_unsynced" for reason in result.reasons
    )
    assert any(package.get("name") == "evilpkg" for package in result.packages)


def test_build_package_protect_payload_reprompts_after_manifest_edit_despite_saved_allow(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_pnpm_workspace(workspace_dir)
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
    assert baseline_rc == 0
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    store.ensure_policy_integrity_ready_for_write(now="2026-06-14T00:00:00Z")
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            workspace=str(workspace_dir),
            publisher=None,
            reason="reviewed",
        ),
        "2026-06-14T00:00:00Z",
    )

    _write_pnpm_workspace(workspace_dir, extra_dependency="evilpkg")
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
    assert retry_payload["verdict"]["action"] == "review"
    evaluation = retry_payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["decision"] == "ask"
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in evaluation.get("reasons", [])
    )


def test_workspace_package_approval_reuses_same_lockfile_across_worktrees(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    worktree_dir = tmp_path / "workspace-worktree"
    workspace_dir.mkdir()
    worktree_dir.mkdir()
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

    assert retry_rc == 0
    assert retry_payload["verdict"]["action"] == "allow"
    retry_receipt = retry_payload["receipt"]
    assert isinstance(retry_receipt, dict)
    assert retry_receipt["artifact_id"] == receipt["artifact_id"]
    assert retry_receipt["artifact_hash"] == receipt["artifact_hash"]
    evaluation = retry_payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in evaluation.get("reasons", [])
    )


def test_workspace_package_approval_reprompts_when_explicit_target_registry_config_changes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    worktree_dir = tmp_path / "workspace-worktree"
    workspace_dir.mkdir()
    worktree_dir.mkdir()
    (workspace_dir / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")
    (worktree_dir / ".npmrc").write_text("registry=https://packages.example.invalid/\n", encoding="utf-8")
    command = ["pnpm", "add", "eslint"]

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
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="req-pnpm-target",
            harness="guard-cli",
            artifact_id=str(receipt["artifact_id"]),
            artifact_name="pnpm add eslint",
            artifact_type="package_request",
            artifact_hash=str(receipt["artifact_hash"]),
            policy_action="require-reapproval",
            recommended_scope="workspace",
            changed_fields=("package_request",),
            source_scope="project",
            config_path=str(workspace_dir / "hol-guard.toml"),
            workspace=str(workspace_dir),
            launch_target="pnpm add eslint",
            review_command="hol-guard approvals approve req-pnpm-target",
            approval_url="http://127.0.0.1:4455/approvals/req-pnpm-target",
        ),
        "2026-06-14T00:00:30Z",
    )
    apply_approval_resolution(
        store=store,
        request_id="req-pnpm-target",
        action="allow",
        scope="workspace",
        workspace=str(workspace_dir),
        reason="trusted registry",
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
    assert retry_payload["verdict"]["action"] == "review"
    retry_receipt = retry_payload["receipt"]
    assert isinstance(retry_receipt, dict)
    assert retry_receipt["artifact_hash"] != receipt["artifact_hash"]
    evaluation = retry_payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in evaluation.get("reasons", [])
    )

def test_package_policy_workspace_candidates_prefer_portable_scope(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
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

    assert candidates[0].startswith("package-request-workspace:v1:")
    assert candidates[1] == str(workspace_dir)


def test_workspace_package_approval_still_reprompts_when_worktree_lockfile_changes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    worktree_dir = tmp_path / "workspace-worktree"
    workspace_dir.mkdir()
    worktree_dir.mkdir()
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
    assert retry_payload["verdict"]["action"] == "review"
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
    assert baseline_rc == 0
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
