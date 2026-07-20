"""Regression tests for manifest-only install supply-chain coverage."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.protect_approvals import _annotate_package_execution_context_change
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    _package_policy_workspace_candidates,
    build_package_protect_payload,
    compose_current_package_policy_action,
    recompute_package_protect_artifact_hash,
)
from codex_plugin_scanner.guard.models import GuardAction, GuardApprovalRequest, GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.runtime.package_intent import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
    evaluate_package_request_artifact,
)
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


def _write_linked_git_worktrees(primary: Path, linked: Path) -> None:
    linked.mkdir(parents=True, exist_ok=True)
    common_git_dir = primary / ".git"
    common_git_dir.mkdir()
    (common_git_dir / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.test/team/app.git\n',
        encoding="utf-8",
    )
    linked_git_dir = common_git_dir / "worktrees" / linked.name
    linked_git_dir.mkdir(parents=True)
    (linked_git_dir / "commondir").write_text("../..\n", encoding="utf-8")
    (linked / ".git").write_text(f"gitdir: {linked_git_dir}\n", encoding="utf-8")


def _install_fake_pnpm(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executable_dir = tmp_path / "bin"
    executable_dir.mkdir()
    executable = executable_dir / "pnpm"
    executable.write_text("#!/bin/sh\n# test pnpm\n", encoding="utf-8")
    executable.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("PATH", str(executable_dir))
    monkeypatch.setenv("HOME", str(home))


def _review_package_evaluation() -> PackageRequestEvaluation:
    return PackageRequestEvaluation(
        decision="ask",
        policy_action="review",
        enforcement="local",
        entitlement_state="active",
        cache_status="fresh",
        package_intent_hash="package-intent-v1",
        policy_version="feed-policy-v1",
        bundle_version="feed-bundle-v1",
        workspace_fingerprint="workspace-v1",
        reasons=({"code": "feed_review", "message": "Current feed result requires review."},),
        packages=({"name": "guard-proof", "decision": "ask"},),
        risk_summary="Current feed result requires review.",
        user_copy=SupplyChainUserCopy(
            title="Review package request",
            summary="Current feed result requires review.",
            next_step="Review the package request.",
            dashboard_url=None,
            harness_message="Current feed result requires review.",
        ),
    )


def _allow_package_evaluation() -> PackageRequestEvaluation:
    return PackageRequestEvaluation(
        decision="allow",
        policy_action="allow",
        enforcement="local",
        entitlement_state="active",
        cache_status="fresh",
        package_intent_hash="package-intent-allow",
        policy_version="feed-policy-allow",
        bundle_version="feed-bundle-allow",
        workspace_fingerprint="workspace-allow",
        reasons=({"code": "feed_allow", "message": "Current feed allows execution."},),
        packages=({"name": "guard-proof", "decision": "allow"},),
        risk_summary="Current feed allows execution.",
        user_copy=SupplyChainUserCopy(
            title="Package allowed",
            summary="Current feed allows execution.",
            next_step="Continue.",
            dashboard_url=None,
            harness_message="Current feed allows execution.",
        ),
    )


def _build_review_package_payload(
    *,
    store: GuardStore,
    workspace_dir: Path,
    config: GuardConfig,
    now: str,
) -> tuple[dict[str, object], int]:
    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now=now,
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    return result


def _package_policy_config(
    *,
    guard_home: Path,
    workspace_dir: Path,
    package_action: GuardAction = "review",
    harness_action: GuardAction | None = None,
    artifact_id: str | None = None,
    artifact_action: GuardAction | None = None,
) -> GuardConfig:
    return GuardConfig(
        guard_home=guard_home,
        workspace=workspace_dir,
        security_level="custom",
        risk_actions={"package_script": package_action},
        harness_actions={"guard-cli": harness_action} if harness_action is not None else None,
        artifact_actions={artifact_id: artifact_action}
        if artifact_id is not None and artifact_action is not None
        else None,
    )


def _seed_exact_package_review_allow(
    *,
    store: GuardStore,
    workspace_dir: Path,
    config: GuardConfig,
) -> dict[str, object]:
    baseline_payload, baseline_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    store.ensure_policy_integrity_ready_for_write(now="2026-07-17T00:00:00Z")
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )
    return receipt


def test_build_package_protect_payload_reuses_unchanged_exact_review_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
    )
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)

    retry_payload, retry_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:01:00Z",
    )

    assert retry_rc == 0
    assert retry_payload["verdict"]["action"] == "allow"
    assert retry_payload["executed"] is False
    assert retry_payload["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_approval"


def test_recomputed_package_protect_hash_includes_the_same_final_launch_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    npm = fake_bin / "npm"
    npm.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    payload, returncode = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
    )
    receipt = payload["receipt"]
    assert isinstance(receipt, dict)

    recomputed = recompute_package_protect_artifact_hash(
        ["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        now="2026-07-17T00:00:00Z",
        config=config,
    )

    assert returncode == 2
    assert recomputed == receipt["artifact_hash"]


def test_package_protect_dry_run_previews_one_shot_allow_then_launch_claims_it_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "npm-launches.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
    )
    baseline_payload, baseline_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    store.ensure_policy_integrity_ready_for_write(now="2026-07-17T00:00:30Z")
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            source="approval-gate",
            expires_at="2026-07-18T00:00:00Z",
        ),
        "2026-07-17T00:00:30Z",
    )

    preview_payload, preview_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:01:00Z",
    )

    assert preview_rc == 0
    assert preview_payload["verdict"]["action"] == "allow"
    assert preview_payload["executed"] is False
    preview_lookup = store.resolve_policy_decision_lookup(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        None,
        None,
        "2026-07-17T00:01:00Z",
        consume_one_shot=False,
    )
    assert preview_lookup["decision"] is not None
    assert store.approval_reuse_claim_disposition(preview_lookup["decision"]) == "consumed"
    assert marker.exists() is False

    launch_result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:02:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert launch_result is not None
    launch_payload, launch_rc = launch_result

    assert launch_rc == 0
    assert launch_payload["verdict"]["action"] == "allow"
    assert launch_payload["executed"] is True
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]
    claimed_lookup = store.resolve_policy_decision_lookup(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        None,
        None,
        "2026-07-17T00:02:00Z",
        consume_one_shot=False,
    )
    assert claimed_lookup["decision"] is None

    denied_result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:03:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert denied_result is not None
    denied_payload, denied_rc = denied_result

    assert denied_rc == 2
    assert denied_payload["verdict"]["action"] == "review"
    assert denied_payload["executed"] is False
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]


def test_package_protect_claim_failure_blocks_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "unexpected-npm-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
    )
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)
    monkeypatch.setattr(store, "claim_approval_reuse_decision", lambda *_args, **_kwargs: False)

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 2
    assert payload["verdict"]["action"] == "review"
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == "approval_reuse_claim_failed"
    assert marker.exists() is False


def test_package_protect_retained_local_once_deletion_after_claim_blocks_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "unexpected-retained-local-once-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    baseline_payload, baseline_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    approval_id = store.record_local_once_approval(
        request_id="package-retained-local-once",
        harness="guard-cli",
        artifact_id=str(receipt["artifact_id"]),
        artifact_hash=str(receipt["artifact_hash"]),
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:30Z",
        expires_at="2026-07-18T00:00:00Z",
    )
    assert approval_id is not None
    selected = store.resolve_policy_decision(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        now="2026-07-17T00:00:45Z",
        consume_one_shot=False,
    )
    assert selected is not None
    assert store.approval_reuse_claim_disposition(selected) == "retained"
    original_claim = store.claim_approval_reuse_decision

    def claim_then_delete(decision: dict[str, object], *, now: str) -> bool:
        assert decision["approval_id"] == approval_id
        assert store.approval_reuse_claim_disposition(decision) == "retained"
        claimed = original_claim(decision, now=now)
        assert claimed is True
        with sqlite3.connect(store.path) as connection:
            cursor = connection.execute(
                "delete from guard_local_once_approvals where approval_id = ?",
                (approval_id,),
            )
        assert cursor.rowcount == 1
        return True

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_delete)

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 2
    assert payload["verdict"]["action"] == "review"
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == ("approval_reuse_context_changed_after_claim")
    assert marker.exists() is False


def test_package_protect_retained_persistent_policy_deletion_after_claim_blocks_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "unexpected-retained-policy-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    receipt = _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)
    selected = store.resolve_policy_decision(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        now="2026-07-17T00:00:45Z",
        consume_one_shot=False,
    )
    assert selected is not None
    assert store.approval_reuse_claim_disposition(selected) == "retained"
    original_claim = store.claim_approval_reuse_decision

    def claim_then_delete(decision: dict[str, object], *, now: str) -> bool:
        assert store.approval_reuse_claim_disposition(decision) == "retained"
        claimed = original_claim(decision, now=now)
        assert claimed is True
        decision_id = decision["decision_id"]
        assert isinstance(decision_id, int)
        with sqlite3.connect(store.path) as connection:
            cursor = connection.execute(
                "delete from policy_decisions where decision_id = ?",
                (decision_id,),
            )
        assert cursor.rowcount == 1
        return True

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_delete)

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 2
    assert payload["verdict"]["action"] == "review"
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == ("approval_reuse_context_changed_after_claim")
    assert marker.exists() is False


def test_package_protect_reloads_saved_policy_after_claim_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "unexpected-post-claim-policy-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)
    original_claim = store.claim_approval_reuse_decision

    def claim_then_block(decision: dict[str, object], *, now: str) -> bool:
        claimed = original_claim(decision, now=now)
        assert claimed is True
        store.upsert_policy(
            PolicyDecision(
                harness=str(decision["harness"]),
                scope="artifact",
                action="block",
                artifact_id=str(decision["artifact_id"]),
                artifact_hash=str(decision["artifact_hash"]),
                reason="policy changed to block during saved approval claim",
                source="manual",
            ),
            now,
        )
        return True

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_block)

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 2
    assert payload["verdict"]["action"] == "block"
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_block"
    assert marker.exists() is False


@pytest.mark.parametrize(
    ("refresh_mode", "expected_returncode", "expected_action", "expected_launch"),
    (
        ("unchanged", 0, "allow", True),
        ("block", 2, "block", False),
        ("failure", 2, "block", False),
    ),
)
def test_package_protect_refreshes_current_config_after_saved_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    refresh_mode: str,
    expected_returncode: int,
    expected_action: str,
    expected_launch: bool,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / f"config-refresh-{refresh_mode}-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)

    def current_config() -> GuardConfig:
        if refresh_mode == "failure":
            raise RuntimeError("sensitive config provider failure")
        return _package_policy_config(
            guard_home=store.guard_home,
            workspace_dir=workspace_dir,
            package_action="block" if refresh_mode == "block" else "review",
        )

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        current_config_provider=current_config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == expected_returncode
    assert payload["verdict"]["action"] == expected_action
    assert payload["executed"] is expected_launch
    assert marker.exists() is expected_launch
    if refresh_mode == "failure":
        first_reason = payload["supply_chain_evaluation"]["reasons"][0]
        assert first_reason["code"] == "approval_reuse_policy_changed"
        assert "sensitive" not in json.dumps(payload)


@pytest.mark.parametrize("final_action", ("allow", "warn"))
def test_package_protect_rebuilds_every_permitted_final_projection_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    final_action: str,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _allow_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / f"final-{final_action}-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    initial_authority = local_supply_chain_module._build_package_protect_authority(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        now="2026-07-17T00:01:00Z",
        config=None,
        additional_current_action=None,
        additional_policy_context=None,
    )
    assert initial_authority is not None

    def insert_final_policy() -> tuple[object | None, dict[str, object] | None]:
        if final_action == "warn":
            store.upsert_policy(
                PolicyDecision(
                    harness=initial_authority.artifact.harness,
                    scope="artifact",
                    action="warn",
                    artifact_id=initial_authority.artifact.artifact_id,
                    artifact_hash=initial_authority.artifact_hash,
                    reason="warn inserted at the final authority boundary",
                    source="manual",
                ),
                "2026-07-17T00:01:00Z",
            )
        return None, None

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
        additional_authority_provider=insert_final_policy,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]
    evaluation = payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["policy_action"] == final_action
    assert evaluation["decision"] == final_action
    user_copy = evaluation["user_copy"]
    assert isinstance(user_copy, dict)
    assert payload["verdict"] == {
        "action": final_action,
        "reason": user_copy["summary"],
        "risk_signals": [reason["message"] for reason in evaluation["reasons"]],
        "matched_advisories": [],
        "blocking": False,
    }
    receipt = payload["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["policy_decision"] == final_action
    assert receipt["capabilities_summary"] == user_copy["summary"]
    assert receipt["provenance_summary"] == user_copy["harness_message"]
    action_envelope = receipt["action_envelope_json"]
    assert isinstance(action_envelope, dict)
    assert action_envelope["policy_action"] == final_action

    stored_receipts = store.list_receipts(limit=10, harness="guard-cli")
    assert len(stored_receipts) == 1
    stored_receipt = stored_receipts[0]
    assert stored_receipt["receipt_id"] == receipt["receipt_id"]
    assert stored_receipt["policy_decision"] == final_action
    assert stored_receipt["capabilities_summary"] == user_copy["summary"]
    assert stored_receipt["provenance_summary"] == user_copy["harness_message"]
    assert stored_receipt["action_envelope_json"]["policy_action"] == final_action
    final_events = store.list_events(event_name=f"install_time_{final_action}")
    assert len(final_events) == 1
    assert final_events[0]["payload"]["action"] == final_action
    other_action = "warn" if final_action == "allow" else "allow"
    assert store.list_events(event_name=f"install_time_{other_action}") == []


def test_package_protect_current_warn_rewrites_every_final_package_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_evaluation = replace(
        _allow_package_evaluation(),
        packages=(
            {
                "name": "guard-proof",
                "version": "1.0.0",
                "decision": "allow",
                "related_advisory_ids": ["adv-feed-allow-current-warn"],
            },
        ),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: feed_evaluation,
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "current-warn-launches.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
        package_action="warn",
    )

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]
    evaluation = payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["decision"] == "warn"
    assert evaluation["policy_action"] == "warn"
    packages = evaluation["packages"]
    assert isinstance(packages, list)
    assert packages
    assert all(package["decision"] == "warn" for package in packages)
    matched_advisories = payload["matched_advisories"]
    assert matched_advisories == [
        {
            "advisory_id": "adv-feed-allow-current-warn",
            "package_name": "guard-proof",
            "version": "1.0.0",
            "decision": "warn",
        }
    ]
    assert payload["verdict"]["action"] == "warn"
    assert payload["verdict"]["matched_advisories"] == matched_advisories
    receipt = payload["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["policy_decision"] == "warn"
    assert receipt["action_envelope_json"]["policy_action"] == "warn"
    stored_receipts = store.list_receipts(limit=10, harness="guard-cli")
    assert len(stored_receipts) == 1
    assert stored_receipts[0]["policy_decision"] == "warn"
    assert stored_receipts[0]["action_envelope_json"]["policy_action"] == "warn"
    events = store.list_events(event_name="install_time_warn")
    assert len(events) == 1
    assert events[0]["payload"]["action"] == "warn"


@pytest.mark.parametrize(
    ("current_action", "expected_package_decision"),
    (("warn", "warn"), ("block", "block"), ("require-reapproval", "ask")),
)
def test_current_package_policy_rewrites_every_package_decision(
    current_action: GuardAction,
    expected_package_decision: str,
) -> None:
    evaluation = replace(
        _allow_package_evaluation(),
        packages=(
            {"name": "first", "decision": "allow"},
            {"name": "second", "decision": "allow"},
        ),
    )

    rewritten = local_supply_chain_module._package_evaluation_with_current_policy_action(
        evaluation,
        current_action=current_action,
    )

    assert rewritten.policy_action == current_action
    assert all(package["decision"] == expected_package_decision for package in rewritten.packages)


def test_package_protect_launch_uses_final_canonical_workspace_after_symlink_retarget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _allow_package_evaluation(),
    )
    approved_workspace = tmp_path / "approved-workspace"
    approved_workspace.mkdir()
    attacker_workspace = tmp_path / "attacker-workspace"
    attacker_workspace.mkdir()
    workspace_alias = tmp_path / "workspace"
    workspace_alias.symlink_to(approved_workspace, target_is_directory=True)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "launch-workspace.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\n/bin/pwd -P > '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    original_resolved_argv = local_supply_chain_module.resolved_runtime_launch_argv

    def retarget_workspace_after_final_identity(
        identity: dict[str, object],
        *,
        args: tuple[str, ...],
    ) -> tuple[str, ...] | None:
        launch_command = original_resolved_argv(identity, args=args)
        workspace_alias.unlink()
        workspace_alias.symlink_to(attacker_workspace, target_is_directory=True)
        return launch_command

    monkeypatch.setattr(
        local_supply_chain_module,
        "resolved_runtime_launch_argv",
        retarget_workspace_after_final_identity,
    )

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_alias,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").strip() == str(approved_workspace.resolve(strict=True))
    assert workspace_alias.resolve(strict=True) == attacker_workspace.resolve(strict=True)


def test_package_protect_launch_uses_final_environment_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _allow_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "launch-registry.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$NPM_CONFIG_REGISTRY\" > '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://approved.example.test/npm")
    package_secret = "package-secret-must-not-appear"
    monkeypatch.setenv("NPM_TOKEN", package_secret)
    store = GuardStore(tmp_path / "guard-home")
    original_resolved_argv = local_supply_chain_module.resolved_runtime_launch_argv

    def mutate_environment_after_final_identity(
        identity: dict[str, object],
        *,
        args: tuple[str, ...],
    ) -> tuple[str, ...] | None:
        launch_command = original_resolved_argv(identity, args=args)
        monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://attacker.example.test/npm")
        monkeypatch.setenv("NPM_TOKEN", "attacker-secret")
        return launch_command

    monkeypatch.setattr(
        local_supply_chain_module,
        "resolved_runtime_launch_argv",
        mutate_environment_after_final_identity,
    )

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").strip() == "https://approved.example.test/npm"
    assert package_secret not in json.dumps(payload)
    assert package_secret not in json.dumps(store.list_receipts(limit=10))


def test_package_protect_normal_launch_uses_captured_authority_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _allow_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "normal-authority-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' > '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["verdict"]["action"] == "allow"
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]


@pytest.mark.parametrize("mutation", ["manager", "manifest", "path"])
def test_package_protect_revalidates_claim_time_execution_context_mutation_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    manifest = workspace_dir / "package.json"
    manifest.write_text('{"name":"demo","version":"1.0.0"}\n', encoding="utf-8")
    first_bin = tmp_path / "first-bin"
    second_bin = tmp_path / "second-bin"
    first_bin.mkdir()
    second_bin.mkdir()
    marker = tmp_path / "unexpected-package-launch.txt"
    first_npm = first_bin / "npm"
    second_npm = second_bin / "npm"
    first_npm.write_text(f"#!/bin/sh\nprintf 'first\\n' >> '{marker}'\n", encoding="utf-8")
    second_npm.write_text(f"#!/bin/sh\nprintf 'second\\n' >> '{marker}'\n", encoding="utf-8")
    first_npm.chmod(0o755)
    second_npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(first_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
    )
    receipt = _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            source="approval-gate",
            expires_at="2026-07-18T00:00:00Z",
        ),
        "2026-07-17T00:00:30Z",
    )
    original_claim = store.claim_approval_reuse_decision

    def claim_then_mutate(decision: dict[str, object], *, now: str) -> bool:
        claimed = original_claim(decision, now=now)
        assert claimed is True
        if mutation == "manager":
            first_npm.write_text(f"#!/bin/sh\nprintf 'changed\\n' >> '{marker}'\n", encoding="utf-8")
            first_npm.chmod(0o755)
        elif mutation == "manifest":
            manifest.write_text('{"name":"demo","version":"2.0.0"}\n', encoding="utf-8")
        else:
            monkeypatch.setenv("PATH", str(second_bin))
        return True

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_mutate)

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 2
    assert payload["executed"] is False
    assert marker.exists() is False
    reasons = payload["supply_chain_evaluation"]["reasons"]
    assert reasons[0]["code"] in {
        "approval_reuse_identity_changed",
        "approval_reuse_content_changed",
        "approval_reuse_capability_changed",
    }
    consumed = store.resolve_policy_decision_lookup(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        None,
        None,
        "2026-07-17T00:01:00Z",
        consume_one_shot=False,
    )
    assert consumed["decision"] is None


def test_package_protect_revalidates_current_allow_immediately_before_every_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allow_evaluation = PackageRequestEvaluation(
        decision="allow",
        policy_action="allow",
        enforcement="local",
        entitlement_state="active",
        cache_status="fresh",
        package_intent_hash="package-intent-allow",
        policy_version="feed-policy-allow",
        bundle_version="feed-bundle-allow",
        workspace_fingerprint="workspace-allow",
        reasons=({"code": "feed_allow", "message": "Current feed allows execution."},),
        packages=({"name": "guard-proof", "decision": "allow"},),
        risk_summary="Current feed allows execution.",
        user_copy=SupplyChainUserCopy(
            title="Package allowed",
            summary="Current feed allows execution.",
            next_step="Continue.",
            dashboard_url=None,
            harness_message="Current feed allows execution.",
        ),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: allow_evaluation,
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "unexpected-current-allow-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'initial\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")

    def mutate_before_final_rebuild() -> tuple[object | None, dict[str, object] | None]:
        npm.write_text(f"#!/bin/sh\nprintf 'changed\\n' >> '{marker}'\n", encoding="utf-8")
        npm.chmod(0o755)
        return None, None

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
        additional_authority_provider=mutate_before_final_rebuild,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 2
    assert payload["executed"] is False
    assert marker.exists() is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == "approval_reuse_identity_changed"


def test_package_protect_fails_closed_when_command_wrapper_launch_semantics_are_unbound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allow_evaluation = PackageRequestEvaluation(
        decision="allow",
        policy_action="allow",
        enforcement="local",
        entitlement_state="active",
        cache_status="fresh",
        package_intent_hash="wrapped-package-intent",
        policy_version="wrapped-package-policy",
        bundle_version="wrapped-package-bundle",
        workspace_fingerprint="wrapped-package-workspace",
        reasons=({"code": "feed_allow", "message": "Current feed allows execution."},),
        packages=({"name": "guard-proof", "decision": "allow"},),
        risk_summary="Current feed allows execution.",
        user_copy=SupplyChainUserCopy(
            title="Package allowed",
            summary="Current feed allows execution.",
            next_step="Continue.",
            dashboard_url=None,
            harness_message="Current feed allows execution.",
        ),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: allow_evaluation,
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "unexpected-wrapper-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")

    result = build_package_protect_payload(
        command=["/usr/bin/env", "npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 2
    assert payload["executed"] is False
    assert marker.exists() is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == "approval_reuse_identity_changed"


@pytest.mark.parametrize("blocking_policy", ["package_script", "harness", "package_artifact"])
def test_build_package_protect_payload_old_review_approval_cannot_lower_current_config_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocking_policy: str,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    base_config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
    )
    receipt = _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=base_config)
    artifact_id = str(receipt["artifact_id"])
    changed_config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
        package_action="block" if blocking_policy == "package_script" else "review",
        harness_action="block" if blocking_policy == "harness" else None,
        artifact_id=artifact_id if blocking_policy == "package_artifact" else None,
        artifact_action="block" if blocking_policy == "package_artifact" else None,
    )

    retry_payload, retry_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=changed_config,
        now="2026-07-17T00:01:00Z",
    )

    assert retry_rc == 2
    assert retry_payload["verdict"]["action"] == "block"
    assert retry_payload["executed"] is False
    evaluation = retry_payload["supply_chain_evaluation"]
    assert evaluation["policy_action"] == "block"
    assert evaluation["reasons"][0]["code"] in {
        "approval_reuse_current_block",
        "approval_reuse_policy_changed",
    }


@pytest.mark.parametrize(
    ("policy_input", "expected_action"),
    (("harness_risk", "block"), ("publisher_override", "block"), ("exact_over_broader", "review")),
)
def test_current_package_policy_composes_every_relevant_config_scope(
    tmp_path: Path,
    policy_input: str,
    expected_action: str,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    intent = parse_package_intent("npm install guard-proof", workspace=workspace_dir)
    assert intent is not None
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    if policy_input == "publisher_override":
        artifact = GuardArtifact(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            name=artifact.name,
            artifact_type=artifact.artifact_type,
            source_scope=artifact.source_scope,
            config_path=artifact.config_path,
            publisher="npm",
            metadata=artifact.metadata,
            transport=artifact.transport,
        )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace_dir,
        security_level="custom",
        risk_actions={"package_script": "review"},
        harness_risk_actions={"guard-cli": {"package_script": "block"}} if policy_input == "harness_risk" else None,
        publisher_actions={"npm": "block"} if policy_input == "publisher_override" else None,
        artifact_actions={artifact.artifact_id: "allow"} if policy_input == "exact_over_broader" else None,
        harness_actions={"guard-cli": "block"} if policy_input == "exact_over_broader" else None,
    )

    assert (
        compose_current_package_policy_action(
            artifact=artifact,
            evaluation=_review_package_evaluation(),
            config=config,
        )
        == expected_action
    )


def test_current_package_policy_harness_risk_override_replaces_global_risk_action(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    intent = parse_package_intent("npm install guard-proof", workspace=workspace_dir)
    assert intent is not None
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace_dir,
        security_level="custom",
        risk_actions={"package_script": "block"},
        harness_risk_actions={"guard-cli": {"package_script": "allow"}},
    )

    assert (
        compose_current_package_policy_action(
            artifact=artifact,
            evaluation=_review_package_evaluation(),
            config=config,
        )
        == "review"
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
    assert retry_payload["verdict"]["action"] == "require-reapproval"
    evaluation = retry_payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["decision"] == "ask"
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in evaluation.get("reasons", [])
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
