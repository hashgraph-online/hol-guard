from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    build_package_protect_payload,
)
from codex_plugin_scanner.guard.models import (
    GuardAction,
    PolicyDecision,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _native_package_intent(package_intent_native):
    """Parse intents through the resident authority."""

    return package_intent_native

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
    command: list[str] | None = None,
) -> tuple[dict[str, object], int]:
    result = build_package_protect_payload(
        command=command or ["npm", "install", "guard-proof"],
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
