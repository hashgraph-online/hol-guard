from __future__ import annotations

from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    build_package_protect_payload,
    compose_current_package_policy_action,
)
from codex_plugin_scanner.guard.models import (
    GuardArtifact,
    PolicyDecision,
)
from codex_plugin_scanner.guard.runtime.package_intent import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.manifest_install_fixtures import (
    _build_review_package_payload,
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _package_policy_config,
    _review_package_evaluation,
    _seed_exact_package_review_allow,
)


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
