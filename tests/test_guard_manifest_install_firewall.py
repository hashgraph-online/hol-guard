from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.local_supply_chain import (
    build_package_protect_payload,
    evaluate_package_request_artifact,
)
from codex_plugin_scanner.guard.models import (
    PolicyDecision,
)
from codex_plugin_scanner.guard.runtime.package_intent_common import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
from codex_plugin_scanner.guard.store import GuardStore
from tests.manifest_install_fixtures import (
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _write_pnpm_workspace,
)
from tests.native_workspace import bind_workspace


def test_parse_package_intent_supports_pnpm_install_alias(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path)

    intent = parse_package_intent("pnpm i", workspace=tmp_path)

    assert intent is not None
    assert intent.package_manager == "pnpm"
    assert intent.intent_kind == "install"
    assert intent.targets == ()
    assert intent.manifest_paths == ("package.json",)
    assert intent.lockfile_paths == ("pnpm-lock.yaml",)


def test_parse_npm_package_intent_excludes_prefix_destination(tmp_path: Path) -> None:
    install_dir = tmp_path / "agent" / "npm"

    intent = parse_package_intent(
        f"npm install @firecrawl/pi-firecrawl --prefix {install_dir} --legacy-peer-deps",
        workspace=tmp_path,
    )

    assert intent is not None
    assert [target.package_name for target in intent.targets] == ["@firecrawl/pi-firecrawl"]


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


def test_manifest_targets_scope_lockfile_versions_to_their_workspace(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    app_dir = workspace_dir / "app"
    service_dir = workspace_dir / "service"
    app_dir.mkdir(parents=True)
    service_dir.mkdir()
    (app_dir / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^1.0.0"}}),
        encoding="utf-8",
    )
    (app_dir / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/lodash": {"version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    (service_dir / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^2.0.0"}}),
        encoding="utf-8",
    )
    intent = parse_package_intent("npm install", workspace=app_dir)
    assert intent is not None
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    artifact = replace(
        artifact,
        metadata={
            **artifact.metadata,
            "manifest_paths": ["app/package.json", "service/package.json"],
            "lockfile_paths": ["app/package-lock.json"],
        },
    )

    store = GuardStore(tmp_path / "guard-home")
    bind_workspace(store, "workspace-1")
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-06-14T00:00:00Z",
    )

    lodash = [package for package in result.packages if package.get("name") == "lodash"]
    assert [(package.get("requestedVersion"), package.get("resolvedVersion")) for package in lodash] == [
        ("1.0.0", "1.0.0"),
        ("^2.0.0", None),
    ]


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
