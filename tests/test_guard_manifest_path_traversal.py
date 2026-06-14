"""Regression tests for workspace-contained manifest and lockfile reads."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.manifest_dependency_targets import unsynced_manifest_dependency_targets
from codex_plugin_scanner.guard.runtime.package_intent import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.runtime.workspace_path_guard import (
    existing_paths_within_workspace,
    read_text_within_workspace,
    resolve_path_within_workspace,
)
from codex_plugin_scanner.guard.store import GuardStore


def test_resolve_path_within_workspace_rejects_parent_traversal(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace.mkdir()
    (outside / "requirements.txt").write_text("leakpkg==1.0.0\n", encoding="utf-8")

    assert resolve_path_within_workspace(workspace, "../outside/requirements.txt") is None
    assert read_text_within_workspace(workspace, "../outside/requirements.txt") is None
    assert existing_paths_within_workspace(workspace, ("../outside/requirements.txt",)) == ()


def test_resolve_path_within_workspace_rejects_symlink_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    secret = tmp_path / "secret.env"
    workspace.mkdir()
    secret.write_text("AWS_SECRET_ACCESS_KEY=super-secret\n", encoding="utf-8")
    (workspace / "requirements.txt").symlink_to(secret)

    assert resolve_path_within_workspace(workspace, "requirements.txt") is None
    assert read_text_within_workspace(workspace, "requirements.txt") is None


def test_parse_pip_intent_ignores_requirements_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "requirements.txt").write_text("leakpkg==1.0.0\n", encoding="utf-8")

    intent = parse_package_intent("pip install -r ../outside/requirements.txt", workspace=workspace)

    assert intent is not None
    assert intent.manifest_paths == ()


def test_unsynced_manifest_targets_do_not_read_symlinked_requirements(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    secret = tmp_path / "secret.env"
    workspace.mkdir()
    secret.write_text("AWS_SECRET_ACCESS_KEY=super-secret\n", encoding="utf-8")
    (workspace / "requirements.txt").symlink_to(secret)
    (workspace / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    intent = parse_package_intent("pip install", workspace=workspace)
    assert intent is not None
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )

    targets = unsynced_manifest_dependency_targets(artifact, workspace)

    assert not any("AWS_SECRET" in str(target.get("package_name")) for target in targets)
    assert not any("super-secret" in str(target.get("range")) for target in targets)


def test_evaluate_package_request_artifact_does_not_leak_traversal_requirements(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "requirements.txt").write_text("AWS_SECRET_ACCESS_KEY=super-secret\n", encoding="utf-8")
    (workspace / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    intent = parse_package_intent("pip install -r ../outside/requirements.txt", workspace=workspace)
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
        workspace_dir=workspace,
        now="2026-06-14T00:00:00Z",
    )

    serialized = json.dumps(result.to_dict())
    assert "AWS_SECRET_ACCESS_KEY" not in serialized
    assert "super-secret" not in serialized
