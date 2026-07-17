"""Regression coverage for context-complete package approval identities."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.approval_scope_support import (
    package_request_portable_workspace_scope,
    package_request_runtime_workspace_scope,
    supported_request_scopes,
)
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.package_execution_context import (
    build_package_execution_context,
    changed_package_execution_context_components,
)


def _write_repository(root: Path, *, common_git_dir: Path | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if common_git_dir is None:
        common_git_dir = root / ".git"
        common_git_dir.mkdir(parents=True)
        (common_git_dir / "config").write_text(
            '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.test/team/app.git\n',
            encoding="utf-8",
        )
    else:
        git_dir = common_git_dir / "worktrees" / root.name
        git_dir.mkdir(parents=True)
        (git_dir / "commondir").write_text("../..\n", encoding="utf-8")
        (root / ".git").write_text(f"gitdir: {git_dir}\n", encoding="utf-8")
    return common_git_dir


def _write_package_files(workspace: Path) -> None:
    (workspace / "package.json").write_text(
        json.dumps({"name": "demo", "dependencies": {"left-pad": "1.3.0"}}, indent=2),
        encoding="utf-8",
    )
    (workspace / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0: {}\n",
        encoding="utf-8",
    )


def _artifact(*, manager: str = "pnpm", prefix: str = "") -> GuardArtifact:
    manifest_path = f"{prefix}package.json"
    lockfile_path = f"{prefix}pnpm-lock.yaml"
    return GuardArtifact(
        artifact_id="guard-cli:project:package-request:context-test",
        name=f"{manager} install",
        harness="guard-cli",
        artifact_type="package_request",
        source_scope="project",
        config_path="hol-guard.toml",
        metadata={
            "package_manager": manager,
            "intent_kind": "install",
            "manifest_paths": [manifest_path],
            "lockfile_paths": [lockfile_path],
            "flags": [],
        },
    )


def _environment(tmp_path: Path, *, executable_payload: str = "pnpm-v1") -> dict[str, str]:
    executable_dir = tmp_path / "bin"
    executable_dir.mkdir(exist_ok=True)
    executable = executable_dir / "pnpm"
    executable.write_text(f"#!/bin/sh\n# {executable_payload}\n", encoding="utf-8")
    executable.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {"PATH": str(executable_dir), "HOME": str(home)}


def _context(
    workspace: Path,
    artifact: GuardArtifact,
    environment: dict[str, str],
):
    return build_package_execution_context(
        workspace_dir=workspace,
        artifact=artifact,
        executable="pnpm",
        environment=environment,
    )


def _component_digest(context, name: str) -> str:
    return next(component.digest for component in context.components if component.name == name)


def test_portable_context_matches_across_linked_git_worktrees(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    linked = tmp_path / "linked"
    common = _write_repository(primary)
    _write_repository(linked, common_git_dir=common)
    _write_package_files(primary)
    _write_package_files(linked)
    environment = _environment(tmp_path)
    artifact = _artifact()

    primary_context = _context(primary, artifact, environment)
    linked_context = _context(linked, artifact, environment)

    assert primary_context.portable is True
    assert linked_context.portable is True
    assert primary_context.digest == linked_context.digest
    primary_scope = package_request_portable_workspace_scope(
        artifact_id=artifact.artifact_id,
        artifact_hash="a" * 64,
        artifact_type=artifact.artifact_type,
        execution_context=primary_context,
    )
    linked_scope = package_request_portable_workspace_scope(
        artifact_id=artifact.artifact_id,
        artifact_hash="a" * 64,
        artifact_type=artifact.artifact_type,
        execution_context=linked_context,
    )
    assert primary_scope == linked_scope
    assert primary_scope is not None and primary_scope.startswith("package-request-workspace:v2:")


def test_identical_files_in_unrelated_repositories_do_not_share_context(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write_repository(first)
    _write_repository(second)
    _write_package_files(first)
    _write_package_files(second)
    environment = _environment(tmp_path)
    artifact = _artifact()

    first_context = _context(first, artifact, environment)
    second_context = _context(second, artifact, environment)

    assert first_context.portable is True
    assert second_context.portable is True
    assert first_context.digest != second_context.digest
    assert changed_package_execution_context_components(first_context, second_context) == ("repository_identity",)


def test_registry_config_is_normalized_and_security_changes_rekey(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_repository(workspace)
    _write_package_files(workspace)
    environment = _environment(tmp_path)
    artifact = _artifact()
    npmrc = workspace / ".npmrc"
    npmrc.write_text("# local registry\nregistry = https://registry.example.test/\n", encoding="utf-8")
    before = _context(workspace, artifact, environment)

    npmrc.write_text("registry=https://registry.example.test/\n; comment only\n", encoding="utf-8")
    comment_only = _context(workspace, artifact, environment)
    npmrc.write_text("registry=https://mirror.example.test/\n", encoding="utf-8")
    changed = _context(workspace, artifact, environment)

    assert before.digest == comment_only.digest
    assert _component_digest(before, "registry_and_proxy_configuration") != _component_digest(
        changed,
        "registry_and_proxy_configuration",
    )


def test_pnpm_hook_and_yarn_plugin_changes_rekey_hook_component(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_repository(workspace)
    _write_package_files(workspace)
    environment = _environment(tmp_path)
    artifact = _artifact()
    hook = workspace / "pnpmfile.cjs"
    plugin = workspace / ".yarn" / "plugins" / "guard.cjs"
    plugin.parent.mkdir(parents=True)
    hook.write_text("module.exports = { hooks: {} };\n", encoding="utf-8")
    plugin.write_text("module.exports = {};\n", encoding="utf-8")
    before = _context(workspace, artifact, environment)

    hook.write_text("module.exports = { hooks: { readPackage: value => value } };\n", encoding="utf-8")
    hook_changed = _context(workspace, artifact, environment)
    plugin.write_text("module.exports = { name: 'updated' };\n", encoding="utf-8")
    plugin_changed = _context(workspace, artifact, environment)

    component = "lifecycle_hooks_overrides_and_patches"
    assert _component_digest(before, component) != _component_digest(hook_changed, component)
    assert _component_digest(hook_changed, component) != _component_digest(plugin_changed, component)


def test_root_workspace_manifest_change_rekeys_nested_workspace_configuration(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    workspace = repository / "packages" / "app"
    _write_repository(repository)
    workspace.mkdir(parents=True)
    _write_package_files(workspace)
    root_manifest = repository / "package.json"
    root_manifest.write_text(json.dumps({"private": True, "workspaces": ["packages/*"]}), encoding="utf-8")
    environment = _environment(tmp_path)
    artifact = _artifact()
    before = _context(workspace, artifact, environment)

    root_manifest.write_text(json.dumps({"private": True, "workspaces": ["packages/app"]}), encoding="utf-8")
    after = _context(workspace, artifact, environment)

    assert _component_digest(before, "workspace_configuration") != _component_digest(
        after,
        "workspace_configuration",
    )


def test_root_yarn_plugin_change_rekeys_nested_workspace_hook_context(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    workspace = repository / "packages" / "app"
    _write_repository(repository)
    workspace.mkdir(parents=True)
    _write_package_files(workspace)
    (repository / "package.json").write_text(
        json.dumps({"private": True, "workspaces": ["packages/*"]}),
        encoding="utf-8",
    )
    plugin = repository / ".yarn" / "plugins" / "guard.cjs"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("module.exports = { name: 'first' };\n", encoding="utf-8")
    environment = _environment(tmp_path)
    artifact = _artifact()
    before = _context(workspace, artifact, environment)

    plugin.write_text("module.exports = { name: 'second' };\n", encoding="utf-8")
    after = _context(workspace, artifact, environment)

    assert before.portable is True
    assert after.portable is True
    assert _component_digest(before, "lifecycle_hooks_overrides_and_patches") != _component_digest(
        after,
        "lifecycle_hooks_overrides_and_patches",
    )


def test_lockfile_executable_and_proxy_environment_each_rekey_context(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_repository(workspace)
    _write_package_files(workspace)
    environment = _environment(tmp_path)
    artifact = _artifact()
    baseline = _context(workspace, artifact, environment)

    (workspace / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\npackages: {}\n", encoding="utf-8")
    lock_changed = _context(workspace, artifact, environment)
    _write_package_files(workspace)
    executable = Path(environment["PATH"]) / "pnpm"
    executable.write_text("#!/bin/sh\n# pnpm-v2\n", encoding="utf-8")
    executable_changed = _context(workspace, artifact, environment)
    proxy_environment = {**environment, "HTTPS_PROXY": "https://proxy.example.test"}
    proxy_changed = _context(workspace, artifact, proxy_environment)

    assert _component_digest(baseline, "manifests_and_lockfiles") != _component_digest(
        lock_changed,
        "manifests_and_lockfiles",
    )
    assert _component_digest(baseline, "package_manager_executable") != _component_digest(
        executable_changed,
        "package_manager_executable",
    )
    assert _component_digest(executable_changed, "environment_policy") != _component_digest(
        proxy_changed,
        "environment_policy",
    )


def test_oversized_or_dynamic_configuration_is_not_portable(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_repository(workspace)
    _write_package_files(workspace)
    environment = _environment(tmp_path)
    artifact = _artifact()
    (workspace / ".npmrc").write_bytes(b"x" * (2 * 1024 * 1024 + 1))

    oversized = _context(workspace, artifact, environment)

    assert oversized.portable is False
    assert oversized.non_portable_reason == "oversized_configuration"
    (workspace / ".npmrc").unlink()
    (workspace / "pnpmfile.cjs").write_text("module.exports = require(resolveHook());\n", encoding="utf-8")
    dynamic = _context(workspace, artifact, environment)
    assert dynamic.portable is False
    assert dynamic.non_portable_reason == "dynamic_manager_configuration"
    runtime_scope = package_request_runtime_workspace_scope(
        artifact_id=artifact.artifact_id,
        artifact_hash="b" * 64,
        artifact_type=artifact.artifact_type,
        execution_context=dynamic,
    )
    assert runtime_scope is not None
    assert runtime_scope.startswith("package-request-workspace-exact:v2:")
    assert (
        package_request_portable_workspace_scope(
            artifact_id=artifact.artifact_id,
            artifact_hash="b" * 64,
            artifact_type=artifact.artifact_type,
            execution_context=dynamic,
        )
        is None
    )
    (workspace / "pnpmfile.cjs").unlink()
    (workspace / "package.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "dependencies": {"left-pad": "1.3.0"},
                "scripts": {"postinstall": "node scripts/setup.js"},
            }
        ),
        encoding="utf-8",
    )
    lifecycle = _context(workspace, artifact, environment)
    assert lifecycle.portable is False
    assert lifecycle.non_portable_reason == "dynamic_lifecycle_hook"


def test_context_evidence_never_contains_configuration_values(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_repository(workspace)
    _write_package_files(workspace)
    environment = _environment(tmp_path)
    environment["NPM_TOKEN"] = "test-registry-credential"
    (workspace / ".npmrc").write_text(
        "//registry.example.test/:_authToken=test-file-credential\n",
        encoding="utf-8",
    )

    evidence = _context(workspace, _artifact(), environment).to_evidence()
    serialized = json.dumps(evidence, sort_keys=True)

    assert "test-registry-credential" not in serialized
    assert "test-file-credential" not in serialized
    assert "registry.example.test" not in serialized


def test_package_project_scope_is_offered_only_for_complete_portable_context(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_repository(workspace)
    _write_package_files(workspace)
    environment = _environment(tmp_path)
    portable = _context(workspace, _artifact(), environment)
    request = {
        "artifact_id": "guard-cli:project:package-request:context-test",
        "artifact_type": "package_request",
        "workspace": str(workspace),
        "scanner_evidence": [portable.to_evidence()],
    }

    assert supported_request_scopes(request) == ("artifact", "workspace")
    nonportable_evidence = {
        **portable.to_evidence(),
        "portable": False,
        "non_portable_reason": "dynamic_manager_configuration",
    }
    assert supported_request_scopes({**request, "scanner_evidence": [nonportable_evidence]}) == ("artifact",)
    assert supported_request_scopes({**request, "scanner_evidence": []}) == ("artifact",)
