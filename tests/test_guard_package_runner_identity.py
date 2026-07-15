from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.package_shim_gate import package_shim_command_requires_guard
from codex_plugin_scanner.guard.runtime import package_intent_parser
from codex_plugin_scanner.guard.runtime.package_intent_common import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent


def _write_executable(path: Path, marker: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\n# {marker}\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)


def _write_workspace(workspace: Path, *, symlink_runner: bool = False) -> Path:
    (workspace / "package.json").write_text(
        '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n',
        encoding="utf-8",
    )
    (workspace / "bun.lock").write_text('"vitest": "4.1.8"\n', encoding="utf-8")
    runner = workspace / "node_modules" / ".bin" / "vitest"
    if symlink_runner:
        target = workspace / "node_modules" / "vitest" / "cli.js"
        _write_executable(target, "runner-v1")
        runner.parent.mkdir(parents=True)
        runner.symlink_to(Path("..") / "vitest" / "cli.js")
        return target
    _write_executable(runner, "runner-v1")
    return runner


def _artifact(command: str, workspace: Path):
    intent = parse_package_intent(command, workspace=workspace)
    assert intent is not None
    return build_package_request_artifact(
        "codex",
        intent,
        config_path="runtime",
        source_scope="project",
    )


@pytest.mark.parametrize(
    "wrapper",
    ["{assignment} bunx", "env {assignment} bunx", "time {assignment} bunx"],
)
def test_local_package_runner_uses_command_effective_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wrapper: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_workspace(workspace)
    home_dir = tmp_path / "home"
    guard_shim = home_dir / ".hol-guard" / "package-shims" / "bin" / "bunx"
    direct_manager = tmp_path / "direct-bin" / "bunx"
    _write_executable(guard_shim, "guard-shim")
    _write_executable(direct_manager, "direct-manager")
    monkeypatch.setattr(package_intent_parser.Path, "home", classmethod(lambda cls: home_dir))
    monkeypatch.setenv("PATH", os.pathsep.join((str(guard_shim.parent), str(direct_manager.parent))))
    command = f"{wrapper.format(assignment=f'PATH={direct_manager.parent}')} vitest --help"

    intent = parse_package_intent(command, workspace=workspace)

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.path_source in {"inline", "env"}
    assert evidence.manager is not None
    assert evidence.manager.resolved_path == str(direct_manager.resolve())
    assert evidence.manager_is_guard_shim is False


def test_local_package_runner_resolves_relative_path_from_env_cwd(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_workspace(workspace)
    manager = workspace / "tools" / "bin" / "bunx"
    _write_executable(manager, "manager")

    intent = parse_package_intent(
        "env -C tools PATH=bin bunx --no-install vitest --help",
        workspace=workspace,
    )

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.effective_cwd == str((workspace / "tools").resolve())
    assert evidence.cwd_source == "env_chdir"
    assert evidence.manager is not None
    assert evidence.manager.resolved_path == str(manager.resolve())


def test_local_package_runner_tracks_shell_cd_and_nested_project_context(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = workspace / "packages" / "tool"
    project.mkdir(parents=True)
    runner = _write_workspace(project)
    manager = project / "tools" / "bin" / "bunx"
    _write_executable(manager, "manager")

    intent = parse_package_intent(
        "cd packages/tool && PATH=tools/bin bunx --no-install vitest --help",
        workspace=workspace,
    )

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.effective_cwd == str(project.resolve())
    assert evidence.cwd_source == "shell_cd"
    assert evidence.manager is not None
    assert evidence.manager.resolved_path == str(manager.resolve())
    assert evidence.local_executable is not None
    assert evidence.local_executable.resolved_path == str(runner.resolve())
    assert evidence.declared_version == "^4.1.8"
    assert evidence.manifests[0].path == "packages/tool/package.json"


def test_env_search_path_option_resolves_the_executed_manager(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_workspace(workspace)
    manager = tmp_path / "manager-bin" / "npx"
    _write_executable(manager, "manager")

    intent = parse_package_intent(
        f"env -P {manager.parent} npx --no-install vitest --help",
        workspace=workspace,
    )

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.path_source == "env_search_path"
    assert evidence.manager is not None
    assert evidence.manager.resolved_path == str(manager.resolve())


@pytest.mark.parametrize("option", ["-S", "--split-string"])
def test_env_split_string_preserves_package_runner_identity(
    tmp_path: Path,
    option: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_workspace(workspace)
    manager = tmp_path / "manager-bin" / "npx"
    _write_executable(manager, "manager")

    intent = parse_package_intent(
        f'env {option} "PATH={manager.parent} npx --no-install vitest --help"',
        workspace=workspace,
    )

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.path_source == "env"
    assert evidence.manager is not None
    assert evidence.manager.resolved_path == str(manager.resolve())


def test_local_runner_outside_workspace_uses_node_ancestor_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external_project = tmp_path / "external-project"
    external_project.mkdir()
    runner = _write_workspace(external_project)
    nested_cwd = external_project / "packages" / "demo"
    nested_cwd.mkdir(parents=True)
    manager = tmp_path / "bin" / "npx"
    _write_executable(manager, "manager")
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent(
        f"env -C {nested_cwd} npx --no-install vitest --help",
        workspace=workspace,
    )

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.local_executable is not None
    assert evidence.local_executable.resolved_path == str(runner.resolve())
    assert evidence.declared_version == "^4.1.8"


def test_repository_local_runner_inputs_require_review_and_are_recorded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = _write_workspace(workspace)
    manager = tmp_path / "bin" / "bunx"
    _write_executable(manager, "manager")
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent("bunx --no-install vitest --help", workspace=workspace)

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.local_only_requested is True
    assert evidence.declared_version == "^4.1.8"
    assert evidence.local_executable is not None
    assert evidence.local_executable.resolved_path == str(runner.resolve())
    assert evidence.local_executable.content_hash is not None
    assert evidence.manifests[0].content_hash is not None
    assert evidence.lockfiles[0].content_hash is not None
    artifact = build_package_request_artifact(
        "codex",
        intent,
        config_path="runtime",
        source_scope="project",
    )
    assert str(manager.resolve()) in artifact.metadata["request_summary"]
    assert artifact.metadata["runtime_request_reason_code"] == "local_package_execution_review"
    assert "Unchanged exact executions reuse" in artifact.metadata["runtime_request_remediation_hint"]


def test_unchanged_local_execution_has_stable_approval_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_workspace(workspace, symlink_runner=True)
    manager = tmp_path / "bin" / "npx"
    _write_executable(manager, "manager")
    monkeypatch.setenv("PATH", str(manager.parent))

    first = _artifact("npx --no-install vitest --help", workspace)
    second = _artifact("npx --no-install vitest --help", workspace)

    assert first.artifact_id == second.artifact_id


@pytest.mark.parametrize("changed_input", ["manager", "runner", "manifest", "lockfile"])
def test_local_execution_change_requires_a_new_approval_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_input: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner_target = _write_workspace(workspace, symlink_runner=True)
    manager = tmp_path / "bin" / "npx"
    _write_executable(manager, "manager-v1")
    monkeypatch.setenv("PATH", str(manager.parent))
    first = _artifact("npx --no-install vitest --help", workspace)

    if changed_input == "manager":
        _write_executable(manager, "manager-v2")
    elif changed_input == "runner":
        _write_executable(runner_target, "runner-v2")
    elif changed_input == "manifest":
        (workspace / "package.json").write_text(
            '{"name":"demo","devDependencies":{"vitest":"^4.2.0"}}\n',
            encoding="utf-8",
        )
    else:
        (workspace / "bun.lock").write_text('"vitest": "4.2.0"\n', encoding="utf-8")

    second = _artifact("npx --no-install vitest --help", workspace)

    assert first.artifact_id != second.artifact_id


def test_unresolved_command_path_still_requires_review(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_workspace(workspace)

    intent = parse_package_intent("PATH=$UNKNOWN_PATH bunx --no-install vitest --help", workspace=workspace)

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.path_source == "inline_unresolved"
    assert evidence.manager is None


def test_unresolved_context_changes_cannot_reuse_an_approval_identity(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_workspace(workspace)

    first = _artifact("PATH=$FIRST_UNKNOWN bunx --no-install vitest --help", workspace)
    second = _artifact("PATH=$SECOND_UNKNOWN bunx --no-install vitest --help", workspace)

    assert first.artifact_id != second.artifact_id


def test_scoped_package_uses_installed_single_bin_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        '{"name":"demo","devDependencies":{"@scope/tool":"1.2.3"}}\n',
        encoding="utf-8",
    )
    package_dir = workspace / "node_modules" / "@scope" / "tool"
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text(
        '{"name":"@scope/tool","bin":{"tool-run":"cli.js"}}\n',
        encoding="utf-8",
    )
    target = package_dir / "cli.js"
    _write_executable(target, "scoped-runner")
    shim = workspace / "node_modules" / ".bin" / "tool-run"
    shim.parent.mkdir(parents=True)
    shim.symlink_to(Path("..") / "@scope" / "tool" / "cli.js")
    manager = tmp_path / "bin" / "npx"
    _write_executable(manager, "manager")
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent("npx --no-install @scope/tool --help", workspace=workspace)

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.package_name == "@scope/tool"
    assert evidence.executable_name == "tool-run"
    assert evidence.declared_version == "1.2.3"
    assert evidence.local_executable is not None
    assert evidence.local_executable.resolved_path == str(target.resolve())


def test_bin_symlink_retargeting_changes_approval_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n',
        encoding="utf-8",
    )
    first_target = workspace / "node_modules" / "first" / "cli.js"
    second_target = workspace / "node_modules" / "second" / "cli.js"
    _write_executable(first_target, "same-content")
    _write_executable(second_target, "same-content")
    runner = workspace / "node_modules" / ".bin" / "vitest"
    runner.parent.mkdir(parents=True)
    runner.symlink_to(Path("..") / "first" / "cli.js")
    manager = tmp_path / "bin" / "npx"
    _write_executable(manager, "manager")
    monkeypatch.setenv("PATH", str(manager.parent))
    first = _artifact("npx --no-install vitest --help", workspace)

    runner.unlink()
    runner.symlink_to(Path("..") / "second" / "cli.js")
    second = _artifact("npx --no-install vitest --help", workspace)

    assert first.artifact_id != second.artifact_id


@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_package_shim_routes_local_only_execution_through_guard(tmp_path: Path, manager: str) -> None:
    _write_workspace(tmp_path)

    assert package_shim_command_requires_guard(
        manager,
        ("--no-install", "vitest", "--help"),
        workspace=tmp_path,
    )
