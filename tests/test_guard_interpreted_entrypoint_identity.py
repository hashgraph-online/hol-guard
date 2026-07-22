"""Approval identity regressions for local interpreted entrypoints."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
    _runtime_hook_approval_context_token,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash, evaluate_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime import approval_context as approval_context_module
from codex_plugin_scanner.guard.runtime.approval_context import (
    approval_context_tokens_validation_reason,
    build_runtime_launch_identity,
    resolved_runtime_launch_argv,
)
from codex_plugin_scanner.guard.store import GuardStore


def _replace_file(path: Path, content: bytes, *, executable: bool = False) -> None:
    replacement = path.with_name(f"{path.name}.replacement")
    replacement.parent.mkdir(parents=True, exist_ok=True)
    replacement.write_bytes(content)
    if executable:
        replacement.chmod(0o755)
    os.replace(replacement, path)


def _fake_launcher(workspace: Path, name: str) -> Path:
    launcher = workspace / "bin" / name
    _replace_file(launcher, b"fake interpreter binary\n", executable=True)
    return launcher


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return value


def _main_context_token(*, artifact: GuardArtifact, workspace: Path, config: GuardConfig) -> str:
    return _runtime_hook_approval_context_token(
        artifact=artifact,
        content_hash="unchanged-artifact-content",
        runtime_workspace=workspace,
        action_envelope=None,
        config=config,
        current_config_action="review",
        trusted_cli_action=None,
        untrusted_payload_action=None,
        package_action=None,
        data_flow_action=None,
        scanner_action=None,
        current_action="review",
        data_flow_signals=(),
        scanner_evidence=(),
    )


@pytest.mark.parametrize(
    ("launcher_name", "launch_args", "entrypoint_relative"),
    (
        ("python", ("server.py", "--stdio"), "server.py"),
        ("python", ("-m", "localpkg", "--stdio"), "localpkg/__main__.py"),
        ("node", ("server.js", "--stdio"), "server.js"),
        ("bash", ("server.sh", "--stdio"), "server.sh"),
    ),
)
def test_main_runtime_context_rejects_saved_identity_after_only_interpreted_entrypoint_bytes_change(
    tmp_path: Path,
    launcher_name: str,
    launch_args: tuple[str, ...],
    entrypoint_relative: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, launcher_name)
    entrypoint = workspace / entrypoint_relative
    entrypoint.parent.mkdir(parents=True, exist_ok=True)
    _replace_file(entrypoint, b"entrypoint version one\n")
    artifact = GuardArtifact(
        artifact_id=f"codex:project:{launcher_name}-entrypoint",
        name=f"{launcher_name} entrypoint",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=str(launcher),
        args=launch_args,
        transport="stdio",
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )

    approved_token = _main_context_token(artifact=artifact, workspace=workspace, config=config)
    unchanged_token = _main_context_token(artifact=artifact, workspace=workspace, config=config)
    assert approved_token == unchanged_token

    _replace_file(entrypoint, b"entrypoint version two\n")
    changed_token = _main_context_token(artifact=artifact, workspace=workspace, config=config)

    assert changed_token != approved_token
    assert approval_context_tokens_validation_reason(approved_token, changed_token) == (
        "approval_reuse_identity_changed"
    )


def test_unresolved_interpreted_entrypoint_is_non_reusable_even_when_launch_vector_is_unchanged(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, "python")

    first = build_runtime_launch_identity(
        str(launcher),
        args=("missing-server.py",),
        cwd=workspace,
    )
    second = build_runtime_launch_identity(
        str(launcher),
        args=("missing-server.py",),
        cwd=workspace,
    )

    assert first["executable"] == second["executable"]
    assert first["entrypoint"] != second["entrypoint"]
    assert _mapping(first["entrypoint"])["status"] == _mapping(second["entrypoint"])["status"] == "unreadable"
    assert first != second


def test_python_dash_e_module_ignores_pythonpath_and_binds_only_cwd_candidate(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    python_path_root = tmp_path / "python-path"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, "python")
    cwd_entrypoint = workspace / "localpkg" / "__main__.py"
    python_path_entrypoint = python_path_root / "localpkg" / "__main__.py"
    _replace_file(cwd_entrypoint, b"print('cwd module')\n")
    _replace_file(python_path_entrypoint, b"print('pythonpath module one')\n")
    launch_env = {"PYTHONPATH": str(python_path_root), "PYTHONINSPECT": "1"}

    first = build_runtime_launch_identity(
        str(launcher),
        args=("-E", "-m", "localpkg"),
        structured_command=True,
        cwd=workspace,
        launch_env=launch_env,
    )
    entrypoint = _mapping(first["entrypoint"])
    assert entrypoint["status"] == "verified"
    assert entrypoint["path"] == str(cwd_entrypoint.resolve())

    _replace_file(python_path_entrypoint, b"print('pythonpath module two')\n")
    python_path_changed = build_runtime_launch_identity(
        str(launcher),
        args=("-E", "-m", "localpkg"),
        structured_command=True,
        cwd=workspace,
        launch_env=launch_env,
    )
    assert python_path_changed == first

    _replace_file(cwd_entrypoint, b"print('cwd module changed')\n")
    cwd_changed = build_runtime_launch_identity(
        str(launcher),
        args=("-E", "-m", "localpkg"),
        structured_command=True,
        cwd=workspace,
        launch_env=launch_env,
    )
    assert cwd_changed != first


def test_python_dash_e_module_does_not_hash_pythonpath_only_candidate(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    python_path_root = tmp_path / "python-path"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, "python")
    ignored_entrypoint = python_path_root / "externalpkg" / "__main__.py"
    _replace_file(ignored_entrypoint, b"print('ignored module')\n")

    identity = build_runtime_launch_identity(
        str(launcher),
        args=("-E", "-m", "externalpkg"),
        structured_command=True,
        cwd=workspace,
        launch_env={"PYTHONPATH": str(python_path_root)},
    )
    entrypoint = _mapping(identity["entrypoint"])

    assert entrypoint["status"] == "unproven"
    assert entrypoint["reason"] == "module_entrypoint_unresolved"
    assert "path" not in entrypoint
    serialized = json.dumps(identity, sort_keys=True)
    assert str(ignored_entrypoint.resolve()) not in serialized
    assert hashlib.sha256(ignored_entrypoint.read_bytes()).hexdigest() not in serialized


def test_python_isolated_module_resolution_ignores_cwd_and_pythonpath_and_fails_closed(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    python_path_root = tmp_path / "python-path"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, "python")
    _replace_file(workspace / "localpkg" / "__main__.py", b"print('cwd module')\n")
    _replace_file(python_path_root / "localpkg" / "__main__.py", b"print('pythonpath module')\n")
    launch_env = {"PYTHONPATH": str(python_path_root), "PYTHONINSPECT": "1"}

    first = build_runtime_launch_identity(
        str(launcher),
        args=("-I", "-m", "localpkg"),
        structured_command=True,
        cwd=workspace,
        launch_env=launch_env,
    )
    second = build_runtime_launch_identity(
        str(launcher),
        args=("-I", "-m", "localpkg"),
        structured_command=True,
        cwd=workspace,
        launch_env=launch_env,
    )
    entrypoint = _mapping(first["entrypoint"])

    assert entrypoint["status"] == "unproven"
    assert entrypoint["reason"] == "isolated_module_resolution_unproven"
    assert "path" not in entrypoint
    serialized = json.dumps(first, sort_keys=True)
    assert str((workspace / "localpkg" / "__main__.py").resolve()) not in serialized
    assert str((python_path_root / "localpkg" / "__main__.py").resolve()) not in serialized
    assert first != second


def test_structured_executable_path_with_spaces_and_unicode_is_stable_and_content_bound(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace / "runtime dir Δ", "node")
    entrypoint = workspace / "server ü.js"
    _replace_file(entrypoint, b"console.log('one');\n")

    first = build_runtime_launch_identity(
        str(launcher),
        args=(entrypoint.name,),
        structured_command=True,
        cwd=workspace,
    )
    unchanged = build_runtime_launch_identity(
        str(launcher),
        args=(entrypoint.name,),
        structured_command=True,
        cwd=workspace,
    )

    assert first == unchanged
    assert _mapping(first["executable"])["path"] == str(launcher.resolve())
    assert _mapping(first["entrypoint"])["path"] == str(entrypoint.resolve())

    _replace_file(entrypoint, b"console.log('two');\n")
    changed = build_runtime_launch_identity(
        str(launcher),
        args=(entrypoint.name,),
        structured_command=True,
        cwd=workspace,
    )
    assert changed != first


def test_inline_launch_identity_is_opaque_stable_and_secret_change_bound(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, "bash")
    first_secret = "password=approval-context-one"
    second_secret = "password=approval-context-two"

    first = build_runtime_launch_identity(
        str(launcher),
        args=("-c", f"printf %s {first_secret}"),
        structured_command=True,
        cwd=workspace,
    )
    unchanged = build_runtime_launch_identity(
        str(launcher),
        args=("-c", f"printf %s {first_secret}"),
        structured_command=True,
        cwd=workspace,
    )
    changed = build_runtime_launch_identity(
        str(launcher),
        args=("-c", f"printf %s {second_secret}"),
        structured_command=True,
        cwd=workspace,
    )

    serialized = json.dumps(first, sort_keys=True)
    assert first == unchanged
    assert first != changed
    assert first_secret not in serialized
    assert second_secret not in serialized


def test_main_runtime_context_handles_structured_mcp_executable_path_with_spaces(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace / "runtime dir Δ", "node")
    entrypoint = workspace / "server ü.js"
    _replace_file(entrypoint, b"console.log('one');\n")
    artifact = GuardArtifact(
        artifact_id="codex:project:spaced-mcp-server",
        name="spaced MCP server",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=str(launcher),
        args=(entrypoint.name,),
        transport="stdio",
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace, default_action="review")

    first = _main_context_token(artifact=artifact, workspace=workspace, config=config)
    unchanged = _main_context_token(artifact=artifact, workspace=workspace, config=config)
    assert first == unchanged

    _replace_file(entrypoint, b"console.log('two');\n")
    assert _main_context_token(artifact=artifact, workspace=workspace, config=config) != first


def test_main_runtime_context_binds_configured_environment_values_without_exposing_them(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, "node")
    entrypoint = workspace / "server.js"
    _replace_file(entrypoint, b"console.log('server');\n")
    first_secret = "configured-secret-value-one"
    second_secret = "configured-secret-value-two"
    artifact = GuardArtifact(
        artifact_id="codex:project:environment-bound-mcp-server",
        name="environment-bound MCP server",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=str(launcher),
        args=(entrypoint.name,),
        transport="stdio",
        metadata={"env": {"TOKEN": first_secret}, "env_keys": ["TOKEN"]},
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace, default_action="review")

    first = _main_context_token(artifact=artifact, workspace=workspace, config=config)
    unchanged = _main_context_token(artifact=artifact, workspace=workspace, config=config)
    changed = _main_context_token(
        artifact=replace(artifact, metadata={"env": {"TOKEN": second_secret}, "env_keys": ["TOKEN"]}),
        workspace=workspace,
        config=config,
    )

    assert first == unchanged
    assert changed != first
    assert first_secret not in first
    assert second_secret not in changed


def test_unavailable_code_loading_environment_value_disables_main_context_reuse(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, "node")
    entrypoint = workspace / "server.js"
    _replace_file(entrypoint, b"console.log('server');\n")
    artifact = GuardArtifact(
        artifact_id="claude-code:project:hidden-node-options",
        name="hidden NODE_OPTIONS MCP server",
        harness="claude-code",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace / ".mcp.json"),
        command=str(launcher),
        args=(entrypoint.name,),
        transport="stdio",
        metadata={"env_keys": ["NODE_OPTIONS"], "env_values_hash": "a" * 64},
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace, default_action="review")

    first = _main_context_token(artifact=artifact, workspace=workspace, config=config)
    second = _main_context_token(artifact=artifact, workspace=workspace, config=config)

    assert first != second


@pytest.mark.parametrize(
    ("launcher_name", "launch_args", "launch_env"),
    (
        ("python", ("-i", "server.py"), {}),
        ("python", ("server.py",), {"PYTHONINSPECT": "1"}),
        ("python", ("-X", "presite=local_bootstrap", "server.py"), {}),
        ("node", ("--require", "./preload.js", "server.js"), {}),
        ("node", ("server.js",), {"NODE_OPTIONS": "--require ./preload.js"}),
        ("bash", ("--rcfile", "bootstrap.sh", "server.sh"), {}),
        ("bash", ("-i", "server.sh"), {}),
    ),
)
def test_unbound_interactive_or_code_loading_options_disable_reuse(
    tmp_path: Path,
    launcher_name: str,
    launch_args: tuple[str, ...],
    launch_env: dict[str, str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, launcher_name)
    for filename in ("server.py", "server.js", "server.sh", "preload.js", "bootstrap.sh"):
        _replace_file(workspace / filename, b"entrypoint\n")

    first = build_runtime_launch_identity(
        str(launcher),
        args=launch_args,
        structured_command=True,
        cwd=workspace,
        launch_env=launch_env,
    )
    second = build_runtime_launch_identity(
        str(launcher),
        args=launch_args,
        structured_command=True,
        cwd=workspace,
        launch_env=launch_env,
    )

    assert _mapping(first["entrypoint"])["status"] == "unproven"
    assert first != second


def test_direct_env_shebang_binds_path_selected_interpreter_and_fails_closed_when_unresolved(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    first_bin = workspace / "first-bin"
    second_bin = workspace / "second-bin"
    first_bin.mkdir(parents=True)
    second_bin.mkdir(parents=True)
    direct_script = workspace / "server"
    _replace_file(direct_script, b"#!/usr/bin/env python\nprint('server')\n", executable=True)
    first_interpreter = first_bin / "python"
    second_interpreter = second_bin / "python"
    _replace_file(first_interpreter, b"fake python runtime\n", executable=True)
    _replace_file(second_interpreter, b"fake python runtime\n", executable=True)

    first_env = {"PATH": str(first_bin)}
    first = build_runtime_launch_identity(
        str(direct_script),
        cwd=workspace,
        launch_env=first_env,
    )
    unchanged = build_runtime_launch_identity(
        str(direct_script),
        cwd=workspace,
        launch_env=first_env,
    )
    assert first == unchanged
    first_entrypoint = _mapping(first["entrypoint"])
    assert first_entrypoint["status"] == "verified"
    assert _mapping(first_entrypoint["interpreter"])["path"] == str(first_interpreter.resolve())

    _replace_file(first_interpreter, b"evil python runtime\n", executable=True)
    changed_interpreter = build_runtime_launch_identity(
        str(direct_script),
        cwd=workspace,
        launch_env=first_env,
    )
    assert changed_interpreter != first

    changed_path = build_runtime_launch_identity(
        str(direct_script),
        cwd=workspace,
        launch_env={"PATH": str(second_bin)},
    )
    assert changed_path != first
    changed_path_entrypoint = _mapping(changed_path["entrypoint"])
    assert _mapping(changed_path_entrypoint["interpreter"])["path"] == str(second_interpreter.resolve())

    unresolved_first = build_runtime_launch_identity(
        str(direct_script),
        cwd=workspace,
        launch_env={"PATH": str(workspace / "empty-bin")},
    )
    unresolved_second = build_runtime_launch_identity(
        str(direct_script),
        cwd=workspace,
        launch_env={"PATH": str(workspace / "empty-bin")},
    )
    assert _mapping(unresolved_first["entrypoint"])["status"] == "unproven"
    assert unresolved_first != unresolved_second


def test_direct_package_script_launch_argv_pins_verified_env_interpreter(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    runtime_bin = workspace / "runtime-bin"
    runtime_bin.mkdir(parents=True)
    interpreter = runtime_bin / "python3"
    _replace_file(interpreter, b"fake python runtime\n", executable=True)
    manager = workspace / "npm"
    _replace_file(manager, b"#!/usr/bin/env python3\nprint('manager')\n", executable=True)
    identity = build_runtime_launch_identity(
        str(manager),
        args=("install", "demo"),
        structured_command=True,
        direct_executable=True,
        cwd=workspace,
        launch_env={"PATH": str(runtime_bin)},
    )

    pinned = resolved_runtime_launch_argv(identity, args=("install", "demo"))

    assert pinned == (
        str(interpreter.resolve()),
        str(manager.resolve()),
        "install",
        "demo",
    )


def test_direct_package_script_launch_argv_fails_closed_for_unbound_nested_preload(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    runtime_bin = workspace / "runtime-bin"
    runtime_bin.mkdir(parents=True)
    interpreter = runtime_bin / "node"
    _replace_file(interpreter, b"fake node runtime\n", executable=True)
    manager = workspace / "npm"
    _replace_file(
        manager,
        b"#!/usr/bin/env -S node --require ./preload.js\n",
        executable=True,
    )
    _replace_file(workspace / "preload.js", b"module.exports = {};\n")

    identity = build_runtime_launch_identity(
        str(manager),
        structured_command=True,
        direct_executable=True,
        cwd=workspace,
        launch_env={"PATH": str(runtime_bin)},
    )

    assert _mapping(identity["entrypoint"])["status"] == "unproven"
    assert resolved_runtime_launch_argv(identity) is None


def test_launch_identity_never_exposes_raw_shebang_arguments(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    runtime_bin = workspace / "bin"
    runtime_bin.mkdir(parents=True)
    interpreter = runtime_bin / "python"
    _replace_file(interpreter, b"fake python runtime\n", executable=True)
    secret = "guard-shebang-secret-42"
    direct_script = workspace / "server"
    _replace_file(
        direct_script,
        f"#!/usr/bin/env -S python -u --api-key={secret}\nprint('server')\n".encode(),
        executable=True,
    )

    executable_identity = approval_context_module.build_runtime_executable_identity(str(direct_script))
    launch_identity = build_runtime_launch_identity(
        str(direct_script),
        cwd=workspace,
        launch_env={"PATH": str(runtime_bin)},
    )
    serialized = json.dumps(
        {"executable": executable_identity, "launch": launch_identity},
        sort_keys=True,
    )

    assert secret not in serialized
    assert "shebang" not in executable_identity
    assert "shebang_sha256" in executable_identity


def test_executable_hash_rechecks_descriptor_metadata_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "racing-tool"
    _replace_file(executable, b"#!/bin/sh\nexit 0\n", executable=True)
    real_fstat = os.fstat
    fstat_calls = 0

    def racing_fstat(descriptor: int) -> object:
        nonlocal fstat_calls
        observed = real_fstat(descriptor)
        fstat_calls += 1
        if fstat_calls < 2:
            return observed
        return SimpleNamespace(
            st_dev=observed.st_dev,
            st_ino=observed.st_ino,
            st_size=observed.st_size,
            st_mtime_ns=observed.st_mtime_ns,
            st_ctime_ns=observed.st_ctime_ns + 1,
            st_mode=observed.st_mode,
        )

    approval_context_module._cached_executable_hash.cache_clear()
    monkeypatch.setattr(approval_context_module.os, "fstat", racing_fstat)
    identity = approval_context_module.build_runtime_executable_identity(str(executable))

    assert identity["status"] == "identity_raced"
    assert "sha256" not in identity
    assert "reuse_nonce" in identity
    approval_context_module._cached_executable_hash.cache_clear()


def test_consumer_saved_allow_is_rejected_after_only_node_entrypoint_bytes_change(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = _fake_launcher(workspace, "node")
    entrypoint = workspace / "server.js"
    _replace_file(entrypoint, b"console.log('version one');\n")
    artifact = GuardArtifact(
        artifact_id="codex:project:consumer-node-entrypoint",
        name="consumer node entrypoint",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=str(launcher),
        args=("server.js", "--stdio"),
        transport="stdio",
        metadata={
            "action_class": "interpreted entrypoint identity proof",
            "guard_default_action": "review",
        },
    )
    detection = HarnessDetection(
        harness=artifact.harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    store = GuardStore(config.guard_home)
    initial_artifact_hash = artifact_hash(artifact)

    initial = evaluate_detection(detection, store, config, persist=False)
    approved_token = str(initial["artifacts"][0]["approval_context_hash"])
    approval_id = store.record_local_once_approval(
        request_id="consumer-node-entrypoint-v1",
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=approved_token,
        workspace=str(workspace.resolve()),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None

    unchanged = evaluate_detection(detection, store, config, persist=False)
    unchanged_item = unchanged["artifacts"][0]
    assert unchanged_item["approval_context_hash"] == approved_token
    assert unchanged_item["policy_action"] == "allow"
    assert unchanged_item["approval_reuse_status"] == "accepted"

    _replace_file(entrypoint, b"console.log('version two');\n")
    changed = evaluate_detection(detection, store, config, persist=False)
    changed_item = changed["artifacts"][0]

    assert artifact_hash(artifact) == initial_artifact_hash
    assert changed_item["approval_context_hash"] != approved_token
    assert changed_item["policy_action"] == "review"
    assert changed_item["approval_reuse_status"] == "rejected"
    assert changed_item["approval_reuse_reason_code"] == "approval_reuse_identity_changed"
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=approved_token,
            workspace=str(workspace.resolve()),
            publisher=None,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )
