"""Executable and MCP configuration binding regressions for hook approvals."""

from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli import commands_support as _commands_support  # noqa: F401
from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import _copilot_runtime_tool_call
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import evaluate_tool_call
from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.approval_context import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    approval_context_tokens_validation_reason,
)
from codex_plugin_scanner.guard.store import GuardStore

_GENERIC_HARNESS = "generic-executable-test"
_GENERIC_ARTIFACT_ID = "generic-executable-test:project:server"


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _replace_executable(path: Path, content: bytes) -> None:
    replacement = path.with_name(f"{path.name}.replacement")
    replacement.parent.mkdir(parents=True, exist_ok=True)
    replacement.write_bytes(content)
    replacement.chmod(0o755)
    replacement.replace(path)


def _replace_file(path: Path, content: bytes) -> None:
    replacement = path.with_name(f"{path.name}.replacement")
    replacement.parent.mkdir(parents=True, exist_ok=True)
    replacement.write_bytes(content)
    replacement.replace(path)


def _run_generic_hook(
    *,
    capsys: pytest.CaptureFixture[str],
    config: GuardConfig,
    payload: dict[str, object],
    store: GuardStore,
    workspace: Path,
    action_envelope: GuardActionEnvelope | None = None,
) -> tuple[int, dict[str, object]]:
    args = argparse.Namespace(
        artifact_id=None,
        artifact_name=None,
        harness=_GENERIC_HARNESS,
        json=True,
        policy_action=None,
    )
    rc = _run_hook_generic_payload(
        args,
        action_envelope=action_envelope,
        config=config,
        home_dir=workspace.parent,
        payload=payload,
        runtime_workspace=workspace,
        store=store,
    )
    output = json.loads(capsys.readouterr().out)
    assert isinstance(output, dict)
    return rc, cast(dict[str, object], output)


def _approval_reuse_reason(output: dict[str, object]) -> str:
    approval_reuse = output.get("approval_reuse")
    assert isinstance(approval_reuse, dict)
    reason = approval_reuse.get("reason_code")
    assert isinstance(reason, str)
    return reason


def _record_generic_allow(
    store: GuardStore,
    *,
    artifact_hash: str,
    request_id: str,
    workspace: Path,
) -> None:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=_GENERIC_HARNESS,
        artifact_id=_GENERIC_ARTIFACT_ID,
        artifact_hash=artifact_hash,
        workspace=str(workspace),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None


def _generic_server_payload(command: str) -> dict[str, object]:
    return {
        "artifact_id": _GENERIC_ARTIFACT_ID,
        "artifact_name": "workspace server",
        "hook_event_name": "OpaqueHookEvent",
        "source_scope": "project",
        "tool_name": "shell",
        "tool_input": {"command": command},
    }


def _generic_server_action_envelope(command: str, *, workspace: Path) -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness=_GENERIC_HARNESS,
        event_name="PreToolUse",
        action_type="shell_command",
        workspace=str(workspace),
        workspace_hash=None,
        tool_name="shell",
        command=command,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
    )


def test_generic_hook_rejects_exact_allow_after_same_path_executable_replacement(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    outside_cwd = tmp_path / "outside"
    workspace.mkdir()
    outside_cwd.mkdir()
    server = workspace / "server"
    _replace_executable(server, b"#!/bin/sh\necho version-one\n")
    monkeypatch.chdir(outside_cwd)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    payload = _generic_server_payload("./server --stdio")
    action_envelope = _generic_server_action_envelope("./server --stdio", workspace=workspace)

    first_rc, first_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
        action_envelope=action_envelope,
    )
    approved_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    assert first_rc == 1
    assert first_output["policy_action"] == "review"
    assert approved_token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    _record_generic_allow(
        store,
        artifact_hash=approved_token,
        request_id="generic-server-v1",
        workspace=workspace,
    )

    _replace_executable(server, b"#!/bin/sh\necho version-two\n")
    second_rc, second_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
        action_envelope=action_envelope,
    )

    assert second_rc == 1
    assert second_output["policy_action"] == "review"
    assert _approval_reuse_reason(second_output) == "approval_reuse_identity_changed"
    current_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    assert approval_context_tokens_validation_reason(approved_token, current_token) == (
        "approval_reuse_identity_changed"
    )
    assert (
        store.resolve_policy_decision(
            _GENERIC_HARNESS,
            _GENERIC_ARTIFACT_ID,
            approved_token,
            str(workspace),
            consume_one_shot=False,
        )
        is not None
    )


@pytest.mark.parametrize(
    ("launcher_name", "entrypoint_name", "version_one", "version_two"),
    (
        ("python", "server.py", b"print('version one')\n", b"print('version two')\n"),
        ("node", "server.js", b"console.log('version one');\n", b"console.log('version two');\n"),
    ),
)
def test_generic_hook_rejects_exact_allow_after_only_interpreted_entrypoint_changes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    launcher_name: str,
    entrypoint_name: str,
    version_one: bytes,
    version_two: bytes,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = workspace / launcher_name
    entrypoint = workspace / entrypoint_name
    _replace_executable(launcher, b"fake native interpreter\n")
    _replace_file(entrypoint, version_one)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    command = f"./{launcher_name} {entrypoint_name} --stdio"
    payload = _generic_server_payload(command)
    action_envelope = _generic_server_action_envelope(command, workspace=workspace)

    _, first_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
        action_envelope=action_envelope,
    )
    approved_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    assert first_output["policy_action"] == "review"
    _record_generic_allow(
        store,
        artifact_hash=approved_token,
        request_id=f"generic-{launcher_name}-entrypoint-v1",
        workspace=workspace,
    )

    _replace_file(entrypoint, version_two)
    second_rc, second_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
        action_envelope=action_envelope,
    )

    current_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    assert second_rc == 1
    assert second_output["policy_action"] == "review"
    assert _approval_reuse_reason(second_output) == "approval_reuse_identity_changed"
    assert approval_context_tokens_validation_reason(approved_token, current_token) == (
        "approval_reuse_identity_changed"
    )


def test_generic_hook_resolved_interpreter_with_missing_entrypoint_never_reuses_allow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _replace_executable(workspace / "python", b"fake native interpreter\n")
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    command = "./python missing-server.py --stdio"
    payload = _generic_server_payload(command)
    action_envelope = _generic_server_action_envelope(command, workspace=workspace)

    _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
        action_envelope=action_envelope,
    )
    approved_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    _record_generic_allow(
        store,
        artifact_hash=approved_token,
        request_id="generic-python-missing-entrypoint",
        workspace=workspace,
    )

    second_rc, second_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
        action_envelope=action_envelope,
    )
    current_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])

    assert second_rc == 1
    assert second_output["policy_action"] == "review"
    assert _approval_reuse_reason(second_output) == "approval_reuse_identity_changed"
    assert approved_token != current_token


def test_generic_hook_unresolved_executable_never_reuses_exact_allow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    payload = _generic_server_payload("./missing-server --stdio")

    _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    approved_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    _record_generic_allow(
        store,
        artifact_hash=approved_token,
        request_id="generic-unresolved-server",
        workspace=workspace,
    )

    second_rc, second_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    current_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])

    assert second_rc == 1
    assert second_output["policy_action"] == "review"
    assert _approval_reuse_reason(second_output) == "approval_reuse_identity_changed"
    assert approved_token != current_token
    assert (
        store.resolve_policy_decision(
            _GENERIC_HARNESS,
            _GENERIC_ARTIFACT_ID,
            approved_token,
            str(workspace),
            consume_one_shot=False,
        )
        is not None
    )


def _copilot_server_config(command: str = "./server") -> dict[str, object]:
    return {
        "type": "local",
        "command": command,
        "args": ["--stdio", "--safe-mode"],
        "env": {"SERVER_TOKEN": "version-one"},
        "metadata": {"revision": 1},
        "tools": {
            "shell_exec": {
                "description": "Execute a reviewed shell command.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            }
        },
    }


def _resolve_copilot_tool(
    *,
    config: GuardConfig,
    home_dir: Path,
    workspace: Path,
) -> tuple[GuardArtifact, str, object]:
    resolved = _copilot_runtime_tool_call(
        payload={
            "tool_name": "mcp_danger_lab_shell_exec",
            "tool_input": {"command": "rm relative-target"},
            "source_scope": "project",
        },
        home_dir=home_dir,
        workspace=workspace,
        config=config,
        preferred_workspace_config="ide",
    )
    assert resolved is not None
    return resolved


def test_copilot_mcp_exact_allow_is_invalid_after_server_executable_bytes_change(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    server = workspace / "server"
    _replace_executable(server, b"#!/bin/sh\necho copilot-server-v1\n")
    _write_json(
        workspace / ".vscode" / "mcp.json",
        {"servers": {"danger_lab": _copilot_server_config()}},
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    old_artifact, old_token, arguments = _resolve_copilot_tool(
        config=config,
        home_dir=home_dir,
        workspace=workspace,
    )
    unchanged_artifact, unchanged_token, _ = _resolve_copilot_tool(
        config=config,
        home_dir=home_dir,
        workspace=workspace,
    )
    assert old_token == unchanged_token
    assert old_artifact == unchanged_artifact
    metadata = old_artifact.metadata
    fingerprint = metadata.get("server_fingerprint")
    assert isinstance(fingerprint, dict)
    launch_identity = fingerprint.get("resolved_executable")
    assert isinstance(launch_identity, dict)
    executable_identity = launch_identity.get("executable")
    assert isinstance(executable_identity, dict)
    assert executable_identity["path"] == str(server.resolve())
    assert executable_identity["sha256"] == hashlib.sha256(server.read_bytes()).hexdigest()
    assert launch_identity["argv_sha256"]
    assert launch_identity["entrypoint"]
    server_identity = metadata.get("mcp_server_identity")
    assert isinstance(server_identity, dict)
    assert server_identity["transport"] == "stdio"
    assert server_identity["env_keys"] == ["SERVER_TOKEN"]
    assert isinstance(server_identity["env_values_hash"], str)
    assert "version-one" not in json.dumps(metadata, sort_keys=True)
    assert metadata["tool_description"] == "Execute a reviewed shell command."
    tool_schema = metadata.get("tool_schema")
    assert isinstance(tool_schema, dict)
    assert tool_schema["required"] == ["command"]

    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="copilot",
            scope="artifact",
            action="allow",
            artifact_id=old_artifact.artifact_id,
            artifact_hash=old_token,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    _replace_executable(server, b"#!/bin/sh\necho copilot-server-v2\n")
    new_artifact, new_token, _ = _resolve_copilot_tool(
        config=config,
        home_dir=home_dir,
        workspace=workspace,
    )

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=new_artifact,
        artifact_hash=new_token,
        arguments=arguments,
    )

    assert old_artifact.artifact_id == new_artifact.artifact_id
    assert approval_context_tokens_validation_reason(old_token, new_token) == "approval_reuse_identity_changed"
    assert decision.current_action == "review"
    assert decision.action == "review"
    assert decision.approval_reuse_reason_code == "approval_reuse_identity_changed"


def test_copilot_mcp_exact_allow_is_invalid_after_only_python_entrypoint_bytes_change(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = workspace / "python"
    entrypoint = workspace / "server.py"
    _replace_executable(launcher, b"fake native python interpreter\n")
    _replace_file(entrypoint, b"print('copilot server v1')\n")
    configured_secret = "copilot-env-secret-must-not-leak"
    server_config = _copilot_server_config(command="./python")
    server_config["args"] = ["server.py", "--stdio"]
    server_config["env"] = {"SERVER_TOKEN": configured_secret}
    _write_json(
        workspace / ".vscode" / "mcp.json",
        {"servers": {"danger_lab": server_config}},
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )

    old_artifact, old_token, arguments = _resolve_copilot_tool(
        config=config,
        home_dir=home_dir,
        workspace=workspace,
    )
    unchanged_artifact, unchanged_token, _ = _resolve_copilot_tool(
        config=config,
        home_dir=home_dir,
        workspace=workspace,
    )
    assert old_token == unchanged_token
    assert old_artifact == unchanged_artifact
    fingerprint = old_artifact.metadata.get("server_fingerprint")
    assert isinstance(fingerprint, dict)
    launch_identity = fingerprint.get("resolved_executable")
    assert isinstance(launch_identity, dict)
    executable_identity = launch_identity.get("executable")
    entrypoint_identity = launch_identity.get("entrypoint")
    assert isinstance(executable_identity, dict)
    assert isinstance(entrypoint_identity, dict)
    assert executable_identity["path"] == str(launcher.resolve())
    assert entrypoint_identity["path"] == str(entrypoint.resolve())
    assert entrypoint_identity["sha256"] == hashlib.sha256(entrypoint.read_bytes()).hexdigest()
    serialized_metadata = json.dumps(old_artifact.metadata, sort_keys=True)
    assert configured_secret not in serialized_metadata
    server_identity = old_artifact.metadata.get("mcp_server_identity")
    assert isinstance(server_identity, dict)
    assert server_identity["env_keys"] == ["SERVER_TOKEN"]
    assert isinstance(server_identity["env_values_hash"], str)

    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="copilot",
            scope="artifact",
            action="allow",
            artifact_id=old_artifact.artifact_id,
            artifact_hash=old_token,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    _replace_file(entrypoint, b"print('copilot server v2')\n")
    new_artifact, new_token, _ = _resolve_copilot_tool(
        config=config,
        home_dir=home_dir,
        workspace=workspace,
    )

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=new_artifact,
        artifact_hash=new_token,
        arguments=arguments,
    )

    assert old_artifact.artifact_id == new_artifact.artifact_id
    assert approval_context_tokens_validation_reason(old_token, new_token) == "approval_reuse_identity_changed"
    assert decision.current_action == "review"
    assert decision.action == "review"
    assert decision.approval_reuse_reason_code == "approval_reuse_identity_changed"
    assert configured_secret not in json.dumps(new_artifact.metadata, sort_keys=True)


@pytest.mark.parametrize(
    "change",
    ["command", "full_config", "transport", "tool_contract"],
)
def test_copilot_mcp_server_and_tool_configuration_changes_invalidate_identity(
    tmp_path: Path,
    change: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _replace_executable(workspace / "server", b"#!/bin/sh\necho primary\n")
    _replace_executable(workspace / "server-alt", b"#!/bin/sh\necho alternate\n")
    config_path = workspace / ".vscode" / "mcp.json"
    server_config = _copilot_server_config()
    _write_json(config_path, {"servers": {"danger_lab": server_config}})
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    old_artifact, old_token, old_arguments = _resolve_copilot_tool(
        config=config,
        home_dir=home_dir,
        workspace=workspace,
    )

    changed_config = deepcopy(server_config)
    if change == "command":
        changed_config["command"] = "./server-alt"
    elif change == "full_config":
        changed_config["env"] = {"SERVER_TOKEN": "version-two"}
        changed_config["metadata"] = {"revision": 2}
    elif change == "transport":
        changed_config["type"] = "sse"
    else:
        changed_tools = changed_config.get("tools")
        assert isinstance(changed_tools, dict)
        changed_tools["shell_exec"] = {
            "description": "Execute a changed shell contract.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command", "timeout"],
            },
        }
    _write_json(config_path, {"servers": {"danger_lab": changed_config}})
    new_artifact, new_token, new_arguments = _resolve_copilot_tool(
        config=config,
        home_dir=home_dir,
        workspace=workspace,
    )

    assert old_artifact.artifact_id == new_artifact.artifact_id
    assert old_arguments == new_arguments
    assert old_token != new_token
    expected_reuse_reasons = {
        "approval_reuse_identity_changed",
        "approval_reuse_capability_changed",
    }
    assert approval_context_tokens_validation_reason(old_token, new_token) in expected_reuse_reasons
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="copilot",
            scope="artifact",
            action="allow",
            artifact_id=old_artifact.artifact_id,
            artifact_hash=old_token,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=new_artifact,
        artifact_hash=new_token,
        arguments=new_arguments,
    )

    assert decision.current_action == "review"
    assert decision.action == "review"
    assert decision.approval_reuse_reason_code in expected_reuse_reasons
