"""Typed native fixtures are checked against the real normalized hook producer."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_hook_payload import (
    _hook_action_envelope,
    _normalize_hook_payload,
)
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.exact_command import exact_command_sha256, exact_shell_command_from_hook

FIXTURE = Path(__file__).parents[1] / "rust/crates/guard-runtime/tests/fixtures/typed-artifact-sources.json"


def produce_typed_artifact(case, directory):
    home = directory / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    for name in case["workspaceFiles"]:
        (workspace / name).write_text("{}", encoding="utf-8")
    payload = _normalize_hook_payload(case["payload"], harness=case["harness"])
    action = _hook_action_envelope(
        harness=case["harness"],
        payload=payload,
        home_dir=home,
        workspace=workspace,
    )
    assert action is not None and action.action_type == "shell_command"
    artifact = _hook_runtime_artifact(
        harness=case["harness"],
        payload=payload,
        action_envelope=action,
        home_dir=home,
        guard_home=home / "guard",
        workspace=workspace,
    )
    assert artifact is not None
    raw_command = exact_shell_command_from_hook(case["payload"])
    assert raw_command is not None
    return artifact, exact_command_sha256(raw_command)


def test_shared_typed_vectors_use_the_complete_actual_action_envelope(tmp_path):
    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
    assert len(cases) == 32
    for index, case in enumerate(cases):
        artifact, digest = produce_typed_artifact(case, tmp_path / str(index))
        assert artifact.artifact_id == case["artifactId"], case["name"]
        assert artifact.artifact_type == case["artifactType"], case["name"]
        assert digest == case["sha256"], case["name"]
        assert artifact.metadata.get("shell_execution_context_hash") is None
        assert not artifact.metadata.get("shell_execution_context_hashes")


def test_directory_context_and_missing_workspace_cannot_reuse_a_plain_typed_identity(tmp_path):
    original = {
        "harness": "codex",
        "workspaceFiles": ["package.json"],
        "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "npm ci"}},
    }
    artifact, _ = produce_typed_artifact(original, tmp_path)
    workspace = tmp_path / "home/workspace"
    for command, cwd in [("cd . && npm ci", workspace), ("npm ci", workspace / "missing")]:
        raw = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}
        payload = _normalize_hook_payload(raw, harness="codex")
        action = _hook_action_envelope(harness="codex", payload=payload, home_dir=tmp_path, workspace=cwd)
        changed = _hook_runtime_artifact(
            harness="codex",
            payload=payload,
            action_envelope=action,
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            workspace=cwd,
        )
        assert changed is not None and changed.artifact_id != artifact.artifact_id


def test_normalized_scope_alias_is_part_of_the_real_typed_identity(tmp_path):
    original = {
        "harness": "codex",
        "workspaceFiles": [],
        "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "npm ci"}},
    }
    first, _ = produce_typed_artifact(original, tmp_path / "first")
    for scope in ("project", "user"):
        case = {**original, "payload": {**original["payload"], "sourceScope": scope}}
        artifact, _ = produce_typed_artifact(case, tmp_path / scope)
        assert artifact.artifact_id.startswith(f"codex:{scope}:package-request:")
        assert (artifact.artifact_id == first.artifact_id) is (scope == "project")
