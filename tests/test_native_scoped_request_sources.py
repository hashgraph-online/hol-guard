"""Shared native request vectors come from actual Python artifact producers."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_hook_payload import (
    _hook_action_envelope,
    _normalize_hook_payload,
)
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _artifact_id_from_event,
    _hook_runtime_artifact,
)
from codex_plugin_scanner.guard.exact_command import exact_command_sha256, exact_shell_command_from_hook

_FIXTURE = Path(__file__).parents[1] / "rust/crates/guard-runtime/src/policy_scoped_request_fixture.json"


def test_shared_generic_vectors_match_the_actual_artifact_and_byte_producers(tmp_path):
    fixture = json.loads(_FIXTURE.read_text())
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    assert len(fixture["cases"]) == 29
    for case in fixture["cases"]:
        harness = case["harness"]
        original = case["payload"]
        command = exact_shell_command_from_hook(original)
        assert command is not None
        payload = _normalize_hook_payload(original, harness=harness)
        action = _hook_action_envelope(harness=harness, payload=payload, home_dir=home, workspace=workspace)
        runtime = _hook_runtime_artifact(
            harness=harness, payload=payload, action_envelope=action, home_dir=home,
            guard_home=home / "guard", workspace=workspace,
        )
        assert runtime is None, case["name"]
        artifact = payload.get("artifact_id") or _artifact_id_from_event(harness, payload)
        assert artifact == case["artifactId"], case["name"]
        assert exact_command_sha256(command) == case["sha256"], case["name"]


def test_missing_working_directory_is_a_different_runtime_identity(tmp_path):
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Shell", "tool_input": {"command": "printf synthetic"}}
    artifact = _hook_runtime_artifact(
        harness="codex", payload=payload, action_envelope=None, home_dir=tmp_path,
        guard_home=tmp_path / "guard", workspace=tmp_path / "does-not-exist",
    )
    assert artifact is not None and ":unmodeled-shell:" in artifact.artifact_id
