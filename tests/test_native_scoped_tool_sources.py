"""Non-shell scoped identities are checked against the actual hook producer."""

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
from codex_plugin_scanner.guard.exact_command import exact_shell_command_from_hook
from tests.test_exact_command_hook_policy import _outer, _publish
from tests.test_guard_review_policy_memory_command import _store

_FIXTURE = Path(__file__).parents[1] / "rust/crates/guard-runtime/src/policy_scoped_tool_fixture.json"


def test_native_non_shell_vectors_retain_the_real_hook_artifact_identity(tmp_path):
    fixture = json.loads(_FIXTURE.read_text())
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "guide.md").write_text("Synthetic local guide.\n")
    assert len(fixture["cases"]) == 24
    for case in fixture["cases"]:
        harness = case["harness"]
        original = case["payload"]
        assert exact_shell_command_from_hook(original) is None
        payload = _normalize_hook_payload(original, harness=harness)
        action = _hook_action_envelope(harness=harness, payload=payload, home_dir=home, workspace=workspace)
        artifact = _hook_runtime_artifact(
            harness=harness,
            payload=payload,
            action_envelope=action,
            home_dir=home,
            guard_home=home / "guard",
            workspace=workspace,
        )
        assert artifact is None, case["name"]
        assert _artifact_id_from_event(harness, payload) == case["artifactId"], case["name"]


def test_destination_only_ssh_is_a_generic_review_with_exact_signed_reuse(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = "ssh synthetic@example.invalid"
    original = {"hook_event_name": "PreToolUse", "tool_name": "Shell", "tool_input": {"command": command}}
    payload = _normalize_hook_payload(original, harness="codex")
    action = _hook_action_envelope(harness="codex", payload=payload, home_dir=tmp_path, workspace=workspace)
    assert (
        _hook_runtime_artifact(
            harness="codex",
            payload=payload,
            action_envelope=action,
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            workspace=workspace,
        )
        is None
    )
    store = _store(tmp_path)
    before_rc, before = _outer(capsys, store, workspace, command, harness="codex")
    assert before_rc == 1 and before["policy_action"] == "review"
    artifact = store.list_receipts(limit=1)[0]["artifact_id"]
    assert artifact == "codex:project:Shell"
    _publish(store, artifact, "memory", command, harness="codex")
    after_rc, after = _outer(capsys, store, workspace, command, harness="codex")
    assert after_rc == 0 and after["policy_action"] == "allow"
    changed_rc, changed = _outer(capsys, store, workspace, command + " ", harness="codex")
    assert changed_rc == 1 and changed["policy_action"] == "review"
