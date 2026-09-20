"""Raw compatibility aliases must retain the actual generic artifact identity."""

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

_FIXTURE = Path(__file__).parents[1] / "rust/crates/guard-runtime/src/policy_scoped_alias_fixture.json"


def test_raw_alias_vectors_use_the_actual_normalized_hook_producer(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "guide.md").write_text("Synthetic guide.\n")
    cases = json.loads(_FIXTURE.read_text())["cases"]
    assert len(cases) == 12
    for case in cases:
        payload = _normalize_hook_payload(case["payload"], harness=case["harness"])
        action = _hook_action_envelope(harness=case["harness"], payload=payload, home_dir=tmp_path, workspace=workspace)
        assert (
            _hook_runtime_artifact(
                harness=case["harness"],
                payload=payload,
                action_envelope=action,
                home_dir=tmp_path,
                guard_home=tmp_path / "guard",
                workspace=workspace,
            )
            is None
        ), case["name"]
        actual = payload.get("artifact_id") or _artifact_id_from_event(case["harness"], payload)
        assert actual == case["artifactId"], case["name"]
        assert payload["source_scope"] == "project"


def test_raw_user_scope_is_not_a_project_artifact() -> None:
    payload = _normalize_hook_payload(
        {"tool_name": "Shell", "tool_input": {"command": "printf synthetic"}, "sourceScope": "user"},
        harness="codex",
    )
    assert _artifact_id_from_event("codex", payload) == "codex:user:Shell"
