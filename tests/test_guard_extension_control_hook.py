from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize(
    ("command", "permission_id"),
    (
        (
            "gh api -X PUT repos/example/project/pulls/5115/merge -f merge_method=squash",
            "command.github.permission.merge-remote",
        ),
        ("git push --force origin feature", "command.git.permission.force-push"),
    ),
)
def test_guard_hook_honors_explicit_extension_permission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    permission_id: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace, default_action="review")
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.PERMISSION, permission_id),
                state=ControlState.ENABLED,
            ),
        ),
    )
    authority = ExtensionControlAuthorityView(
        health=AuthorityHealth.PROTECTED,
        revision=9,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        layers=(layer,),
    )
    monkeypatch.setattr(store, "read_extension_control_authority", lambda **_kwargs: authority)
    output = io.StringIO()
    result = commands_hook._run_guard_hook_command(
        argparse.Namespace(
            artifact_id=None,
            artifact_name=None,
            event_file=None,
            harness="codex",
            json=True,
            policy_action=None,
            runtime_harness=None,
        ),
        guard_home=guard_home,
        workspace=workspace,
        context=HarnessContext(tmp_path, workspace, guard_home),
        store=store,
        config=config,
        input_text=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "source_scope": "project",
            }
        ),
        output_stream=output,
    )

    assert result == 0
    assert output.getvalue() == ""
    assert store.list_approval_requests(limit=1) == []
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "allow"
