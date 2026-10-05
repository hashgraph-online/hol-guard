"""AsDecided's native read-only MCP tools inherit policy and stay external."""

from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    mcp_tool_state,
    validate_mcp_contribution,
)
from codex_plugin_scanner.guard.runtime.mcp_server_grants import (
    apply_contributed_mcp_decision,
    matching_mcp_contribution,
)

from .test_guard_mcp_server_grants import _AuthorityStore, _layer

_ROOT = Path(__file__).resolve().parents[1]
_PATH = "contributions/mcp-servers/mcp.asdecided.json"
_ID = "command.mcp-asdecided"
_TOOLS = ("get_summary", "search_artifacts", "retrieve_grounding", "get_artifact", "get_related", "find_decisions")


def _payload():
    return json.loads((_ROOT / _PATH).read_text())


def test_validates_and_registers_as_external_opt_in():
    payload = _payload()
    validate_mcp_contribution(payload, filename=_PATH)
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_ID)
    assert extension is not None
    data = extension.to_dict()
    assert data["trust_class"] == "external"
    assert data["activation"] == "opt-in"
    assert data["enabled"] is False
    assert data["mcp_launch"] == {"kind": "direct-command", "command": "decided-mcp"}
    assert {tool["name"] for tool in payload["tools"]} == {*_TOOLS, "other"}


@pytest.mark.parametrize("tool", (*_TOOLS, "future_tool"))
@pytest.mark.parametrize(
    "current_action", ["allow", "warn", "review", "require-reapproval", "block", "sandbox-required"]
)
def test_read_tools_never_change_existing_policy(tool, current_action):
    assert mcp_tool_state(_payload(), tool) == "inherit"
    identity = build_mcp_server_identity(
        config_path="",
        command="/opt/homebrew/bin/decided-mcp",
        args=("--root", "/repo one"),
        transport="stdio",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="my-decisions",
        tool_name=tool,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )
    assert matching_mcp_contribution(artifact)["id"] == "mcp.asdecided"
    for layers in [
        (),
        (_layer(ControlLayerKind.LOCAL_ADMIN, _ID, ControlState.ENABLED),),
        (_layer(ControlLayerKind.SIGNED_CLOUD, _ID, ControlState.ENABLED),),
        (_layer(ControlLayerKind.LOCAL_ADMIN, _ID, ControlState.DISABLED),),
    ]:
        assert apply_contributed_mcp_decision(_AuthorityStore(layers), artifact, current_action) is None


def test_frozen_packaging_includes_canonical_manifest(tmp_path):
    stage = runpy.run_path(str(_ROOT / "scripts/release/stage_guard_cloud_review_artifacts.py"))
    stage["stage_artifacts"](_ROOT, destination_root=tmp_path)
    assert (tmp_path / "mcp_servers/contributions/mcp.asdecided.json").read_bytes() == (_ROOT / _PATH).read_bytes()
