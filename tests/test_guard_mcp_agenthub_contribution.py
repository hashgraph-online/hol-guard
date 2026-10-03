"""Launcher and tool-state validation for the AgentHub MCP contribution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_cli_trust import apply_local_mcp_extension_decision
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
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
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import mcp_tool_state, validate_mcp_contribution

_AGENTHUB = Path(__file__).resolve().parents[1] / "contributions/mcp-servers/mcp.agenthub.json"
_CATALOG_ID = "command.mcp-agenthub"
# Tools that start another agent, stop or discard its work, write to the user's working tree,
# or send code to a provider.
_REVIEWED_TOOLS = (
    "ask",
    "start_task",
    "apply_task",
    "send_message",
    "review",
    "compare",
    "cancel_task",
    "discard_task",
)
# Tools that only read AgentHub state keep Guard's usual handling.
_READ_ONLY_TOOLS = (
    "list_agents",
    "get_task",
    "wait_task",
    "get_task_logs",
    "list_tasks",
    "get_task_diff",
    "list_sessions",
    "search_sessions",
    "get_transcript",
    "list_models",
)


def _payload() -> dict[str, object]:
    payload = json.loads(_AGENTHUB.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _artifact(tool_name: str, args: tuple[str, ...] = ("agenthub-gateway", "mcp")):
    identity = build_mcp_server_identity(
        config_path="",
        command="uvx",
        args=args,
        transport="stdio",
    )
    return build_tool_call_artifact(
        harness="claude-code",
        server_name="agenthub",
        tool_name=tool_name,
        source_scope="user",
        config_path=".claude.json",
        transport="stdio",
        server_identity=identity,
    )


class _AuthorityStore:
    def __init__(self, layers: tuple[ExtensionControlLayer, ...] = ()) -> None:
        self.layers = layers

    def read_local_mcp_grant(self, *_args: object, **_kwargs: object) -> None:
        return None

    def read_extension_control_authority_for_registry(self, registry: object) -> ExtensionControlAuthorityView:
        digest = getattr(registry, "catalog_digest", "0" * 64)
        assert isinstance(digest, str)
        return ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=digest,
            layers=self.layers,
        )


def _enabled(kind: ControlLayerKind) -> _AuthorityStore:
    return _AuthorityStore(
        (
            ExtensionControlLayer(
                schema_version=CONTROL_SCHEMA_VERSION,
                kind=kind,
                catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
                global_lockdown=False,
                controls=(
                    ExtensionControl(
                        target=ControlTarget(ControlTargetKind.EXTENSION, _CATALOG_ID),
                        state=ControlState.ENABLED,
                    ),
                ),
            ),
        )
    )


def test_contribution_validates() -> None:
    validate_mcp_contribution(_payload(), filename="mcp.agenthub.json")


def test_catalog_item_is_external_opt_in_uvx_launch() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_CATALOG_ID)
    assert extension is not None
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["surface"] == "mcp"
    assert payload["mcp_launch"]["command"] == "uvx"
    assert payload["mcp_launch"]["package"] == "agenthub-gateway"
    assert trust_class_for(_CATALOG_ID) == "external"


@pytest.mark.parametrize(
    "args",
    [
        ("agenthub-gateway", "mcp"),
        ("agenthub-gateway@1.2.1", "mcp"),
        ("--from", "agenthub-gateway", "agenthub", "mcp"),
    ],
)
def test_uvx_launch_forms_resolve_to_the_package(args: tuple[str, ...]) -> None:
    identity = build_mcp_server_identity(config_path="", command="uvx", args=args, transport="stdio")
    assert identity.package_name == "agenthub-gateway"


def test_rejects_unlisted_launcher() -> None:
    payload = _payload()
    payload["launch"] = {"kind": "package-launcher", "command": "sh", "package": "agenthub-gateway"}
    with pytest.raises(ValueError):
        validate_mcp_contribution(payload, filename="launcher.json")


@pytest.mark.parametrize("tool_name", _REVIEWED_TOOLS)
def test_agent_running_and_writing_tools_are_reviewed(tool_name: str) -> None:
    assert mcp_tool_state(_payload(), tool_name) == "review"


@pytest.mark.parametrize("tool_name", _READ_ONLY_TOOLS)
def test_read_only_tools_inherit(tool_name: str) -> None:
    assert mcp_tool_state(_payload(), tool_name) == "inherit"


def test_no_tool_is_allowlisted() -> None:
    assert all(tool["state"] != "allow" for tool in _payload()["tools"])


def test_every_agenthub_tool_is_listed_and_unknown_tools_are_reviewed() -> None:
    listed = {tool["name"] for tool in _payload()["tools"]} - {"other"}
    assert listed == set(_REVIEWED_TOOLS) | set(_READ_ONLY_TOOLS)
    # A tool added in a later AgentHub release is reviewed until this contribution lists it.
    assert mcp_tool_state(_payload(), "unknown_tool") == "review"


@pytest.mark.parametrize("tool_name", _REVIEWED_TOOLS)
def test_review_applies_only_after_local_admin_enable(tool_name: str) -> None:
    artifact = _artifact(tool_name)
    assert apply_local_mcp_extension_decision(_AuthorityStore(), artifact, "allow") is None
    assert apply_local_mcp_extension_decision(_enabled(ControlLayerKind.SIGNED_CLOUD), artifact, "allow") is None
    reviewed = apply_local_mcp_extension_decision(_enabled(ControlLayerKind.LOCAL_ADMIN), artifact, "allow")
    assert reviewed is not None
    assert reviewed[0] == "review"
    assert reviewed[1] == "catalog-mcp-extension"
