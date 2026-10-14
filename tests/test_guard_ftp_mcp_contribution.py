"""FTP directory deletion requires review only after local activation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .mcp_extension_driver import apply_contributed_mcp_decision, apply_local_mcp_extension_decision
from .test_guard_mcp_server_grants import _AuthorityStore, _layer

ROOT = Path(__file__).resolve().parents[1]
CATALOG_ID = "command.mcp-ftp"


def artifact(tool="delete-directory", package="mcp-server-ftp@1.2.3"):
    """Build a Codex tool-call artifact for an npx-launched FTP MCP package."""
    identity = build_mcp_server_identity(config_path="", command="npx", args=("-y", package), transport="stdio")
    return build_tool_call_artifact(
        harness="codex",
        server_name="my-remote-files",
        tool_name=tool,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )


def enabled_store():
    """Create a test authority store with the FTP profile locally enabled."""
    return _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, CATALOG_ID, ControlState.ENABLED),))


def test_inventory_policy_and_trust_binding():
    payload = json.loads((ROOT / "contributions/mcp-servers/mcp.ftp.json").read_bytes())
    validate_mcp_contribution(payload, filename="mcp.ftp.json")
    assert payload["launch"] == {"kind": "package-launcher", "command": "npx", "package": "mcp-server-ftp"}
    assert payload["activation"] == "opt-in"
    assert payload["trustClass"] == "external"
    defaults = {row["name"]: row["state"] for row in payload["tools"]}
    assert len(defaults) == len(payload["tools"]) == 10
    assert defaults.pop("delete-directory") == "review"
    assert set(defaults.values()) == {"inherit"}
    binding = json.loads((ROOT / f"contracts/extensions/trust/{CATALOG_ID}.v1.json").read_bytes())
    assert binding == {
        "schemaVersion": "guard.extension-trust-binding.v1",
        "extension": CATALOG_ID,
        "trustClass": "external",
    }


@pytest.mark.parametrize(
    "kind,state",
    [
        (None, None),
        (ControlLayerKind.SIGNED_CLOUD, ControlState.ENABLED),
        (ControlLayerKind.LOCAL_ADMIN, ControlState.DISABLED),
    ],
)
def test_inert_until_local_enable(kind, state):
    layers = () if kind is None else (_layer(kind, CATALOG_ID, state),)
    assert apply_contributed_mcp_decision(_AuthorityStore(layers), artifact(), "allow") is None


def test_enabled_directory_delete_strengthens_allow_to_review():
    decision = apply_contributed_mcp_decision(enabled_store(), artifact(), "allow")
    assert decision is not None
    assert decision[:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("current", ["block", "require-reapproval", "review", "sandbox-required"])
def test_stronger_floors_are_preserved(current):
    assert apply_contributed_mcp_decision(enabled_store(), artifact(), current) is None


@pytest.mark.parametrize(
    "tool",
    [
        "list-directory",
        "download-file",
        "upload-file",
        "create-directory",
        "delete-file",
        "rename-file",
        "edit-file",
        "append-file",
        "unknown-tool",
    ],
)
def test_other_tools_inherit(tool):
    assert apply_contributed_mcp_decision(enabled_store(), artifact(tool), "allow") is None


def test_unrelated_package_does_not_match():
    assert apply_contributed_mcp_decision(enabled_store(), artifact(package="unrelated-mcp"), "allow") is None


@pytest.mark.parametrize("state", ["allow", "review", "block"])
def test_device_grant_precedes_contribution(tmp_path, state):
    from codex_plugin_scanner.guard.store import GuardStore

    from .test_guard_local_mcp_grants import _enroll

    tool = artifact()
    identity = build_mcp_server_identity(
        config_path="", command="npx", args=("-y", "mcp-server-ftp@1.2.3"), transport="stdio"
    )
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        identity,
        states={"delete-directory": state},
        commands=(LocalCliCommand("delete-directory", "Delete directory", "delete-directory", "Delete directory"),),
    )
    decision = apply_local_mcp_extension_decision(store, tool, "review")
    assert decision is not None
    assert decision[:2] == (state, "local-mcp-extension")
