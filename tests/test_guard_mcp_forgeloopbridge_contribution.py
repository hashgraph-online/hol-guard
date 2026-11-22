"""ForgeLoopBridge launcher, SHA-256 file-transfer gates, and local opt-in tool boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import _extension
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_directory_inventory import catalog_rows

from . import mcp_policy_catalog_fixture
from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .mcp_extension_driver import apply_contributed_mcp_decision, apply_local_mcp_extension_decision
from .test_guard_local_mcp_grants import _enroll
from .test_guard_mcp_server_grants import _AuthorityStore, _layer
from .test_native_source_program import canonical_packs as canonical_packs
from .test_native_source_program import compiler as compiler

_CATALOG_ID: Final = "command.mcp-forgeloopbridge"
_MANIFEST: Final = Path(__file__).resolve().parents[1] / "contributions/mcp-servers/mcp.forgeloopbridge.json"
_TRANSFER_MUTATION_TOOLS: Final = (
    "prepare_transfer",
    "complete_transfer",
    "fetch_transfer",
)
_REVIEWED_TOOLS: Final = (
    "register_participant",
    "rename_participant",
    "get_updates",
    "send_message",
    "post_order",
    "report_execution",
    "create_channel",
    "set_channel_archived",
    "prepare_transfer",
    "complete_transfer",
    "fetch_transfer",
    "create_signal",
    "revoke_signal",
    "revoke_wake",
    "record_improvement",
)
_READONLY_TOOLS: Final = (
    "get_context",
    "read_messages",
    "list_pending_orders",
    "get_pack_command",
    "read_transfer",
    "list_wakes",
)


@pytest.fixture(autouse=True)
def _forgeloopbridge_catalog(mcp_policy_delivery, monkeypatch: pytest.MonkeyPatch) -> None:
    """Admit this contribution through the shared installed-pack fixture."""
    monkeypatch.setattr(mcp_policy_catalog_fixture, "_DELIVERY", [mcp_policy_delivery])
    monkeypatch.setattr(mcp_policy_catalog_fixture, "_CATALOG_HOMES", {})


def _identity(
    command: str = "forgeloopbridge-mcp",
    args: tuple[str, ...] = ("--url", "http://localhost:8000"),
) -> McpServerIdentity:
    return build_mcp_server_identity(
        config_path="",
        command=command,
        args=args,
        transport="stdio",
        env={},
    )


def _artifact(tool_name: str, identity: McpServerIdentity | None = None) -> GuardArtifact:
    return build_tool_call_artifact(
        harness="claude-code",
        server_name="forgeloopbridge",
        tool_name=tool_name,
        source_scope="user",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity if identity is not None else _identity(),
    )


def test_file_transfer_verify_and_publish_steps_require_review_when_enabled() -> None:
    """Gate prepare_transfer, complete_transfer, and fetch_transfer on review while keeping read_transfer inherit."""
    payload = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    validate_mcp_contribution(payload, filename=_MANIFEST.name)
    tool_states = {item["name"]: item["state"] for item in payload["tools"]}
    for tool_name in _TRANSFER_MUTATION_TOOLS:
        assert tool_states[tool_name] == "review"
    assert tool_states["read_transfer"] == "inherit"
    assert tool_states["get_pack_command"] == "inherit"
    assert any(
        "prepare_transfer" in note and "sha256" in note and "complete_transfer" in note
        for note in payload["saferAlternatives"]
    )

    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    for tool_name in _TRANSFER_MUTATION_TOOLS:
        decision = apply_contributed_mcp_decision(enabled, _artifact(tool_name), "allow")
        assert decision is not None
        assert decision[:2] == ("review", "catalog-mcp-extension")
    assert apply_contributed_mcp_decision(enabled, _artifact("read_transfer"), "allow") is None


def test_catalog_is_external_and_off(canonical_packs) -> None:
    reader, release = canonical_packs
    registry = GeneratedCommandCatalog(tuple(_extension(row) for _, _, row in catalog_rows(reader, release)))
    extension = registry.get(_CATALOG_ID)
    assert extension is not None
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["mcp_launch"] == {"kind": "direct-command", "command": "forgeloopbridge-mcp"}
    assert payload["permissions"][0]["example_command"] == "forgeloopbridge-mcp"


@pytest.mark.parametrize("command", ("forgeloopbridge-mcp", "/opt/fixture/bin/forgeloopbridge-mcp"))
def test_installed_launcher_matches_with_user_url(command: str) -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    reviewed = apply_contributed_mcp_decision(enabled, _artifact("prepare_transfer", _identity(command)), "allow")
    assert reviewed is not None
    assert reviewed[:2] == ("review", "catalog-mcp-extension")


def test_python_wrapper_retains_ordinary_policy() -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    wrapper = _identity("python", ("examples/mcp_stdio.py",))
    assert apply_contributed_mcp_decision(enabled, _artifact("prepare_transfer", wrapper), "allow") is None


@pytest.mark.parametrize("tool_name", _REVIEWED_TOOLS)
def test_mutations_require_local_admin_enable(tool_name: str) -> None:
    artifact = _artifact(tool_name)
    inert = _AuthorityStore()
    cloud = _AuthorityStore((_layer(ControlLayerKind.SIGNED_CLOUD, _CATALOG_ID, ControlState.ENABLED),))
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(inert, artifact, "allow") is None
    assert apply_contributed_mcp_decision(cloud, artifact, "allow") is None
    reviewed = apply_contributed_mcp_decision(enabled, artifact, "allow")
    assert reviewed is not None
    assert reviewed[:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("tool_name", (*_READONLY_TOOLS, "unknown_future_tool"))
def test_readonly_and_unknown_tools_preserve_existing_review(tool_name: str) -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(enabled, _artifact(tool_name), "review") is None


@pytest.mark.parametrize("enabled", (False, True))
@pytest.mark.parametrize("current_action", ("allow", "block"))
@pytest.mark.parametrize(
    "tool_name", ("unknown_future_tool", *_READONLY_TOOLS, "prepare_transfer", "complete_transfer")
)
def test_unknown_tool_only_tightens_allow_when_locally_enabled(
    enabled: bool, current_action: GuardAction, tool_name: str
) -> None:
    state = ControlState.ENABLED if enabled else ControlState.DISABLED
    store = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, state),))
    result = apply_contributed_mcp_decision(store, _artifact(tool_name), current_action)
    if enabled and tool_name not in _READONLY_TOOLS and current_action == "allow":
        assert result is not None
        assert result[:2] == ("review", "catalog-mcp-extension")
    else:
        assert result is None


def test_custom_device_grant_wins_over_enabled_contribution() -> None:
    artifact = _artifact("prepare_transfer")
    identity = _identity()
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    store = GuardStore(enabled.guard_home)
    reviewed = apply_contributed_mcp_decision(store, artifact, "allow")
    assert reviewed is not None
    assert reviewed[:2] == ("review", "catalog-mcp-extension")
    _enroll(
        store,
        identity,
        states={"prepare_transfer": "allow"},
        example_label="forgeloopbridge-mcp --url http://localhost:8000",
        commands=(
            LocalCliCommand(
                "prepare_transfer",
                "prepare_transfer",
                "prepare_transfer",
                "Step 1 of sending a file or packed folder out-of-band.",
            ),
        ),
    )
    granted = apply_local_mcp_extension_decision(store, artifact, "review")
    assert granted is not None
    assert granted[:2] == ("allow", "local-mcp-extension")
