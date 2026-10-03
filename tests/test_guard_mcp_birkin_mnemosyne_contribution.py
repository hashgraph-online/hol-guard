"""Released birkin-mnemosyne launcher and local opt-in tool boundaries."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from codex_plugin_scanner.guard.local_cli_trust import apply_local_mcp_extension_decision, utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_grants import matching_mcp_contribution
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_mcp_server_grants import _AuthorityStore, _layer

_CATALOG_ID: Final = "command.mcp-birkin-mnemosyne"
_REVIEWED_TOOLS: Final = ("memory_remember", "memory_forget", "memory_restore", "memory_curate")
_RECALL_TOOLS: Final = ("memory_search", "memory_get_note", "memory_list", "memory_related", "memory_curation_catalog")


def _artifact(tool_name: str, package: str = "birkin-mnemosyne[mcp]") -> GuardArtifact:
    identity = build_mcp_server_identity(
        config_path="",
        command="uvx",
        args=("--from", package, "mnemosyne-mcp", "--vault", "/chosen/vault"),
        transport="stdio",
        env={},
    )
    return build_tool_call_artifact(
        harness="claude-code",
        server_name="mnemosyne",
        tool_name=tool_name,
        source_scope="user",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )


def test_catalog_is_external_and_off() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_CATALOG_ID)
    assert extension is not None
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"


@pytest.mark.parametrize("package", ("birkin-mnemosyne[mcp]", "birkin-mnemosyne[mcp]==0.4.0"))
def test_documented_launcher_matches_with_extras_and_user_vault(package: str) -> None:
    matched = matching_mcp_contribution(_artifact("memory_remember", package))
    assert matched is not None
    assert matched["id"] == "mcp.birkin-mnemosyne"


@pytest.mark.parametrize("tool_name", _REVIEWED_TOOLS)
def test_mutations_require_local_admin_enable(tool_name: str) -> None:
    artifact = _artifact(tool_name)
    inert = _AuthorityStore()
    cloud = _AuthorityStore((_layer(ControlLayerKind.SIGNED_CLOUD, _CATALOG_ID, ControlState.ENABLED),))
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    assert apply_local_mcp_extension_decision(inert, artifact, "allow") is None
    assert apply_local_mcp_extension_decision(cloud, artifact, "allow") is None
    reviewed = apply_local_mcp_extension_decision(enabled, artifact, "allow")
    assert reviewed is not None
    assert reviewed[:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("tool_name", (*_RECALL_TOOLS, "unknown_future_tool"))
def test_recall_and_unknown_tools_preserve_existing_review(tool_name: str) -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    assert apply_local_mcp_extension_decision(enabled, _artifact(tool_name), "review") is None


def test_mutation_does_not_weaken_existing_block() -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    assert apply_local_mcp_extension_decision(enabled, _artifact("memory_remember"), "block") is None


def test_custom_device_grant_wins_over_enabled_contribution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = _artifact("memory_remember")
    identity = build_mcp_server_identity(
        config_path="",
        command="uvx",
        args=("--from", "birkin-mnemosyne[mcp]", "mnemosyne-mcp", "--vault", "/chosen/vault"),
        transport="stdio",
        env={},
    )
    store = GuardStore(tmp_path / "guard-home")
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    monkeypatch.setattr(
        store, "read_extension_control_authority_for_registry", enabled.read_extension_control_authority_for_registry
    )
    cli_identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name="mnemosyne",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label="uvx --from birkin-mnemosyne[mcp] mnemosyne-mcp --vault /chosen/vault",
    )
    store.record_local_cli_observation(
        cli_identity,
        seen_at=utc_now(),
        surface="mcp",
        server_identity_hash=identity.identity_hash,
        server_command=identity.command,
        server_args_hash=identity.args_hash,
        help_status="ok",
    )
    store.replace_local_cli_commands(
        cli_identity.cli_id,
        (LocalCliCommand("memory_remember", "memory_remember", "memory_remember", "Store a memory note"),),
    )
    store.upsert_local_cli_grant(
        identity=cli_identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
        command_states={"memory_remember": "allow"},
    )
    granted = apply_local_mcp_extension_decision(store, artifact, "review")
    assert granted is not None
    assert granted[:2] == ("allow", "local-mcp-extension")
