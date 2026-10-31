"""Released birkin-mnemosyne launcher and local opt-in tool boundaries."""

from __future__ import annotations

from typing import Final

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import _extension
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_directory_inventory import catalog_rows

from . import mcp_policy_catalog_fixture
from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .mcp_extension_driver import apply_contributed_mcp_decision, apply_local_mcp_extension_decision
from .test_guard_local_mcp_grants import _enroll
from .test_guard_mcp_server_grants import _AuthorityStore, _layer
from .test_native_source_program import canonical_packs as canonical_packs
from .test_native_source_program import compiler as compiler

_CATALOG_ID: Final = "command.mcp-birkin-mnemosyne"
_REVIEWED_TOOLS: Final = (
    "memory_remember",
    "memory_forget",
    "memory_restore",
    "memory_curate",
    "memory_review_apply",
    "memory_review_undo",
    "memory_index_register",
    "memory_index_split",
    "memory_handoff_capture",
    "memory_handoff_fold",
)
_RECALL_TOOLS: Final = (
    "memory_search",
    "memory_get_note",
    "memory_list",
    "memory_related",
    "memory_curation_catalog",
    "memory_capacity",
    "memory_review_questions",
    "memory_identity_read",
    "memory_kibitzer_candidates",
    "memory_index_read",
    "memory_open_trigger",
    "memory_index_check",
    "memory_startup_read",
    "memory_startup_verify",
    "memory_handoff_read",
)


@pytest.fixture(autouse=True)
def _birkin_catalog(mcp_policy_delivery, monkeypatch: pytest.MonkeyPatch) -> None:
    """Admit this contribution through the shared installed-pack fixture."""
    monkeypatch.setattr(mcp_policy_catalog_fixture, "_DELIVERY", [mcp_policy_delivery])
    monkeypatch.setattr(mcp_policy_catalog_fixture, "_CATALOG_HOMES", {})


def _identity(package: str = "birkin-mnemosyne[mcp]") -> McpServerIdentity:
    return build_mcp_server_identity(
        config_path="",
        command="uvx",
        args=("--from", package, "mnemosyne-mcp", "--vault", "/chosen/vault"),
        transport="stdio",
        env={},
    )


def _artifact(tool_name: str, package: str = "birkin-mnemosyne[mcp]") -> GuardArtifact:
    identity = _identity(package)
    return build_tool_call_artifact(
        harness="claude-code",
        server_name="mnemosyne",
        tool_name=tool_name,
        source_scope="user",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )


def test_catalog_is_external_and_off(canonical_packs) -> None:
    reader, release = canonical_packs
    registry = GeneratedCommandCatalog(tuple(_extension(row) for _, _, row in catalog_rows(reader, release)))
    extension = registry.get(_CATALOG_ID)
    assert extension is not None
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"


@pytest.mark.parametrize("package", ("birkin-mnemosyne[mcp]", "birkin-mnemosyne[mcp]==0.7.0"))
def test_documented_launcher_matches_with_extras_and_user_vault(package: str) -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    reviewed = apply_contributed_mcp_decision(enabled, _artifact("memory_remember", package), "allow")
    assert reviewed is not None
    assert reviewed[:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize(
    "package",
    ("birkin-mnemosyne[mcp,semantic]", "birkin_mnemosyne[mcp]", "birkin-mnemosyne", "birkin-mnemosyne[semantic]"),
)
def test_undeclared_launcher_spellings_are_outside_this_entry(package: str) -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(enabled, _artifact("memory_remember", package), "allow") is None


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


@pytest.mark.parametrize("tool_name", (*_RECALL_TOOLS, "unknown_future_tool"))
def test_recall_and_unknown_tools_preserve_existing_review(tool_name: str) -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(enabled, _artifact(tool_name), "review") is None


@pytest.mark.parametrize("enabled", (False, True))
@pytest.mark.parametrize("current_action", ("allow", "block"))
@pytest.mark.parametrize(
    "tool_name", ("unknown_future_tool", *_RECALL_TOOLS, "memory_handoff_capture", "memory_handoff_fold")
)
def test_unknown_tool_only_tightens_allow_when_locally_enabled(
    enabled: bool, current_action: GuardAction, tool_name: str
) -> None:
    state = ControlState.ENABLED if enabled else ControlState.DISABLED
    store = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, state),))
    result = apply_contributed_mcp_decision(store, _artifact(tool_name), current_action)
    if enabled and tool_name not in _RECALL_TOOLS and current_action == "allow":
        assert result is not None
        assert result[:2] == ("review", "catalog-mcp-extension")
    else:
        assert result is None


def test_custom_device_grant_wins_over_enabled_contribution() -> None:
    artifact = _artifact("memory_remember")
    identity = _identity()
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, _CATALOG_ID, ControlState.ENABLED),))
    store = GuardStore(enabled.guard_home)
    reviewed = apply_contributed_mcp_decision(store, artifact, "allow")
    assert reviewed is not None
    assert reviewed[:2] == ("review", "catalog-mcp-extension")
    _enroll(
        store,
        identity,
        states={"memory_remember": "allow"},
        example_label="uvx --from birkin-mnemosyne[mcp] mnemosyne-mcp --vault /chosen/vault",
        commands=(LocalCliCommand("memory_remember", "memory_remember", "memory_remember", "Store a memory note"),),
    )
    granted = apply_local_mcp_extension_decision(store, artifact, "review")
    assert granted is not None
    assert granted[:2] == ("allow", "local-mcp-extension")
