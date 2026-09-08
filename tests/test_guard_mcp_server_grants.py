"""Contributed MCP defaults stay inert until local-admin enable."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_cli_trust import apply_local_mcp_extension_decision, utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
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
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_grants import apply_contributed_mcp_decision
from codex_plugin_scanner.guard.store import GuardStore


def _identity():
    return build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )


def _artifact(identity, tool_name: str):
    return build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )


def _config(tmp_path: Path) -> GuardConfig:
    return GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace", mode="prompt")


def _layer(
    kind: ControlLayerKind,
    extension_id: str,
    state: ControlState,
    *,
    lockdown: bool = False,
) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=kind,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=lockdown,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=state,
            ),
        ),
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


def test_filesystem_mcp_stays_inert_until_enabled() -> None:
    artifact = _artifact(_identity(), "write_file")
    assert apply_contributed_mcp_decision(_AuthorityStore(), artifact, "review") is None
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-filesystem", ControlState.ENABLED),))
    blocked = apply_contributed_mcp_decision(enabled, artifact, "review")
    assert blocked is not None
    assert blocked[0] == "block"
    assert blocked[1] == "catalog-mcp-extension"


def test_enabled_filesystem_keeps_read_on_review() -> None:
    artifact = _artifact(_identity(), "read_file")
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-filesystem", ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(enabled, artifact, "review") is None


def test_signed_cloud_enable_does_not_activate_mcp_contribution() -> None:
    artifact = _artifact(_identity(), "write_file")
    cloud = _AuthorityStore((_layer(ControlLayerKind.SIGNED_CLOUD, "command.mcp-filesystem", ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(cloud, artifact, "review") is None


def test_global_lockdown_suppresses_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.mcp_server_grants.mcp_tool_state",
        lambda *_args, **_kwargs: "allow",
    )
    artifact = _artifact(_identity(), "read_file")
    locked = _AuthorityStore(
        (
            _layer(
                ControlLayerKind.LOCAL_ADMIN,
                "command.mcp-filesystem",
                ControlState.ENABLED,
                lockdown=True,
            ),
        )
    )
    assert apply_contributed_mcp_decision(locked, artifact, "review") is None


def test_missing_tool_identity_does_not_apply_other_defaults() -> None:
    artifact = _artifact(_identity(), "write_file")
    metadata = {key: value for key, value in artifact.metadata.items() if key != "mcp_tool_identity"}
    artifact = replace(artifact, metadata=metadata)
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-filesystem", ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(enabled, artifact, "review") is None


def test_allow_does_not_override_block_floor() -> None:
    artifact = _artifact(_identity(), "write_file")
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-filesystem", ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(enabled, artifact, "block") is None


def test_custom_mcp_grant_overrides_contribution(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    cli_identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name=identity.package_name or "mcp-server",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label="npx -y @modelcontextprotocol/server-filesystem",
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
        (LocalCliCommand("write_file", "write_file", "write_file", "Write a file"),),
    )
    store.upsert_local_cli_grant(
        identity=cli_identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
        command_states={"write_file": "allow"},
    )
    artifact = _artifact(identity, "write_file")
    granted = apply_local_mcp_extension_decision(store, artifact, "review")
    assert granted is not None
    assert granted[0] == "allow"
    assert granted[1] == "local-mcp-extension"


def test_evaluate_write_file_blocks_after_local_enable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    view = ExtensionControlAuthorityView(
        health=AuthorityHealth.PROTECTED,
        revision=1,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        layers=(_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-filesystem", ControlState.ENABLED),),
    )
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: view)
    artifact = _artifact(identity, "write_file")
    arguments = {"path": "notes.txt", "contents": "hi"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "block"
    assert decision.source == "catalog-mcp-extension"


def test_evaluate_write_file_stays_review_while_inert(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    artifact = _artifact(identity, "write_file")
    arguments = {"path": "notes.txt", "contents": "hi"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "review"
    assert decision.source != "catalog-mcp-extension"


def _tether_identity():
    return build_mcp_server_identity(
        config_path="",
        command="uvx",
        args=("tether-memory",),
        transport="stdio",
    )


def _tether_artifact(identity, tool_name: str):
    return build_tool_call_artifact(
        harness="codex",
        server_name="tether",
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )


@pytest.mark.parametrize("tool_name", ["remember", "recall", "link", "forget"])
def test_tether_mcp_stays_inert_until_enabled(tool_name: str) -> None:
    artifact = _tether_artifact(_tether_identity(), tool_name)
    assert apply_contributed_mcp_decision(_AuthorityStore(), artifact, "review") is None


@pytest.mark.parametrize("tool_name", ["remember", "recall", "link", "forget"])
def test_enabled_tether_keeps_every_tool_on_review(tool_name: str) -> None:
    artifact = _tether_artifact(_tether_identity(), tool_name)
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-tether", ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(enabled, artifact, "review") is None


def test_signed_cloud_enable_does_not_activate_tether() -> None:
    artifact = _tether_artifact(_tether_identity(), "forget")
    cloud = _AuthorityStore((_layer(ControlLayerKind.SIGNED_CLOUD, "command.mcp-tether", ControlState.ENABLED),))
    assert apply_contributed_mcp_decision(cloud, artifact, "review") is None


def test_pipx_launch_matches_tether_package() -> None:
    identity = build_mcp_server_identity(
        config_path="",
        command="pipx",
        args=("run", "tether-memory"),
        transport="stdio",
    )
    assert identity.package_name == "tether-memory"
    artifact = _tether_artifact(identity, "remember")
    assert apply_contributed_mcp_decision(_AuthorityStore(), artifact, "review") is None


def test_custom_mcp_grant_overrides_tether_contribution(tmp_path: Path) -> None:
    identity = _tether_identity()
    store = GuardStore(tmp_path / "guard-home")
    cli_identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name=identity.package_name or "mcp-server",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label="uvx tether-memory",
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
        (LocalCliCommand("forget", "forget", "forget", "Soft-delete a memory"),),
    )
    store.upsert_local_cli_grant(
        identity=cli_identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
        command_states={"forget": "block"},
    )
    artifact = _tether_artifact(identity, "forget")
    granted = apply_local_mcp_extension_decision(store, artifact, "review")
    assert granted is not None
    assert granted[0] == "block"
    assert granted[1] == "local-mcp-extension"


def _evaluate_tether_forget(tmp_path: Path, store: GuardStore):
    artifact = _tether_artifact(_tether_identity(), "forget")
    arguments = {"id": 42}
    config = _config(tmp_path)
    return evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=config),
        arguments=arguments,
        claim_saved_approval=False,
    )


def test_evaluate_tether_forget_unchanged_by_local_enable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every tether tool inherits, so enabling the catalog item must not change Guard's usual review."""

    inert = _evaluate_tether_forget(tmp_path, GuardStore(tmp_path / "inert-home"))
    assert inert.source != "catalog-mcp-extension"

    store = GuardStore(tmp_path / "guard-home")
    view = ExtensionControlAuthorityView(
        health=AuthorityHealth.PROTECTED,
        revision=1,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        layers=(_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-tether", ControlState.ENABLED),),
    )
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: view)
    enabled = _evaluate_tether_forget(tmp_path, store)
    assert enabled.action == inert.action
    assert enabled.source != "catalog-mcp-extension"
