"""Offline approval and activation boundaries for mcp-mail-server. No mail is sent or deleted."""

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
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
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
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import mcp_payload_for_catalog_id, mcp_tool_state
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401

_CATALOG_ID = "command.mcp-mail-server"
_DELETE_TOOLS = ("delete_message", "delete_messages")
_READ_TOOLS = ("list_mailboxes", "search_messages")


def _artifact(
    tool: str,
    package: str = "mcp-mail-server@2.1.0",
    *,
    command: str = "npx",
    args: tuple[str, ...] | None = None,
    transport: str = "stdio",
    env: dict[str, str] | None = None,
) -> GuardArtifact:
    identity = build_mcp_server_identity(
        config_path="",
        command=command,
        args=args if args is not None else ("-y", package),
        transport=transport,
        env=env,
    )
    return build_tool_call_artifact(
        harness="codex",
        server_name="mail",
        tool_name=tool,
        source_scope="project",
        config_path=".mcp.json",
        transport=transport,
        server_identity=identity,
    )


def _layer(
    kind: ControlLayerKind = ControlLayerKind.LOCAL_ADMIN,
    state: ControlState = ControlState.ENABLED,
    *,
    lockdown: bool = False,
) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=kind,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=lockdown,
        controls=(ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, _CATALOG_ID), state),),
    )


class _AuthorityStore:
    """Synthetic authenticated controls, never written to production state."""

    def __init__(self, layers: tuple[ExtensionControlLayer, ...] = ()) -> None:
        self.layers = layers

    def has_local_cli_grant_rules(self) -> bool:
        """No device grant rows exist, so an unavailable resident cannot hide one."""
        return False

    def read_extension_control_authority_for_registry(self, registry: object) -> ExtensionControlAuthorityView:
        assert registry is BUILT_IN_COMMAND_EXTENSION_REGISTRY
        return ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=self.layers,
        )


@pytest.mark.parametrize("tool", _DELETE_TOOLS + _READ_TOOLS)
@pytest.mark.parametrize(
    "layers",
    [(), (_layer(ControlLayerKind.SIGNED_CLOUD),), (_layer(state=ControlState.DISABLED),)],
)
def test_profile_is_inert_without_local_admin_enable(tool: str, layers: tuple[ExtensionControlLayer, ...]) -> None:
    action: GuardAction = "allow" if tool in _DELETE_TOOLS else "review"
    assert apply_local_mcp_extension_decision(_AuthorityStore(layers), _artifact(tool), action) is None


@pytest.mark.parametrize("tool", _DELETE_TOOLS)
@pytest.mark.parametrize("base_action", ["allow", "warn", "review"])
def test_enabled_permanent_deletion_requires_approval(tool: str, base_action: GuardAction) -> None:
    decision = apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), _artifact(tool), base_action)
    assert decision is not None
    assert decision[:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("tool", _READ_TOOLS)
def test_enabled_explicit_read_only_tools_remain_automatic(tool: str) -> None:
    decision = apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), _artifact(tool), "review")
    assert decision is not None
    assert decision[:2] == ("allow", "catalog-mcp-extension")


_UNREVIEWED_LAUNCHES = (
    ("bunx", ("mcp-mail-server@2.1.0",)),
    ("uvx", ("mcp-mail-server",)),
    ("npx", ("--registry", "https://alternate.example.invalid", "-y", "mcp-mail-server@2.1.0")),
    ("npx", ("--registry=https://alternate.example.invalid", "-y", "mcp-mail-server@2.1.0")),
    ("npx", ("-y", "mcp-mail-server@npm:evil-pkg")),
    ("npx", ("-y", "mcp-mail-server@github:attacker/repo")),
    ("npx", ("-y", "mcp-mail-server@file:../x")),
    ("npx", ("-y", "mcp-mail-server@attacker/repo")),
    ("npx", ("-y", "mcp-mail-server@payload.tgz")),
    ("npx", ("-y", "mcp-mail-server@payload.tar.gz")),
    ("npx", ("-y", "mcp-mail-server@payload.tar")),
    ("npx", ("-y", "mcp-mail-server@payload.TAR")),
    ("npx", ("-y", "mcp-mail-server@.")),
    ("npx", ("-y", "mcp-mail-server@..")),
    ("npx", ("-y", "mcp-mail-server@.hidden")),
    ("npx", ("--userconfig", "evil.npmrc", "-y", "mcp-mail-server")),
    ("npx", ("--userconfig=evil.npmrc", "-y", "mcp-mail-server")),
    ("npx", ("--globalconfig", "evil.npmrc", "-y", "mcp-mail-server")),
    ("npx", ("--globalconfig=evil.npmrc", "-y", "mcp-mail-server")),
    ("npx", ("--@scope:registry=https://alternate.example.invalid", "-y", "mcp-mail-server")),
    ("npx", ("--reg=https://alternate.example.invalid", "-y", "mcp-mail-server")),
    ("npx", ("--userconf=evil.npmrc", "-y", "mcp-mail-server")),
    ("npx", ("--future-config=evil.npmrc", "-y", "mcp-mail-server")),
    ("npx", ("--", "--future-config=evil.npmrc", "mcp-mail-server")),
)


@pytest.mark.parametrize("tool", _READ_TOOLS)
@pytest.mark.parametrize("command,args", _UNREVIEWED_LAUNCHES)
def test_unreviewed_launch_does_not_inherit_read_allow(tool: str, command: str, args: tuple[str, ...]) -> None:
    artifact = _artifact(tool, command=command, args=args)
    assert apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), artifact, "review") is None


@pytest.mark.parametrize("tool", _DELETE_TOOLS)
@pytest.mark.parametrize("command,args", _UNREVIEWED_LAUNCHES)
def test_launch_mismatch_cannot_remove_deletion_review(tool: str, command: str, args: tuple[str, ...]) -> None:
    decision = apply_local_mcp_extension_decision(
        _AuthorityStore((_layer(),)), _artifact(tool, command=command, args=args), "allow"
    )
    assert decision is not None
    assert decision[:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("tool", _READ_TOOLS)
@pytest.mark.parametrize("command", ["/opt/node/bin/npx", r"C:\Program Files\nodejs\NPX.CMD"])
@pytest.mark.parametrize("package", ["mcp-mail-server", "mcp-mail-server@2.1.0", "mcp-mail-server@2.2.0"])
def test_reviewed_launcher_paths_keep_read_allow(tool: str, command: str, package: str) -> None:
    decision = apply_local_mcp_extension_decision(
        _AuthorityStore((_layer(),)), _artifact(tool, package, command=command), "review"
    )
    assert decision is not None
    assert decision[:2] == ("allow", "catalog-mcp-extension")


@pytest.mark.parametrize("tool", _READ_TOOLS)
@pytest.mark.parametrize("transport", ["http", "sse"])
def test_non_stdio_identity_does_not_inherit_read_allow(tool: str, transport: str) -> None:
    artifact = _artifact(tool, transport=transport)
    assert apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), artifact, "review") is None


@pytest.mark.parametrize("tool", _READ_TOOLS)
@pytest.mark.parametrize("field", ["command", "package_source", "transport"])
@pytest.mark.parametrize("value", [None, "", 7])
def test_incomplete_launch_identity_does_not_inherit_read_allow(tool: str, field: str, value: object) -> None:
    artifact = _artifact(tool)
    identity = dict(artifact.metadata["mcp_server_identity"])
    identity[field] = value
    metadata = dict(artifact.metadata, mcp_server_identity=identity)
    assert (
        apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), replace(artifact, metadata=metadata), "review")
        is None
    )


_PACKAGE_ENV_KEYS = (
    "NPM_CONFIG_REGISTRY",
    "npm_config_registry",
    "NpM_CoNfIg_ReGiStRy",
    "@scope:registry",
    "npm_config_@scope:registry",
    "NPM_CONFIG_USERCONFIG",
    "NPM_CONFIG_GLOBALCONFIG",
    "UV_INDEX",
    "UV_INDEX_URL",
    "UV_INDEX_PRIVATE_URL",
    "UV_EXTRA_INDEX_URL",
    "UV_DEFAULT_INDEX",
    "UV_FIND_LINKS",
    "UV_CONFIG_FILE",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "PIP_FIND_LINKS",
    "PIP_CONFIG_FILE",
    "PIPX_INDEX_URL",
    "PIPX_PIP_ARGS",
    "YARN_NPM_REGISTRY_SERVER",
)


@pytest.mark.parametrize("tool", _READ_TOOLS)
@pytest.mark.parametrize("key", _PACKAGE_ENV_KEYS)
def test_package_manager_environment_does_not_inherit_read_allow(tool: str, key: str) -> None:
    artifact = _artifact(tool, env={key: "https://alternate.example.invalid"})
    assert apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), artifact, "review") is None


@pytest.mark.parametrize("tool", _READ_TOOLS)
@pytest.mark.parametrize(
    "package", ["mcp-mail-server", "mcp-mail-server@2.1.0", "mcp-mail-server@^2.0.0", "mcp-mail-server@latest"]
)
def test_registry_versions_and_mail_environment_keep_read_allow(tool: str, package: str) -> None:
    artifact = _artifact(tool, package, env={"MAIL_SERVER_HOST": "mail.example.invalid"})
    decision = apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), artifact, "review")
    assert decision is not None
    assert decision[:2] == ("allow", "catalog-mcp-extension")


@pytest.mark.parametrize("field", ["package_version", "env_keys"])
def test_missing_source_identity_cannot_receive_read_allow(field: str) -> None:
    artifact = _artifact("search_messages")
    identity = dict(artifact.metadata["mcp_server_identity"])
    identity.pop(field)
    metadata = dict(artifact.metadata, mcp_server_identity=identity)
    assert (
        apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), replace(artifact, metadata=metadata), "review")
        is None
    )


@pytest.mark.parametrize("value", [None, "NPM_CONFIG_REGISTRY", {}, [None], [7]])
def test_malformed_source_environment_cannot_receive_read_allow(value: object) -> None:
    artifact = _artifact("search_messages")
    identity = dict(artifact.metadata["mcp_server_identity"], env_keys=value)
    metadata = dict(artifact.metadata, mcp_server_identity=identity)
    assert (
        apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), replace(artifact, metadata=metadata), "review")
        is None
    )


@pytest.mark.parametrize("value", [7, False, {}, [], ""])
def test_malformed_source_selector_cannot_receive_read_allow(value: object) -> None:
    artifact = _artifact("search_messages")
    identity = dict(artifact.metadata["mcp_server_identity"], package_version=value)
    metadata = dict(artifact.metadata, mcp_server_identity=identity)
    assert (
        apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), replace(artifact, metadata=metadata), "review")
        is None
    )


@pytest.mark.parametrize("tool", _DELETE_TOOLS + _READ_TOOLS)
@pytest.mark.parametrize("base_action", ["block", "require-sandbox"])
def test_profile_preserves_stronger_requirements(tool: str, base_action: GuardAction) -> None:
    assert apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), _artifact(tool), base_action) is None


@pytest.mark.parametrize("tool", _READ_TOOLS)
def test_lockdown_suppresses_read_allow_defaults(tool: str) -> None:
    assert (
        apply_local_mcp_extension_decision(_AuthorityStore((_layer(lockdown=True),)), _artifact(tool), "review") is None
    )


@pytest.mark.parametrize(
    "tool",
    ["get_message", "get_messages", "move_message", "move_messages", "send_email", "save_attachment", "future_tool"],
)
def test_unreviewed_authority_is_not_allowlisted(tool: str) -> None:
    payload = mcp_payload_for_catalog_id(_CATALOG_ID)
    assert payload is not None
    assert mcp_tool_state(payload, tool) == "inherit"
    assert apply_local_mcp_extension_decision(_AuthorityStore((_layer(),)), _artifact(tool), "review") is None


def test_package_identity_matches_versions_but_not_server_display_names() -> None:
    store = _AuthorityStore((_layer(),))
    for package in ("mcp-mail-server", "mcp-mail-server@2.1.0", "mcp-mail-server@2.2.0"):
        decision = apply_local_mcp_extension_decision(store, _artifact("delete_messages", package), "allow")
        assert decision is not None and decision[0] == "review"
    assert (
        apply_local_mcp_extension_decision(store, _artifact("delete_messages", "different-mail-server"), "allow")
        is None
    )
    artifact = _artifact("delete_messages")
    metadata = {key: value for key, value in artifact.metadata.items() if key != "mcp_server_identity"}
    assert apply_local_mcp_extension_decision(store, replace(artifact, metadata=metadata), "allow") is None


@pytest.mark.parametrize("tool", _DELETE_TOOLS)
@pytest.mark.parametrize("custom_state", ["allow", "block"])
def test_this_device_custom_grant_wins_over_enabled_delete_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str, custom_state: str
) -> None:
    identity = build_mcp_server_identity(
        config_path="", command="npx", args=("-y", "mcp-mail-server@2.1.0"), transport="stdio"
    )
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        store,
        "read_extension_control_authority_for_registry",
        _AuthorityStore((_layer(),)).read_extension_control_authority_for_registry,
    )
    cli_identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name="mcp-mail-server",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label="npx -y mcp-mail-server@2.1.0",
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
        cli_identity.cli_id, (LocalCliCommand(tool, tool, tool, "Permanently delete mail"),)
    )
    store.upsert_local_cli_grant(
        identity=cli_identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
        command_states={tool: custom_state},
    )
    decision = apply_local_mcp_extension_decision(store, _artifact(tool), "review")
    assert decision is not None
    assert decision[:2] == (custom_state, "local-mcp-extension")


@pytest.mark.parametrize(
    "tool,arguments,expected",
    [
        ("delete_message", {"mailbox": "INBOX", "uid": 42, "uidValidity": 7}, "review"),
        ("delete_messages", {"mailbox": "Archive", "uids": [42, 43], "uidValidity": 7}, "review"),
        ("delete_messages", {"mailbox": "INBOX", "uids": list(range(1, 201))}, "review"),
        ("list_mailboxes", {}, "allow"),
        ("search_messages", {"mailboxes": ["INBOX"], "includeBody": True}, "allow"),
    ],
)
def test_offline_tool_call_evaluation_uses_enabled_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str, arguments: dict[str, object], expected: str
) -> None:
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace", mode="prompt")
    store = GuardStore(config.guard_home)
    monkeypatch.setattr(
        store,
        "read_extension_control_authority_for_registry",
        _AuthorityStore((_layer(),)).read_extension_control_authority_for_registry,
    )
    artifact = _artifact(tool)
    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=config.workspace, config=config),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == expected
    assert decision.source == "catalog-mcp-extension"


@pytest.mark.parametrize(
    "command,args,env",
    [(command, args, None) for command, args in _UNREVIEWED_LAUNCHES]
    + [
        ("npx", ("-y", "mcp-mail-server@2.1.0"), {key: "https://alternate.example.invalid"})
        for key in ("NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG", "UV_DEFAULT_INDEX")
    ],
)
@pytest.mark.parametrize(
    "tool,arguments",
    [("list_mailboxes", {}), ("search_messages", {"mailboxes": ["INBOX"], "includeBody": True})],
)
def test_offline_unreviewed_launch_retains_host_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    args: tuple[str, ...],
    env: dict[str, str] | None,
    tool: str,
    arguments: dict[str, object],
) -> None:
    """Exercise native identity and final tool evaluation without invoking mail."""
    # No grants are enrolled here; an unkeyed home must not trip the shared resident.
    from codex_plugin_scanner.guard import local_mcp_grant_decision
    from codex_plugin_scanner.guard.native_local_mcp_grant import NativeLocalMcpGrant

    monkeypatch.setattr(
        local_mcp_grant_decision, "native_local_mcp_grant", lambda **_: NativeLocalMcpGrant("none", None, None)
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace", mode="prompt")
    store = GuardStore(config.guard_home)
    artifact = _artifact(tool, command=command, args=args, env=env)
    artifact_hash = build_tool_call_hash(artifact, arguments, workspace=config.workspace, config=config)
    baseline = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=False,
    )
    monkeypatch.setattr(
        store,
        "read_extension_control_authority_for_registry",
        _AuthorityStore((_layer(),)).read_extension_control_authority_for_registry,
    )
    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert (decision.action, decision.source) == (baseline.action, baseline.source)
