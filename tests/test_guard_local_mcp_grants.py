from __future__ import annotations

import os
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.local_cli_trust import matching_local_mcp_grant, utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_mcp_probe import McpProbeResult
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import McpCatalogResult
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_mcp_catalog import tool_definition_authority_hash

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401


def _clean_npx() -> str | None:
    path_value = os.environ.get("PATH", "")
    parts = [
        part
        for part in path_value.split(os.pathsep)
        if part
        and not (
            Path(part).as_posix().rstrip("/").endswith("/package-shims/bin")
            or "/.hol-guard/package-shims/" in Path(part).as_posix()
        )
    ]
    return shutil.which("npx", path=os.pathsep.join(parts)) if parts else shutil.which("npx")


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
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        mode="prompt",
    )


def _enroll(
    store: GuardStore,
    identity,
    *,
    states: dict[str, str],
    grant_state: str = "allowed",
    example_label: str | None = None,
    commands: tuple[LocalCliCommand, ...] | None = None,
) -> None:
    from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

    cli_identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name=identity.package_name or "mcp-server",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label=example_label or "npx -y @modelcontextprotocol/server-filesystem",
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
        commands
        or (
            LocalCliCommand("read_file", "read_file", "read_file", "Read a file"),
            LocalCliCommand("write_file", "write_file", "write_file", "Write a file"),
            LocalCliCommand("other", "Other tools", "server …", "other"),
        ),
    )
    store.upsert_local_cli_grant(
        identity=cli_identity,
        state=grant_state,
        expected_revision=0,
        updated_at=utc_now(),
        command_states=states,
    )


def test_allowed_tool_overrides_review(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow", "write_file": "inherit"})
    artifact = _artifact(identity, "read_file")
    arguments = {"path": "notes.txt"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "allow"
    assert decision.source == "local-mcp-extension"


def test_explicit_empty_public_hash_cannot_use_private_catalog_authority(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    definition = {"name": "read_file", "inputSchema": {"type": "object"}}
    store.replace_local_cli_commands(
        f"local-cli.mcp-{identity.identity_hash[:8]}",
        (LocalCliCommand("read_file", "read_file", "read_file", "Read a file"),),
        mcp_catalog=McpCatalogResult(tools=(definition,), complete=True),
        identity_hash=identity.identity_hash,
        seen_at=utc_now(),
    )
    store.upsert_local_cli_command_states(f"local-cli.mcp-{identity.identity_hash[:8]}", {"read_file": "allow"})
    artifact = _artifact(identity, "read_file")
    private_hash = tool_definition_authority_hash(definition)
    private_artifact = replace(artifact, runtime_private_metadata={"mcp_tool_authority_hash": private_hash})
    assert matching_local_mcp_grant(store=store, artifact=private_artifact, current_action="allow") == "allowed"

    empty_public_artifact = replace(private_artifact, metadata={**artifact.metadata, "mcp_tool_authority_hash": ""})
    assert matching_local_mcp_grant(store=store, artifact=empty_public_artifact, current_action="allow") == "review"


def test_mcp_grant_reads_one_snapshot_during_permission_change(tmp_path: Path, monkeypatch) -> None:
    import sqlite3

    from codex_plugin_scanner.guard import store_local_mcp

    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    cli_id = f"local-cli.mcp-{identity.identity_hash[:8]}"
    with sqlite3.connect(store.path) as connection:
        connection.execute("pragma journal_mode=WAL")
    original = store_local_mcp._read_command_catalog
    changed = False

    def read_commands_then_change_permissions(connection, selected_cli_id):
        nonlocal changed
        result = original(connection, selected_cli_id)
        if not changed:
            changed = True
            store.upsert_local_cli_command_states(cli_id, {"read_file": "block"})
        return result

    monkeypatch.setattr(store_local_mcp, "_read_command_catalog", read_commands_then_change_permissions)
    before = store.read_local_mcp_grant(identity.identity_hash)
    after = store.read_local_mcp_grant(identity.identity_hash)
    assert before is not None and after is not None
    assert before["command_states"]["read_file"] == "allow"
    assert after["command_states"]["read_file"] == "block"


def test_mcp_targeted_grant_reads_only_called_tool_and_other(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow", "write_file": "block", "other": "block"})

    grant = store.read_local_mcp_grant(identity.identity_hash, tool_name="read_file")
    assert grant is not None
    assert {command.command_id for command in grant["commands"]} == {"read_file", "other"}
    assert grant["command_states"] == {"read_file": "allow", "other": "block"}
    assert (
        matching_local_mcp_grant(store=store, artifact=_artifact(identity, "read_file"), current_action="review")
        == "allowed"
    )
    assert (
        matching_local_mcp_grant(store=store, artifact=_artifact(identity, "new_file"), current_action="allow")
        == "blocked"
    )
    empty_name_grant = store.read_local_mcp_grant(identity.identity_hash, tool_name="")
    assert empty_name_grant is not None
    assert {command.command_id for command in empty_name_grant["commands"]} == {"other"}
    assert empty_name_grant["command_states"] == {"other": "block"}


def test_configured_connection_does_not_inherit_another_connections_denial(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

    store = GuardStore(tmp_path / "guard-home")
    server_hash = "c" * 64
    other = UnlistedCliIdentity("local-cli.mcp-other", "other", "executable", server_hash, "other")
    store.record_local_cli_observation(
        other,
        seen_at=utc_now(),
        surface="mcp",
        server_identity_hash=server_hash,
        server_command="npx",
        server_args_hash="d" * 64,
    )
    store.upsert_local_cli_grant(
        identity=other,
        state="blocked",
        expected_revision=store.read_local_cli_revision(),
        updated_at=utc_now(),
    )
    configured = UnlistedCliIdentity("local-cli.mcp-configured", "configured", "executable", "a" * 64, "configured")
    store.record_local_cli_observation(
        configured,
        seen_at=utc_now(),
        surface="mcp",
        server_identity_hash=server_hash,
        server_command="npx",
        server_args_hash="d" * 64,
    )

    assert store.read_local_mcp_grant(server_hash, connection_identity_hash="b" * 64) is None


def test_empty_command_filter_never_loads_every_permission(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store_local_cli import _read_command_catalog, _read_command_states

    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow", "other": "block"})
    with store._connect() as connection:
        cli_id = f"local-cli.mcp-{identity.identity_hash[:8]}"
        assert _read_command_catalog(connection, cli_id, ()) == []
        assert _read_command_states(connection, cli_id, ()) == {}
        assert len(_read_command_catalog(connection, cli_id)) == 3


def test_mcp_targeted_grant_keeps_observed_hashed_tool_choice(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
    from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool

    tool = observed_mcp_tool("codex", "mcp__codex_apps__composio__COMPOSIO_SEARCH_TOOLS")
    assert tool is not None
    store = GuardStore(tmp_path / "guard-home")
    identity = UnlistedCliIdentity(
        cli_id=tool.identity.cli_id,
        name=tool.identity.name,
        kind=tool.identity.kind,
        identity_hash=tool.identity.identity_hash,
        example_label=tool.identity.example_label,
    )
    store.record_local_cli_observation(
        identity,
        seen_at=utc_now(),
        surface="mcp",
        server_identity_hash=tool.server_identity.identity_hash,
        server_command=tool.server_identity.command,
        server_args_hash=tool.server_identity.args_hash,
    )
    store.replace_local_cli_commands(
        identity.cli_id,
        (LocalCliCommand(tool.command_id, tool.name, tool.qualified_name, "Observed tool"),),
    )
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
        command_states={tool.command_id: "block"},
    )
    grant = store.read_local_mcp_grant(tool.server_identity.identity_hash, tool_name=tool.qualified_name)
    assert grant is not None
    assert {command.command_id for command in grant["commands"]} == {tool.command_id}
    assert grant["command_states"] == {tool.command_id: "block"}
    artifact = _artifact(tool.server_identity, tool.qualified_name)
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="allow") == "blocked"


def test_retired_deny_still_blocks_an_empty_inventory(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.local_mcp_stdio import McpCatalogResult

    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "block"})
    store.replace_local_cli_commands(
        f"local-cli.mcp-{identity.identity_hash[:8]}",
        (),
        mcp_catalog=McpCatalogResult(tools=(), complete=True),
        identity_hash=identity.identity_hash,
        seen_at=utc_now(),
    )
    artifact = _artifact(identity, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="allow") == "blocked"


def test_recommended_tool_stays_on_review(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow", "write_file": "inherit"})
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
    assert decision.source != "local-mcp-extension"


def test_explicit_ask_reviews_benign_tool(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "review"})
    artifact = _artifact(identity, "read_file")
    arguments = {"path": "notes.txt"}
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="allow") == "review"
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "review"
    assert decision.source == "local-mcp-extension"
    assert store.read_local_cli_command_states(f"local-cli.mcp-{identity.identity_hash[:8]}")["read_file"] == "review"


def test_blocked_tool_overrides_review(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"write_file": "block"})
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
    assert decision.source == "local-mcp-extension"


def test_blocked_server_blocks_every_tool(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"}, grant_state="blocked")
    artifact = _artifact(identity, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "blocked"
    arguments = {"path": "notes.txt"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "block"
    assert decision.source == "local-mcp-extension"


def test_allow_does_not_override_block(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    artifact = _artifact(identity, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="block") is None


@pytest.mark.parametrize("empty_catalog", [False, True])
def test_unlisted_tools_do_not_inherit_allow(tmp_path: Path, empty_catalog: bool) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow", "other": "allow"})
    if empty_catalog:
        store.replace_local_cli_commands(f"local-cli.mcp-{identity.identity_hash[:8]}", ())
    artifact = _artifact(identity, "new_delete_tool")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "review"
    artifact = _artifact(identity, "new_read_tool")
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, {}, workspace=tmp_path, config=_config(tmp_path)),
        arguments={},
        claim_saved_approval=False,
    )
    assert decision.action == "review"


def test_unlisted_tools_keep_explicit_deny(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow", "other": "block"})
    artifact = _artifact(identity, "new_delete_tool")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "blocked"


@pytest.mark.parametrize("choice", ["allow", "block"])
def test_composio_wrapper_choice_cannot_grant_inner_actions(tmp_path: Path, choice: str) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    tool = "composio_multi_execute_tool"
    _enroll(store, identity, states={tool: choice}, commands=(LocalCliCommand(tool, tool, tool, "Execute a batch"),))
    artifact = _artifact(identity, tool)
    expected = "blocked" if choice == "block" else None
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == expected
    arguments = {"tools": [{"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {"channel": "test"}}]}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == ("block" if choice == "block" else "review")


def test_env_drift_cannot_inherit_same_launch_grant(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
        env={"GITHUB_TOKEN": "secret"},
        env_keys=("GITHUB_TOKEN",),
    )
    assert runtime.identity_hash != identity.identity_hash
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_unbound_env_hash_cannot_satisfy_package_launcher_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    import codex_plugin_scanner.guard.store_local_mcp as store_local_mcp

    sentinel = "guard-context-unbound:configured-environment"
    # Simulate detection and lookup both running without the native digest
    # authority: the recorded hash and the recomputed hash share the sentinel.
    monkeypatch.setattr(store_local_mcp, "build_configured_environment_hash", lambda *_a, **_k: sentinel)
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )
    runtime = replace(runtime, env_values_hash=sentinel)
    assert runtime.identity_hash != identity.identity_hash
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_npx_absolute_path_still_matches_command_and_args(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )
    assert runtime.identity_hash != identity.identity_hash
    assert runtime.args_hash == identity.args_hash
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "allowed"
    arguments = {"path": "notes.txt"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "allow"
    assert decision.source == "local-mcp-extension"


def test_same_basename_different_executable_does_not_inherit_npx_grant(tmp_path: Path) -> None:
    impostor = tmp_path / "npx"
    impostor.write_text("#!/bin/sh\nexit 0\n")
    impostor.chmod(0o755)
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command=str(impostor),
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_same_package_extra_npx_flags_still_match_allow_all(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    enrolled = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=(
            "--yes",
            "chrome-devtools-mcp@latest",
            "--isolated",
            "--executablePath",
            "/usr/bin/true",
        ),
        transport="stdio",
    )
    assert runtime.identity_hash != enrolled.identity_hash
    assert runtime.args_hash != enrolled.args_hash
    assert runtime.package_name == enrolled.package_name == "chrome-devtools-mcp"
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        enrolled,
        states={"click": "allow", "evaluate_script": "allow", "other": "allow"},
        example_label="npx -y chrome-devtools-mcp@latest",
        commands=(
            LocalCliCommand("click", "click", "click", "Click a page element"),
            LocalCliCommand("evaluate_script", "evaluate_script", "evaluate_script", "Run page script"),
            LocalCliCommand("other", "Other tools", "server …", "other"),
        ),
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name="click",
        source_scope="global",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=runtime,
    )
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") == "allowed"
    arguments = {"uid": "1_2"}
    decision = evaluate_tool_call(
        store=store,
        config=_config(tmp_path),
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=_config(tmp_path)),
        arguments=arguments,
        claim_saved_approval=False,
    )
    assert decision.action == "allow"
    assert decision.source == "local-mcp-extension"


def test_registry_override_does_not_inherit_npx_grant(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    enrolled = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "--registry", "https://example.invalid/npm", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    assert runtime.package_source != enrolled.package_source
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        enrolled,
        states={"click": "allow", "other": "allow"},
        example_label="npx -y chrome-devtools-mcp@latest",
        commands=(
            LocalCliCommand("click", "click", "click", "Click a page element"),
            LocalCliCommand("other", "Other tools", "server …", "other"),
        ),
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name="click",
        source_scope="global",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=runtime,
    )
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_explicit_package_version_change_does_not_inherit_grant(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    enrolled = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "chrome-devtools-mcp@1.0.0"),
        transport="stdio",
    )
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "chrome-devtools-mcp@2.0.0"),
        transport="stdio",
    )
    store = GuardStore(tmp_path / "guard-home")
    _enroll(
        store,
        enrolled,
        states={"click": "allow", "other": "allow"},
        example_label="npx -y chrome-devtools-mcp@1.0.0",
        commands=(
            LocalCliCommand("click", "click", "click", "Click a page element"),
            LocalCliCommand("other", "Other tools", "server …", "other"),
        ),
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name="click",
        source_scope="global",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=runtime,
    )
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_shim_only_path_does_not_resolve_package_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime.mcp_protection import resolved_package_launcher_executable

    shim_bin = tmp_path / ".hol-guard" / "package-shims" / "bin"
    shim_bin.mkdir(parents=True)
    impostor = shim_bin / "npx"
    impostor.write_text("#!/bin/sh\nexit 0\n")
    impostor.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim_bin))
    assert resolved_package_launcher_executable("npx") is None


def test_different_package_does_not_inherit_npx_grant(tmp_path: Path) -> None:
    npx = _clean_npx()
    if npx is None:
        pytest.skip("npx is not on PATH")
    enrolled = _identity()
    runtime = build_mcp_server_identity(
        config_path="",
        command=npx,
        args=("-y", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, enrolled, states={"read_file": "allow", "other": "allow"})
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name="click",
        source_scope="global",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=runtime,
    )
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_non_launcher_path_does_not_inherit_npx_grant(tmp_path: Path) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    runtime = build_mcp_server_identity(
        config_path="",
        command="/usr/bin/node",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
        transport="stdio",
    )
    artifact = _artifact(runtime, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_identity_mismatch_does_not_apply(tmp_path: Path) -> None:
    identity = _identity()
    other = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-github"),
        transport="stdio",
    )
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"})
    artifact = _artifact(other, "read_file")
    assert matching_local_mcp_grant(store=store, artifact=artifact, current_action="review") is None


def test_recognize_mcp_package_persists_tools(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    identity = _identity()

    def _probe(command: str, **_kwargs):
        return McpProbeResult(
            identity=UnlistedCliIdentity(
                cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
                name="@modelcontextprotocol/server-filesystem",
                kind="executable",
                identity_hash=identity.identity_hash,
                example_label=command,
            ),
            server_identity=identity,
            tools=(
                LocalCliCommand("read_file", "read_file", "read_file", "Read a file"),
                LocalCliCommand("other", "Other tools", "server …", "other"),
            ),
            status="ok",
            argv=("npx", "-y", "@modelcontextprotocol/server-filesystem"),
        )

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        _probe,
    )
    service = LocalCliApiService(store=GuardStore(home))
    result = service.recognize({"command": "npx -y @modelcontextprotocol/server-filesystem"})
    item = result["item"]
    assert isinstance(item, dict)
    assert item["surface"] == "mcp"
    assert item["server_identity_hash"] == identity.identity_hash
    ids = [entry["command_id"] for entry in item["commands"]]
    assert "read_file" in ids
    assert "other" in ids
    assert "MCP server" in str(result["summary"]) or "tools" in str(result["summary"]).lower()


def test_recognize_failed_package_mcp_stays_built_in(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        lambda *args, **kwargs: None,
    )
    service = LocalCliApiService(store=GuardStore(home))
    try:
        service.recognize({"command": "npx -y cowsay"})
    except LocalCliApiError as exc:
        assert exc.code == "already_built_in"
        assert "MCP tools" in str(exc)
    else:
        raise AssertionError("expected package launcher without MCP tools to be rejected")
