"""Rich catalogs retain choices independently of bounded native publication."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.runtime.local_cli_commands import (
    MAX_LOCAL_CLI_COMMANDS,
    LocalCliCommand,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import MAX_MCP_PROBE_TOOLS, McpCatalogResult
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .native_policy_snapshot_test_fixtures import _ack, _status


def test_ten_thousand_tools_keep_per_connection_choices(tmp_path: Path) -> None:
    assert MAX_MCP_PROBE_TOOLS == 100
    assert MAX_LOCAL_CLI_COMMANDS == MAX_MCP_PROBE_TOOLS + 1  # Reserve Other tools.
    store = GuardStore(tmp_path / "guard-home")
    names = tuple(f"tool_{index:03}" for index in range(100))
    commands = (
        *(LocalCliCommand(name, name, name, "Fixture tool") for name in names),
        LocalCliCommand("other", "Other tools", "fixture …", "Unknown tools need review"),
    )
    submitted_states = LocalCliApiService(store=store)._command_states_from_payload(
        {
            "commands": [{"command_id": command.command_id, "state": "block"} for command in commands],
        }
    )
    assert len(submitted_states) == 101 and submitted_states["other"] == "block"
    catalog = McpCatalogResult(
        tuple({"name": name, "inputSchema": {"type": "object"}} for name in names),
        complete=True,
        pages=1,
        protocol_version="2026-07-28",
    )
    identities = []
    seen_at = utc_now()
    for index in range(100):
        server = build_mcp_server_identity(
            config_path="",
            command="npx",
            args=("-y", f"@fixture/server-{index:03}"),
            transport="stdio",
        )
        identity = UnlistedCliIdentity(
            cli_id=f"local-cli.scale-{index:03}",
            name=f"Fixture connector {index:03}",
            kind="executable",
            identity_hash=server.identity_hash,
            example_label=f"fixture-{index:03}",
        )
        identities.append(server)
        store.record_local_cli_observation(
            identity,
            seen_at=seen_at,
            surface="mcp",
            server_identity_hash=server.identity_hash,
            server_command=server.command,
            server_args_hash=server.args_hash,
            help_status="ok",
        )
        store.replace_local_cli_commands(
            identity.cli_id,
            commands,
            mcp_catalog=catalog,
            identity_hash=identity.identity_hash,
            seen_at=seen_at,
        )
        store.upsert_local_cli_grant(
            identity=identity,
            state="allowed",
            expected_revision=store.read_local_cli_revision(),
            updated_at=seen_at,
            command_states={name: "allow" if tool_index % 2 == 0 else "block" for tool_index, name in enumerate(names)},
        )

    items = store.list_local_cli_items()
    assert len(items) == 100
    known_count = 0
    for item in items:
        summary = item.get("mcp_catalog")
        assert isinstance(summary, dict)
        count = summary.get("known_count")
        assert isinstance(count, int)
        known_count += count
        commands_for_item = item.get("commands")
        assert isinstance(commands_for_item, list) and len(commands_for_item) == 101
    assert known_count == 10_000
    for server in identities:
        grant = store.read_local_mcp_grant(server.identity_hash)
        assert grant is not None
        states = grant.get("command_states")
        assert isinstance(states, dict) and len(states) == 100
        assert states["tool_000"] == "allow"
        assert states["tool_099"] == "block"

    config = GuardConfig(guard_home=store.guard_home, workspace=tmp_path / "workspace", mode="prompt")
    for index in (0, 99):
        server = identities[index]
        for name, expected in (("tool_000", "allow"), ("tool_099", "block")):
            artifact = build_tool_call_artifact(
                harness="codex",
                server_name=f"server-{index:03}",
                tool_name=name,
                source_scope="project",
                config_path=".mcp.json",
                transport="stdio",
                server_identity=server,
                tool_definition={"name": name, "inputSchema": {"type": "object"}},
            )
            arguments: dict[str, object] = {}
            decision = evaluate_tool_call(
                store=store,
                config=config,
                artifact=artifact,
                artifact_hash=build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=config),
                arguments=arguments,
                claim_saved_approval=False,
            )
            assert decision.action == expected
            assert decision.source == "local-mcp-extension"


def test_large_observed_catalog_publishes_choices_and_reports_capacity_without_losing_grants(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store._policy_integrity_secret_material = lambda *, create: (b"m" * 32, "fixture")
    seen_at = utc_now()
    connections = []
    for index in range(100):
        observed = [
            observed_mcp_tool("codex", f"mcp__fixture_{index:03}__tool_{tool_index:03}") for tool_index in range(100)
        ]
        assert all(tool is not None for tool in observed)
        tools = [tool for tool in observed if tool is not None]
        server, identity = tools[0].server_identity, tools[0].identity
        connections.append((identity, server, tools))
        store.record_local_cli_observation(
            identity,
            seen_at=seen_at,
            surface="mcp",
            server_identity_hash=server.identity_hash,
            server_command=server.command,
            server_args_hash=server.args_hash,
            help_status="ok",
        )
        store.replace_local_cli_commands(
            identity.cli_id,
            tuple(LocalCliCommand(tool.command_id, tool.name, tool.qualified_name, "Fixture tool") for tool in tools),
            mcp_catalog=McpCatalogResult(
                tuple({"name": tool.qualified_name, "inputSchema": {"type": "object"}} for tool in tools),
                complete=True,
                pages=1,
                protocol_version="2026-07-28",
            ),
            identity_hash=identity.identity_hash,
            seen_at=seen_at,
        )
        store.upsert_local_cli_grant(
            identity=identity,
            state="allowed",
            updated_at=seen_at,
            expected_revision=store.read_local_cli_revision(),
            command_states={
                tool.command_id: "allow" if tool_index % 2 == 0 else "block"
                for tool_index, tool in enumerate(tools[:10])
            },
        )

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=lambda **kwargs: _ack(kwargs["payload"], guard_home=kwargs.get("guard_home")),
    )
    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert publisher._snapshot is not None
        actions = publisher._snapshot["effective_policy"]["mcp_tool_actions"]
        assert len(actions) == 1000
        for _identity, _server, tools in connections:
            for tool_index, tool in enumerate(tools[:10]):
                assert actions[f"codex:{tool.qualified_name}"] == ("allow" if tool_index % 2 == 0 else "block")
            assert f"codex:{tools[99].qualified_name}" not in actions

        # Exceed the restriction bound, which must never discard a Deny.
        for identity, _server, tools in connections[:6]:
            store.upsert_local_cli_grant(
                identity=identity,
                state="allowed",
                updated_at=seen_at,
                expected_revision=store.read_local_cli_revision(),
                command_states={tool.command_id: "block" for tool in tools},
            )
        publisher.request_publish()
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_mcp_permission_capacity_exceeded"
        assert publisher.local_cli_publication_receipt(store.read_local_cli_revision()) is None
        for _identity, server, tools in connections[:6]:
            grant = store.read_local_mcp_grant(server.identity_hash)
            assert grant is not None
            assert grant["command_states"] == {tool.command_id: "block" for tool in tools}
    finally:
        publisher.close()
