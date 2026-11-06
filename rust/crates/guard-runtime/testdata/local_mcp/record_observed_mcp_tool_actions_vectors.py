"""Record observed-MCP tool action parity vectors from the Python compiler.

Run from a checkout whose ``native_observed_mcp_tool_actions`` still compiles
the actions in Python. Each vector seeds a real ``GuardStore`` through its own
write API (plus raw rows for states the API refuses), records the actions the
Python compiler returned and dumps the local CLI rows the compiler read.

Server identities come from the native resident, so run it with an isolated
``HOME``, ``HOL_GUARD_NATIVE=force`` and ``HOL_GUARD_NATIVE_BINARY`` naming a
compiled runtime.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.runtime.local_cli_commands import (
    OTHER_COMMAND_ID,
    LocalCliCommand,
    LocalCliCommandState,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import (
    ObservedMcpTool,
    native_observed_mcp_tool_actions,
    observed_mcp_tool,
)
from codex_plugin_scanner.guard.store import GuardStore

_TABLES = (
    "local_cli_schema_migration",
    "local_cli_observation",
    "local_cli_grant",
    "local_cli_command",
    "local_cli_command_grant",
)
_SEEN = "2026-10-11T10:00:00+00:00"


def _tool(harness: str, name: str) -> ObservedMcpTool:
    tool = observed_mcp_tool(harness, name)
    assert tool is not None, name
    return tool


def _observe(store: GuardStore, tool: ObservedMcpTool, *, seen_at: str = _SEEN) -> None:
    server = tool.server_identity
    store.record_local_cli_observation(
        tool.identity,
        seen_at=seen_at,
        surface="mcp",
        server_identity_hash=server.identity_hash,
        server_command=server.command,
        server_args_hash=server.args_hash,
    )


def _catalog(store: GuardStore, cli_id: str, tools: list[ObservedMcpTool], extra: tuple[LocalCliCommand, ...] = ()):
    commands = [LocalCliCommand(tool.command_id, tool.name, tool.qualified_name, "Observed tool") for tool in tools]
    store.replace_local_cli_commands(cli_id, (*commands, *extra))


def _grant(store: GuardStore, identity: UnlistedCliIdentity, state: str, states: dict[str, str] | None = None) -> None:
    store.upsert_local_cli_grant(
        identity=identity,
        state=state,
        expected_revision=store.read_local_cli_revision(),
        updated_at=_SEEN,
        command_states=cast("dict[str, LocalCliCommandState] | None", states),
    )


def _sql(store: GuardStore, statement: str, parameters: tuple[object, ...] = ()) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.execute(statement, parameters)


def _connector(store: GuardStore, harness: str, names: list[str], state: str, states: dict[str, str]):
    tools = [_tool(harness, name) for name in names]
    _observe(store, tools[0])
    # Discovery lists the "other tools" fallback beside the observed tools.
    other = (LocalCliCommand(OTHER_COMMAND_ID, "Other tools", OTHER_COMMAND_ID, "Tools not yet seen"),)
    _catalog(store, tools[0].identity.cli_id, tools, other if OTHER_COMMAND_ID in states else ())
    by_name = {tool.qualified_name: tool.command_id for tool in tools}
    _grant(store, tools[0].identity, state, {by_name.get(key, key): value for key, value in states.items()})
    return tools


SEARCH = "mcp__codex_apps__composio__search"
EXECUTE = "mcp__codex_apps__composio__execute"
GITHUB = "mcp__github__create_issue"
GITHUB_READ = "mcp__github__get_issue"


def empty(store: GuardStore) -> None:
    del store


def schema_only(store: GuardStore) -> None:
    store.read_local_cli_revision()


def observed_without_grant(store: GuardStore) -> None:
    tool = _tool("codex", SEARCH)
    _observe(store, tool)
    _catalog(store, tool.identity.cli_id, [tool])


def allowed_exact_states(store: GuardStore) -> None:
    _connector(
        store,
        "codex",
        [SEARCH, EXECUTE, "mcp__codex_apps__composio__list"],
        "allowed",
        {SEARCH: "allow", EXECUTE: "block", "mcp__codex_apps__composio__list": "review"},
    )


def inherit_state_is_omitted(store: GuardStore) -> None:
    _connector(store, "codex", [SEARCH, EXECUTE], "allowed", {SEARCH: "inherit", EXECUTE: "allow"})


def blocked_connector(store: GuardStore) -> None:
    _connector(store, "codex", [SEARCH], "blocked", {})


def blocked_connector_ignores_tool_allows(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH, EXECUTE], "allowed", {SEARCH: "allow", EXECUTE: "allow"})
    _grant(store, tools[0].identity, "blocked")


def other_tools_blocked(store: GuardStore) -> None:
    _connector(store, "claude-code", [GITHUB, GITHUB_READ], "allowed", {GITHUB_READ: "allow", "other": "block"})


def other_tools_allowed_is_not_an_action(store: GuardStore) -> None:
    _connector(store, "claude-code", [GITHUB], "allowed", {GITHUB: "review", "other": "allow"})


def unset_grant_still_compiles_tool_states(store: GuardStore) -> None:
    _connector(store, "codex", [SEARCH], "unset", {SEARCH: "block"})


def two_harnesses(store: GuardStore) -> None:
    _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    _connector(store, "cursor", [GITHUB], "blocked", {})
    _connector(store, "claude-code", [GITHUB], "allowed", {GITHUB: "block"})


def stale_grant_identity(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    _sql(store, "update local_cli_grant set identity_hash = ? where cli_id = ?", ("f" * 64, tools[0].identity.cli_id))


def grant_without_observation(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "blocked", {})
    _sql(store, "delete from local_cli_observation where cli_id = ?", (tools[0].identity.cli_id,))


def configured_server_is_not_observed(store: GuardStore) -> None:
    identity = UnlistedCliIdentity("local-cli.mcp-configured", "github", "executable", "a" * 64, "github")
    store.record_local_cli_observation(
        identity,
        seen_at=_SEEN,
        surface="mcp",
        server_identity_hash="a" * 64,
        server_command="npx",
        server_args_hash="b" * 64,
    )
    _grant(store, identity, "blocked")


def cli_surface_with_observed_marker(store: GuardStore) -> None:
    tool = _tool("codex", SEARCH)
    server = tool.server_identity
    store.record_local_cli_observation(
        tool.identity,
        seen_at=_SEEN,
        surface="cli",
        server_identity_hash=server.identity_hash,
        server_command=server.command,
        server_args_hash=server.args_hash,
    )
    _grant(store, tool.identity, "blocked")


def marker_without_separator(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "blocked", {})
    _sql(
        store,
        "update local_cli_observation set server_command = ? where cli_id = ?",
        ("observed-mcp:codex", tools[0].identity.cli_id),
    )


def marker_with_unknown_harness(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "blocked", {})
    _sql(
        store,
        "update local_cli_observation set server_command = ? where cli_id = ?",
        ("observed-mcp:not-a-harness:mcp__codex_apps__composio__", tools[0].identity.cli_id),
    )


def marker_with_bad_namespace(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "blocked", {})
    _sql(
        store,
        "update local_cli_observation set server_command = ? where cli_id = ?",
        ("observed-mcp:codex:mcp__codex_apps__", tools[0].identity.cli_id),
    )


def marker_for_another_connector(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "blocked", {})
    other = _tool("codex", GITHUB)
    _sql(
        store,
        "update local_cli_observation set server_command = ? where cli_id = ?",
        (other.server_identity.command, tools[0].identity.cli_id),
    )


def marker_with_uppercase_harness(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "blocked", {})
    _sql(
        store,
        "update local_cli_observation set server_command = ? where cli_id = ?",
        ("observed-mcp:CODEX:mcp__codex_apps__composio__", tools[0].identity.cli_id),
    )


def harness_alias_marker(store: GuardStore) -> None:
    tool = _tool("claude", GITHUB)
    _connector(store, "claude", [GITHUB], "allowed", {GITHUB: "block"})
    del tool


def item_identity_differs_from_marker(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "blocked", {})
    cli_id = tools[0].identity.cli_id
    _sql(store, "update local_cli_observation set identity_hash = ? where cli_id = ?", ("e" * 64, cli_id))
    _sql(store, "update local_cli_grant set identity_hash = ? where cli_id = ?", ("e" * 64, cli_id))


def command_outside_namespace(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    foreign = _tool("codex", GITHUB)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, sort_index)"
            " values (?, ?, ?, ?, ?, null, 9)",
            (tools[0].identity.cli_id, foreign.command_id, foreign.name, foreign.qualified_name, "Foreign"),
        )
        connection.execute(
            "insert into local_cli_command_grant (cli_id, command_id, state) values (?, ?, 'allow')",
            (tools[0].identity.cli_id, foreign.command_id),
        )


def command_id_mismatch(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, sort_index)"
            " values (?, 'execute', 'execute', ?, 'Slug id', null, 9)",
            (tools[0].identity.cli_id, EXECUTE),
        )
        connection.execute(
            "insert into local_cli_command_grant (cli_id, command_id, state) values (?, 'execute', 'block')",
            (tools[0].identity.cli_id,),
        )


def unparseable_usage(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, sort_index)"
            " values (?, 'bad', 'bad', 'not an mcp tool', 'Bad', null, 9)",
            (tools[0].identity.cli_id,),
        )
        connection.execute(
            "insert into local_cli_command_grant (cli_id, command_id, state) values (?, 'bad', 'block')",
            (tools[0].identity.cli_id,),
        )


def state_without_catalog_entry(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    _sql(store, "delete from local_cli_command where cli_id = ?", (tools[0].identity.cli_id,))


def other_command_in_catalog_only(store: GuardStore) -> None:
    _connector(store, "codex", [SEARCH], "allowed", {"other": "review"})


def duplicate_identity_reads_newest_grant(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    first = tools[0].identity
    twin = UnlistedCliIdentity(
        cli_id=first.cli_id + "-twin",
        name=first.name,
        kind=first.kind,
        identity_hash=first.identity_hash,
        example_label=first.example_label,
    )
    server = tools[0].server_identity
    store.record_local_cli_observation(
        twin,
        seen_at="2026-10-11T11:00:00+00:00",
        surface="mcp",
        server_identity_hash=server.identity_hash,
        server_command=server.command,
        server_args_hash=server.args_hash,
    )
    store.replace_local_cli_commands(
        twin.cli_id, (LocalCliCommand(tools[0].command_id, tools[0].name, tools[0].qualified_name, "Twin"),)
    )
    _grant(store, twin, "allowed", {tools[0].command_id: "block"})


def duplicate_identity_newest_without_grant(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    first = tools[0].identity
    server = tools[0].server_identity
    store.record_local_cli_observation(
        UnlistedCliIdentity(first.cli_id + "-twin", first.name, first.kind, first.identity_hash, first.example_label),
        seen_at="2026-10-11T11:00:00+00:00",
        surface="mcp",
        server_identity_hash=server.identity_hash,
        server_command=server.command,
        server_args_hash=server.args_hash,
    )


def null_server_identity_hash(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "block"})
    _sql(
        store,
        "update local_cli_observation set server_identity_hash = null where cli_id = ?",
        (tools[0].identity.cli_id,),
    )


def foreign_server_identity_hash(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "block"})
    _sql(
        store,
        "update local_cli_observation set server_identity_hash = ? where cli_id = ?",
        ("d" * 64, tools[0].identity.cli_id),
    )


def later_item_overrides_earlier(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    first = tools[0].identity
    server = tools[0].server_identity
    twin = UnlistedCliIdentity(first.cli_id + "-old", first.name, first.kind, first.identity_hash, first.example_label)
    store.record_local_cli_observation(
        twin,
        seen_at="2026-10-11T09:00:00+00:00",
        surface="mcp",
        server_identity_hash=server.identity_hash,
        server_command=server.command,
        server_args_hash=server.args_hash,
    )
    store.replace_local_cli_commands(
        twin.cli_id, (LocalCliCommand(tools[0].command_id, tools[0].name, tools[0].qualified_name, "Old"),)
    )
    _grant(store, twin, "blocked")


def catalog_order_last_write_wins(store: GuardStore) -> None:
    tools = _connector(store, "codex", [SEARCH], "allowed", {SEARCH: "allow"})
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, sort_index)"
            " values (?, 'zz-copy', 'search', ?, 'Copy', null, 9)",
            (tools[0].identity.cli_id, SEARCH),
        )


def many_tools(store: GuardStore) -> None:
    names = [f"mcp__github__tool_{index:02d}" for index in range(12)]
    states = {name: ("allow", "review", "block", "inherit")[index % 4] for index, name in enumerate(names)}
    _connector(store, "codex", names, "allowed", states)


def tool_names_with_dots_and_dashes(store: GuardStore) -> None:
    _connector(
        store,
        "opencode",
        ["mcp__my-server.v2__do_thing", "mcp__my-server.v2__other.thing"],
        "allowed",
        {"mcp__my-server.v2__do_thing": "allow", "mcp__my-server.v2__other.thing": "review", "other": "block"},
    )


VECTORS: dict[str, Callable[[GuardStore], None]] = {
    function.__name__: function
    for function in (
        empty,
        schema_only,
        observed_without_grant,
        allowed_exact_states,
        inherit_state_is_omitted,
        blocked_connector,
        blocked_connector_ignores_tool_allows,
        other_tools_blocked,
        other_tools_allowed_is_not_an_action,
        unset_grant_still_compiles_tool_states,
        two_harnesses,
        stale_grant_identity,
        grant_without_observation,
        configured_server_is_not_observed,
        cli_surface_with_observed_marker,
        marker_without_separator,
        marker_with_unknown_harness,
        marker_with_bad_namespace,
        marker_for_another_connector,
        marker_with_uppercase_harness,
        harness_alias_marker,
        item_identity_differs_from_marker,
        command_outside_namespace,
        command_id_mismatch,
        unparseable_usage,
        state_without_catalog_entry,
        other_command_in_catalog_only,
        duplicate_identity_reads_newest_grant,
        duplicate_identity_newest_without_grant,
        null_server_identity_hash,
        foreign_server_identity_hash,
        later_item_overrides_earlier,
        catalog_order_last_write_wins,
        many_tools,
        tool_names_with_dots_and_dashes,
    )
}


def _dump(path: Path) -> tuple[dict[str, list[dict[str, object]]], list[str]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    present = {
        row["name"]: row["sql"]
        for row in connection.execute("select name, sql from sqlite_master where type = 'table'")
    }
    rows: dict[str, list[dict[str, object]]] = {}
    schema: list[str] = []
    for table in _TABLES:
        if table not in present:
            continue
        schema.append(present[table])
        rows[table] = [dict(row) for row in connection.execute(f"select * from {table} order by rowid")]
    connection.close()
    return rows, schema


def main() -> None:
    from codex_plugin_scanner.guard.native_context import _resolve_digest_home, native_context_digest
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    try:
        # A debug resident can take far longer than the hook budget to start.
        native_context_digest(
            "mcp_server_identity",
            {"request": {"config_path": "", "command": "warm", "args": [], "transport": "observed"}},
            guard_home=_resolve_digest_home(None),
            timeout_seconds=60,
        )
        _record()
    finally:
        close_native_residents(_resolve_digest_home(None))


def _record() -> None:
    vectors = []
    schema: list[str] = []
    for name, seed in VECTORS.items():
        with tempfile.TemporaryDirectory() as home:
            store = GuardStore(Path(home) / "guard-home")
            seed(store)
            actions = native_observed_mcp_tool_actions(store)
            rows, tables = _dump(store.path)
        if len(tables) > len(schema):
            schema = tables
        vectors.append({"name": name, "rows": rows, "expected": actions})
    document = {"schema": schema, "vectors": vectors}
    json.dump(document, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
