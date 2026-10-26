"""Scenarios for the local CLI inventory read parity vectors.

Run by the recorder through the ORIGINAL Python store. Steps are either
`{"sql": [(statement, params), ...]}` or `{"method", "kwargs"}`.

`list_local_cli_items` takes no arguments, so every scenario is a seed built
with SQL and one read of the whole inventory. The recorder runs with the
native resident off, which leaves the ranking and MCP classification fields at
their defaults; the replay normalizes those three fields away on both sides and
covers them separately.
"""

from __future__ import annotations

import json

D0 = "2026-10-01T00:00:00+00:00"
D1 = "2026-10-02T00:00:00+00:00"
D2 = "2026-10-03T00:00:00+00:00"
H_A, H_B, H_C = "a" * 64, "b" * 64, "c" * 64
SERVER = "5" * 64


def call(label: str = "") -> dict[str, object]:
    return {"method": "list_local_cli_items", "label": label, "kwargs": {}}


def observation(
    cli_id: str,
    identity_hash: str = H_A,
    *,
    kind: str = "executable",
    name: str | None = None,
    interpreter_name: str | None = None,
    observed_count: int = 1,
    last_seen_at: str = D0,
    source_path: str | None = None,
    help_status: str | None = None,
    surface: str = "cli",
    server_identity_hash: str | None = None,
    server_command: str | None = None,
    source_label: str | None = None,
    remote_origin: str | None = None,
    declared_sources_json: str | None = None,
) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_observation (cli_id, identity_hash, kind, name, interpreter_name, "
        "example_label, observed_count, last_seen_at, source_path, help_status, surface, "
        "server_identity_hash, server_command, source_label, remote_origin, declared_sources_json) "
        "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            cli_id,
            identity_hash,
            kind,
            name or cli_id.removeprefix("local-cli."),
            interpreter_name,
            cli_id.removeprefix("local-cli."),
            observed_count,
            last_seen_at,
            source_path,
            help_status,
            surface,
            server_identity_hash,
            server_command,
            source_label,
            remote_origin,
            declared_sources_json,
        ],
    )


def grant(cli_id: str, identity_hash: str = H_A, state: str = "allowed", revision: int = 1) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_grant (cli_id, identity_hash, state, revision, updated_at) values (?, ?, ?, ?, ?)",
        [cli_id, identity_hash, state, revision, D0],
    )


def authority(revision: int) -> tuple[str, list[object]]:
    return ("update local_cli_authority set revision = ? where singleton = 1", [revision])


def command(cli_id: str, command_id: str, sort_index: int, usage: str | None = None) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, sort_index) "
        "values (?, ?, ?, ?, ?, ?, ?)",
        [
            cli_id,
            command_id,
            command_id.title(),
            usage or f"{command_id} [args]",
            f"Run {command_id}",
            None,
            sort_index,
        ],
    )


def command_state(cli_id: str, command_id: str, state: str) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_command_grant (cli_id, command_id, state) values (?, ?, ?)",
        [cli_id, command_id, state],
    )


def capability(cli_id: str, name: str, state: str) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_grant_capability (cli_id, capability, state, revision, updated_at) "
        "values (?, ?, ?, ?, ?)",
        [cli_id, name, state, 1, D0],
    )


def cause(cli_id: str, value: str | None) -> tuple[str, list[object]]:
    return ("update local_cli_observation set first_blocked_cause = ? where cli_id = ?", [value, cli_id])


def catalog(cli_id: str, identity_hash: str, payload: object, revision: int = 1) -> tuple[str, list[object]]:
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    return (
        "insert into local_mcp_catalog (cli_id, identity_hash, catalog_json, revision, updated_at, last_complete_at) "
        "values (?, ?, ?, ?, ?, ?)",
        [cli_id, identity_hash, raw, revision, D1, D2],
    )


def provider_action(
    cli_id: str, identity_hash: str, slug: str, full_schema: int, updated_at: str
) -> tuple[str, list[object]]:
    return (
        "insert into local_mcp_provider_action (cli_id, identity_hash, provider, tool_slug, toolkit, description, "
        "input_schema_json, authority_hash, full_schema, source_tool, revision, updated_at) "
        "values (?, ?, 'composio', ?, 'github', 'Do a thing', '{}', ?, ?, 'COMPOSIO_SEARCH', 1, ?)",
        [cli_id, identity_hash, slug, H_C, full_schema, updated_at],
    )


TOOLS = {
    "complete": True,
    "tools": [
        {"name": "fetch", "description": "Fetch a page", "inputSchema": {"type": "object"}},
        {"name": "write", "description": "Write a file", "inputSchema": {"type": "object"}},
    ],
}


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "empty_store",
        "steps": [call("nothing observed and nothing granted")],
    },
    {
        "name": "observations_and_grants",
        "steps": [
            {
                "sql": [
                    authority(7),
                    observation(
                        "local-cli.alpha", H_A, observed_count=4, last_seen_at=D2, source_path="/usr/bin/alpha"
                    ),
                    observation(
                        "local-cli.beta",
                        H_B,
                        kind="script",
                        interpreter_name="python3",
                        last_seen_at=D1,
                        help_status="captured",
                    ),
                    observation("local-cli.gamma", H_C, last_seen_at=D1, source_path="/opt/gamma"),
                    grant("local-cli.alpha", H_A, "allowed", 3),
                    grant("local-cli.beta", H_C, "blocked", 2),
                    grant("local-cli.delta", H_B, "allowed", 5),
                ]
            },
            call("merged grants, a stale grant, and a grant-only item"),
        ],
    },
    {
        "name": "commands_and_capabilities",
        "steps": [
            {
                "sql": [
                    observation("local-cli.alpha", H_A, source_path="/usr/bin/alpha"),
                    observation(
                        "local-cli.beta",
                        H_B,
                        surface="mcp",
                        server_identity_hash=SERVER,
                        server_command="/usr/bin/beta serve",
                    ),
                    grant("local-cli.alpha", H_A),
                    command("local-cli.alpha", "zeta", 1),
                    command("local-cli.alpha", "beta", 0),
                    command("local-cli.beta", "fetch", 0, usage="fetch"),
                    command_state("local-cli.alpha", "zeta", "block"),
                    capability("local-cli.alpha", "loopback-network", "on"),
                    capability("local-cli.alpha", "state-dir-write", "off"),
                    capability("local-cli.beta", "state-dir-read", "on"),
                    cause("local-cli.alpha", "read_home_state"),
                ]
            },
            call("commands, a capability map, and a suggested capability"),
        ],
    },
    {
        "name": "mcp_catalogs_and_providers",
        "steps": [
            {
                "sql": [
                    observation(
                        "local-cli.enrolled",
                        H_A,
                        surface="mcp",
                        server_identity_hash=SERVER,
                        server_command="/usr/bin/enrolled serve",
                        source_label="codex",
                        remote_origin="https://example.test/mcp",
                        declared_sources_json=json.dumps(["codex", "claude"]),
                    ),
                    observation("local-cli.sharer", H_B, surface="mcp", server_identity_hash=SERVER, last_seen_at=D1),
                    observation("local-cli.lonely", H_C, surface="mcp", server_identity_hash="9" * 64, last_seen_at=D1),
                    grant("local-cli.enrolled", H_A),
                    catalog("local-cli.enrolled", H_A, TOOLS, revision=4),
                    catalog("local-cli.sharer", H_C, TOOLS),
                    catalog("local-cli.lonely", H_C, "not json"),
                    command("local-cli.enrolled", "fetch", 0, usage="fetch"),
                    command("local-cli.enrolled", "absent", 1, usage="absent"),
                    provider_action("local-cli.enrolled", H_A, "GITHUB_STAR", 1, D1),
                    provider_action("local-cli.enrolled", H_A, "GITHUB_FORK", 0, D2),
                    provider_action("local-cli.sharer", H_A, "GITHUB_STAR", 1, D1),
                ]
            },
            call("catalogs, a shared enrolled server, and a provider summary"),
        ],
    },
]
