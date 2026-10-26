"""Scenarios for the observed MCP connection parity vectors.

Run by the recorder through the ORIGINAL Python store. Steps are either
`{"sql": [(statement, params), ...]}` or `{"method", "kwargs"}`; an
`identity` kwarg is the `UnlistedCliIdentity` fields as a dict.
"""

from __future__ import annotations

#: The wall clock the vectors assume wherever Python fell back to now.
NOW = "2026-10-10T12:00:00+00:00"
D0 = "2026-10-01T00:00:00+00:00"
D2 = "2026-10-03T00:00:00+00:00"
D5 = "2026-10-06T00:00:00+00:00"
D60_AGO = "2026-08-02T00:00:00+00:00"

H_A, H_B, H_C, H_D, H_E, H_S, H_T = ("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64, "5" * 64, "6" * 64)
ARGS_1, ARGS_2 = "1" * 64, "2" * 64


def mcp_row(
    cli_id: str,
    digest: str,
    seen_at: str,
    *,
    server: str | None = None,
    command: str | None = "npx",
    args_hash: str | None = ARGS_1,
    surface: str = "mcp",
    label: str | None = None,
) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_observation (cli_id, identity_hash, kind, name, interpreter_name, example_label, "
        "observed_count, last_seen_at, surface, server_identity_hash, server_command, server_args_hash, "
        "source_label) values (?, ?, 'executable', ?, null, ?, 2, ?, ?, ?, ?, ?, ?)",
        [cli_id, digest, cli_id[10:], cli_id[10:], seen_at, surface, server, command, args_hash, label],
    )


def grant_row(cli_id: str, digest: str, state: str = "allowed") -> tuple[str, list[object]]:
    return (
        "insert into local_cli_grant (cli_id, identity_hash, state, revision, updated_at) values (?, ?, ?, 1, ?)",
        [cli_id, digest, state, D0],
    )


def find(label: str = "", **kwargs: object) -> dict[str, object]:
    return {"method": "find_local_mcp_observation", "label": label, "kwargs": kwargs}


def ensure(
    name: str,
    digest: str,
    seen_at: str,
    label: str = "",
    *,
    server: str = H_S,
    command: str = "npx",
    args_hash: str = ARGS_1,
    cli_id: str | None = None,
    **kwargs: object,
) -> dict[str, object]:
    identity = {
        "cli_id": cli_id or f"local-cli.{name}",
        "name": name,
        "kind": "executable",
        "identity_hash": digest,
        "example_label": f"{name} server",
        "interpreter_name": None,
    }
    return {
        "method": "ensure_local_mcp_observation",
        "label": label,
        "kwargs": {
            "identity": identity,
            "seen_at": seen_at,
            "server_identity_hash": server,
            "server_command": command,
            "server_args_hash": args_hash,
            **kwargs,
        },
    }


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "find_lookups",
        "steps": [
            {
                "sql": [
                    mcp_row("local-cli.one", H_A, D0, server=H_S),
                    mcp_row("local-cli.two", H_B, D2, server=H_T, args_hash=ARGS_2, label="Codex"),
                    mcp_row("local-cli.three", H_C, D5, server=H_T, args_hash=ARGS_2),
                    mcp_row("local-cli.cli-row", H_D, D0, surface="cli", server=H_E),
                    mcp_row("local-cli.legacy", H_E, D0, server=None, command="uvx", args_hash=ARGS_2),
                ]
            },
            find("nothing supplied"),
            find("command without args hash", command="npx"),
            find("by cli id", cli_id="local-cli.one"),
            find("invalid cli id falls back to the hash", cli_id="local-cli.One", server_identity_hash=H_S),
            find("cli id never falls through", cli_id="local-cli.missing", server_identity_hash=H_S),
            find("uppercase server hash", server_identity_hash=H_S.upper()),
            find("identity hash column matches", server_identity_hash=H_E),
            find("two rows share a server hash", server_identity_hash=H_T),
            find(
                "non-hex hash falls back to the launch", server_identity_hash="z" * 64, command="uvx", args_hash=ARGS_2
            ),
            find("short hash with an ambiguous launch", server_identity_hash="ab", command="npx", args_hash=ARGS_2),
            find("hash never falls through to the launch", server_identity_hash=H_D, command="npx", args_hash=ARGS_1),
            find("cli surface rows are ignored", cli_id="local-cli.cli-row"),
        ],
    },
    {
        "name": "ensure_insert_and_refresh",
        "steps": [
            ensure("Bad", H_A, D0, "invalid id", cli_id="local-cli.Bad"),
            ensure("alpha", H_A, D0, "first sighting inserts and prunes", source_label="Codex · config"),
            ensure("alpha", H_A, D2, "refresh by server hash keeps count", source_label=None),
            ensure(
                "alpha-renamed",
                H_A,
                D5,
                "refresh renames and relabels",
                cli_id="local-cli.alpha",
                source_label="Claude",
            ),
            ensure(
                "beta",
                H_B,
                D5,
                "connection hash looks up a separate connection",
                server=H_T,
                connection_identity_hash=H_B,
            ),
            ensure(
                "beta",
                H_B,
                "2026-10-07T00:00:00+00:00",
                "connection hash finds the stored connection",
                server=H_T,
                connection_identity_hash=H_B,
            ),
            {
                "sql": [
                    mcp_row("local-cli.gamma", H_C, D0, server=None, command=None, args_hash=None),
                    mcp_row("local-cli.stale", H_D, D60_AGO, server=H_E, command="old", args_hash=ARGS_2),
                    ("delete from local_cli_retention_state", []),
                ]
            },
            ensure("gamma", H_C, D2, "server hash matches the identity column and fills nulls", server=H_C),
            ensure(
                "delta",
                H_D,
                "not a time",
                "server hash naming another identity refreshes that record",
                server=H_A,
                command="node",
            ),
        ],
    },
    {
        "name": "ensure_id_collisions",
        "steps": [
            {
                "sql": [
                    mcp_row("local-cli.taken", H_A, D0, server=H_S, command="other", args_hash=ARGS_2),
                    mcp_row("local-cli.dup", H_C, D0, server=H_T, command="x", args_hash=ARGS_2),
                    mcp_row("local-cli.dup-two", H_C, D0, server=H_T, command="x", args_hash=ARGS_2),
                    mcp_row("local-cli.same", H_D, D0, surface="cli", server=None, command=None, args_hash=None),
                ]
            },
            ensure("taken", H_B, D2, "taken id with another identity uses the collision id", server=H_B, command="new"),
            ensure("taken", H_B, D5, "second sighting finds the collision row", server=H_B, command="new"),
            {"sql": [("delete from local_cli_observation where cli_id = 'local-cli.mcp-bbbbbbbbbbbb'", [])]},
            {"sql": [mcp_row("local-cli.mcp-bbbbbbbbbbbb", H_E, D0, surface="cli", command=None, args_hash=None)]},
            ensure("taken", H_B, D5, "collision id also taken returns the original", server=H_B, command="new"),
            ensure("same", H_D, D2, "taken id with the same identity refreshes it", server=H_D, command="same"),
            ensure(
                "dup",
                H_C,
                D2,
                "ambiguous launch refreshes the record holding the id",
                server=H_T,
                command="x",
                args_hash=ARGS_2,
            ),
        ],
    },
    {
        "name": "ensure_replay",
        "steps": [
            {
                "sql": [
                    mcp_row("local-cli.listed", H_A, D5, server=H_S),
                    ("insert into local_cli_forgotten values (?, ?)", [H_B, D2]),
                    ("insert into local_cli_retention_state values (1, ?)", ["2026-09-01T00:00:00+00:00"]),
                    mcp_row("local-cli.expired", H_E, D60_AGO, server=H_E, command="exp", args_hash=ARGS_2),
                ]
            },
            ensure("listed", H_A, D2, "older replay keeps the later stored time", replayed=True),
            ensure("listed", H_A, "2026-10-08T00:00:00Z", "later replay moves forward", replayed=True),
            ensure("listed", H_A, "garbled", "unparsable replay keeps the stored time", replayed=True),
            ensure("forgot", H_B, D0, "forgotten identity is skipped", server=H_B, command="f", replayed=True),
            ensure(
                "forgot",
                H_B,
                D5,
                "seen after the forget is restored without pruning",
                server=H_B,
                command="f",
                replayed=True,
            ),
            ensure("ancient", H_C, D60_AGO, "too old for the clock", server=H_C, command="a", replayed=True),
            ensure(
                "ancient",
                H_C,
                D60_AGO,
                "inside the window of the replay time",
                server=H_C,
                command="a",
                replayed=True,
                replay_now="2026-08-10T00:00:00Z",
            ),
        ],
    },
    {
        "name": "ensure_legacy_denial",
        "steps": [
            {
                "sql": [
                    mcp_row("local-cli.legacy-deny", H_S, D0, server=None, command="npx", args_hash=ARGS_1),
                    grant_row("local-cli.legacy-deny", H_S, "blocked"),
                    mcp_row("local-cli.legacy-choice", H_T, D0, server=H_T, command="uvx", args_hash=ARGS_2),
                    grant_row("local-cli.legacy-choice", H_T),
                    (
                        "insert into local_cli_command_grant (cli_id, command_id, state) values (?, 'tool', 'block')",
                        ["local-cli.legacy-choice"],
                    ),
                    mcp_row("local-cli.legacy-allow", H_E, D0, server=H_E, command="node", args_hash=ARGS_2),
                    grant_row("local-cli.legacy-allow", H_E),
                ]
            },
            ensure("conn-a", H_A, D2, "blocked legacy grant carries", connection_identity_hash=H_A),
            ensure("conn-b", H_B, D2, "carries to a second connection", connection_identity_hash=H_B),
            ensure("conn-a", H_A, D5, "known connection is not a legacy candidate", connection_identity_hash=H_A),
            ensure(
                "conn-c",
                H_C,
                D2,
                "blocked command choice carries",
                server=H_T,
                command="uvx",
                args_hash=ARGS_2,
                connection_identity_hash=H_C,
            ),
            ensure(
                "conn-d",
                H_D,
                D2,
                "legacy allow never crosses",
                server=H_E,
                command="node",
                args_hash=ARGS_2,
                connection_identity_hash=H_D,
            ),
            ensure(
                "conn-e",
                H_S,
                D2,
                "same connection and server hash is not legacy",
                connection_identity_hash=H_S,
                command="npx",
            ),
        ],
    },
]
