"""Scenarios for the custom-extension grant read parity vectors.

Run by the recorder through the ORIGINAL Python store. Steps are either
`{"sql": [(statement, params), ...]}` or `{"method", "kwargs"}`.
"""

from __future__ import annotations

D0 = "2026-10-01T00:00:00+00:00"
H_A, H_B = "a" * 64, "b" * 64


def call(method: str, label: str = "", **kwargs: object) -> dict[str, object]:
    return {"method": method, "label": label, "kwargs": kwargs}


def grant(cli_id: str, digest: str, state: str = "allowed", revision: int = 1) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_grant (cli_id, identity_hash, state, revision, updated_at) values (?, ?, ?, ?, ?)",
        [cli_id, digest, state, revision, D0],
    )


def command(cli_id: str, command_id: str, sort_index: int, parent: str | None = None) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, sort_index) "
        "values (?, ?, ?, ?, ?, ?, ?)",
        [cli_id, command_id, command_id.title(), f"{command_id} [args]", f"Run {command_id}", parent, sort_index],
    )


def command_state(cli_id: str, command_id: str, state: str) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_command_grant (cli_id, command_id, state) values (?, ?, ?)",
        [cli_id, command_id, state],
    )


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "grants",
        "steps": [
            call("read_local_cli_grant", "invalid id", cli_id="local-cli.Bad"),
            call("read_local_cli_grant", "no grant", cli_id="local-cli.alpha"),
            {"sql": [grant("local-cli.alpha", H_A, revision=3)]},
            call("read_local_cli_grant", "allowed grant", cli_id="local-cli.alpha"),
            {"sql": [grant("local-cli.beta", H_B, "blocked", 4)]},
            call("read_local_cli_grant", "blocked grant", cli_id="local-cli.beta"),
            call("read_local_cli_grant", "other grants stay unread", cli_id="local-cli.alpha"),
        ],
    },
    {
        "name": "command_catalog_and_states",
        "steps": [
            call("read_local_cli_command_catalog", "invalid id", cli_id="local-cli.Bad"),
            call("read_local_cli_command_states", "invalid id states", cli_id="local-cli.Bad"),
            call("read_local_cli_command_catalog", "empty catalog", cli_id="local-cli.alpha"),
            call("read_local_cli_command_states", "empty states", cli_id="local-cli.alpha"),
            {
                "sql": [
                    command("local-cli.alpha", "zeta", 0),
                    command("local-cli.alpha", "beta", 2, parent="zeta"),
                    command("local-cli.alpha", "alpha", 2),
                    command("local-cli.alpha", "gamma", 1),
                    command("local-cli.other", "omega", 0),
                    (
                        "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, "
                        "sort_index) values ('local-cli.alpha', 'blobname', x'00', 'u', 'd', null, 3)",
                        [],
                    ),
                    (
                        "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, "
                        "sort_index) values ('local-cli.alpha', 'blobparent', 'n', 'u', 'd', x'00', 4)",
                        [],
                    ),
                    (
                        "insert into local_cli_command (cli_id, command_id, name, usage, description, parent_id, "
                        "sort_index) values ('local-cli.alpha', 'numeric', 7, 8, 9, 10, 5)",
                        [],
                    ),
                    command_state("local-cli.alpha", "zeta", "allow"),
                    command_state("local-cli.alpha", "beta", "review"),
                    command_state("local-cli.alpha", "alpha", "inherit"),
                    command_state("local-cli.alpha", "gamma", "block"),
                    command_state("local-cli.other", "omega", "block"),
                    ("insert into local_cli_command_grant values ('local-cli.alpha', x'00', 'allow')", []),
                ]
            },
            call("read_local_cli_command_catalog", "ordered catalog skips non-text cells", cli_id="local-cli.alpha"),
            call("read_local_cli_command_states", "states skip non-text ids", cli_id="local-cli.alpha"),
            call("read_local_cli_command_catalog", "other extension", cli_id="local-cli.other"),
            call("read_local_cli_command_states", "other extension states", cli_id="local-cli.other"),
        ],
    },
]
