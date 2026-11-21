"""Scenarios for the observed custom-extension retention parity vectors.

Run by the recorder through the ORIGINAL Python store. Steps are either
`{"sql": [(statement, params), ...]}` or `{"method", "args", "kwargs"}`; an
`identity` kwarg is the `UnlistedCliIdentity` fields as a dict.
"""

from __future__ import annotations

#: The wall clock the vectors assume wherever Python fell back to now.
NOW = "2026-10-10T12:00:00+00:00"
D0 = "2026-10-01T00:00:00+00:00"
D0_LATER = "2026-10-01T18:00:00+00:00"
D2 = "2026-10-03T00:00:00+00:00"
D60_AGO = "2026-08-02T00:00:00+00:00"
D20_AGO = "2026-09-11T00:00:00+00:00"

H_A, H_B, H_C, H_D, H_E, H_S = ("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64, "5" * 64)


def identity(name: str, digest: str, **overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "cli_id": f"local-cli.{name}",
        "name": name,
        "kind": "executable",
        "identity_hash": digest,
        "example_label": name,
        "interpreter_name": None,
    }
    fields.update(overrides)
    return fields


def observe(name: str, digest: str, seen_at: str, label: str = "", **kwargs: object) -> dict[str, object]:
    ident = identity(name, digest, **kwargs.pop("identity_overrides", {}))  # type: ignore[arg-type]
    return {
        "method": "record_local_cli_observation",
        "label": label,
        "kwargs": {"identity": ident, "seen_at": seen_at, **kwargs},
    }


def observation_row(
    cli_id: str, digest: str, seen_at: str, *, surface: str = "cli", server: str | None = None
) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_observation (cli_id, identity_hash, kind, name, interpreter_name, example_label, "
        "observed_count, last_seen_at, surface, server_identity_hash, server_command, server_args_hash) "
        "values (?, ?, 'executable', ?, null, ?, 3, ?, ?, ?, null, null)",
        [cli_id, digest, cli_id[10:], cli_id[10:], seen_at, surface, server],
    )


def grant_row(cli_id: str, digest: str) -> tuple[str, list[object]]:
    return (
        "insert into local_cli_grant (cli_id, identity_hash, state, revision, updated_at) "
        "values (?, ?, 'allowed', 1, ?)",
        [cli_id, digest, D0],
    )


def inventory_rows(cli_id: str, digest: str) -> list[tuple[str, list[object]]]:
    return [
        (
            "insert into local_cli_command values (?, 'other', 'Other', 'tool …', 'Other commands', null, 0)",
            [cli_id],
        ),
        ("insert into local_mcp_catalog values (?, ?, '{}', 1, ?, null)", [cli_id, digest, D0]),
        ("insert into local_mcp_tool_authority values (?, ?, 'read', 1, ?)", [cli_id, digest, "f" * 64]),
        (
            "insert into local_mcp_provider_action values "
            "(?, ?, 'composio', 'SLUG', 'kit', 'desc', '{}', ?, 1, 'tool', 1, ?)",
            [cli_id, digest, "f" * 64, D0],
        ),
        ("insert into local_mcp_provider_authority values (?, ?, ?)", [cli_id, digest, "e" * 64]),
        ("insert into local_mcp_workflow_proposal values (?, ?, 'p1', '{}', ?)", [cli_id, digest, D0]),
    ]


def forget(cli_id: str, digest: str, label: str = "") -> dict[str, object]:
    return {
        "method": "forget_local_cli_observation",
        "label": label,
        "args": (cli_id,),
        "kwargs": {"identity_hash": digest},
    }


def replay(digest: str, seen_at: str, label: str = "", **kwargs: object) -> dict[str, object]:
    return {"method": "local_cli_replay_allowed", "label": label, "args": (digest, seen_at), "kwargs": kwargs}


def prune(label: str = "", **kwargs: object) -> dict[str, object]:
    return {"method": "prune_inactive_local_cli_observations", "label": label, "kwargs": kwargs}


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "record_insert_update_and_throttle",
        "steps": [
            observe("alpha", H_A, D0, "first sighting", source_path="/opt/bin/alpha", help_status="ok"),
            observe("alpha", H_A, D0_LATER, "same day keeps the prune throttle", surface="bogus"),
            observe(
                "alpha",
                H_B,
                D2,
                "identity change keeps stored optionals",
                identity_overrides={"kind": "script", "interpreter_name": "python3", "example_label": "py alpha"},
                server_command="node",
            ),
            observe("beta", H_C, "2026-10-04T00:00:00Z", "zulu instant", surface="package-scripts"),
            observe("gamma", H_D, "  2026-10-06T05:30:00+05:30 ", "padded offset instant", surface="mcp"),
            observe("delta", H_E, "2026-10-08T00:00:00", "naive instant"),
            observe("epsilon", H_S, "not a timestamp", "unparsable falls back to the clock"),
            {"sql": [("delete from local_cli_retention_state", [])]},
            observe("epsilon", H_S, "still not a timestamp", "clock fallback on update"),
        ],
    },
    {
        "name": "record_rejects_and_prunes",
        "steps": [
            observe("Bad_Name", H_A, D0, "invalid id", identity_overrides={"cli_id": "local-cli.Bad_Name"}),
            observe("x", H_A, D0, "trailing newline id", identity_overrides={"cli_id": "local-cli.x\n"}),
            {
                "sql": [
                    observation_row("local-cli.stale", H_B, D60_AGO),
                    *inventory_rows("local-cli.stale", H_B),
                    observation_row("local-cli.kept", H_C, D60_AGO),
                    grant_row("local-cli.kept", H_C),
                    observation_row("local-cli.enrolled-mcp", H_D, D60_AGO, surface="mcp", server=H_S),
                    grant_row("local-cli.enrolled-mcp", H_D),
                    observation_row("local-cli.sibling-mcp", H_E, D60_AGO, surface="mcp", server=H_S),
                    observation_row("local-cli.legacy-sibling", "1" * 64, D60_AGO, surface="mcp", server=H_C),
                    observation_row("local-cli.recent", "2" * 64, D20_AGO),
                    observation_row("local-cli.garbled", "3" * 64, "garbled"),
                    ("insert into local_cli_retention_state values (1, ?)", ["2026-09-30T13:00:00Z"]),
                ]
            },
            observe("fresh", H_A, D0, "throttled: inside a day of the last prune"),
            observe("fresh", H_A, "2026-10-01T13:00:00+00:00", "exactly a day later prunes expired rows"),
            {"sql": [("update local_cli_retention_state set last_pruned_at = 'nonsense'", [])]},
            observe("fresh", H_A, "2026-10-01T13:00:01+00:00", "unparsable last prune runs again"),
        ],
    },
    {
        "name": "record_only_if_missing_replay",
        "steps": [
            {
                "sql": [
                    observation_row("local-cli.present", H_A, D0),
                    ("insert into local_cli_forgotten values (?, ?)", [H_B, "2026-10-05T00:00:00Z"]),
                    ("insert into local_cli_forgotten values (?, ?)", [H_C, "not a time"]),
                    observation_row("local-cli.old", H_D, D60_AGO),
                ]
            },
            observe("present", H_A, D2, "existing row is left alone", only_if_missing=True),
            observe("forgot", H_B, "2026-10-05T00:00:00+00:00", "seen at the forget instant", only_if_missing=True),
            observe("forgot", H_B, "2026-10-04T23:00:00-02:00", "seen after forget via offset", only_if_missing=True),
            observe("garbled-forget", H_C, D2, "unparsable forget time allows", only_if_missing=True),
            observe("expired", H_E, D60_AGO, "older than the window", only_if_missing=True),
            observe(
                "expired",
                H_E,
                D60_AGO,
                "window measured from replayed_at",
                only_if_missing=True,
                replayed_at="2026-08-20T00:00:00Z",
            ),
            observe("unparsed", H_S, "whenever", "unparsable seen is allowed", only_if_missing=True),
            observe(
                "listed-hash",
                H_D,
                D60_AGO,
                "listed identity always refreshes",
                only_if_missing=True,
            ),
        ],
    },
    {
        "name": "forget_refusals_and_success",
        "steps": [
            {
                "sql": [
                    observation_row("local-cli.gone", H_A, D0),
                    *inventory_rows("local-cli.gone", H_A),
                    *inventory_rows("local-cli.other", H_B),
                    observation_row("local-cli.other", H_B, D0),
                    observation_row("local-cli.granted", H_C, D0),
                    grant_row("local-cli.granted", H_C),
                    observation_row("local-cli.server-owner", H_D, D0, surface="mcp", server=H_S),
                    grant_row("local-cli.server-owner", H_D),
                    observation_row("local-cli.server-peer", H_E, D0, surface="mcp", server=H_S),
                ]
            },
            forget("local-cli.Bad", H_A, "invalid id"),
            forget("local-cli.missing", H_A, "not found"),
            forget("local-cli.gone", H_B, "identity changed"),
            forget("local-cli.granted", H_C, "enrolled"),
            forget("local-cli.server-peer", H_E, "shares an enrolled server"),
            forget("local-cli.gone", H_A, "forgotten"),
            forget("local-cli.gone", H_A, "already forgotten"),
            {"sql": [observation_row("local-cli.gone", H_A, D2)]},
            forget("local-cli.gone", H_A, "forget again refreshes the stamp"),
        ],
    },
    {
        "name": "replay_gate",
        "steps": [
            {
                "sql": [
                    observation_row("local-cli.listed", H_A, D60_AGO),
                    ("insert into local_cli_forgotten values (?, ?)", [H_B, "2026-10-05T00:00:00+00:00"]),
                ]
            },
            replay(H_A, "garbage", "listed"),
            replay(H_B, "2026-10-04T00:00:00Z", "before forget"),
            replay(H_B, "2026-10-06T00:00:00Z", "after forget"),
            replay(H_B, "nope", "unparsable seen against a forget"),
            replay(H_C, "nope", "unparsable seen without a forget"),
            replay(H_C, D60_AGO, "expired against the clock"),
            replay(H_C, D60_AGO, "inside the window of an explicit now", now="2026-08-15T00:00:00Z"),
            replay(H_C, D60_AGO, "unparsable now falls back to the clock", now="later"),
            replay(H_C, "2026-09-10T12:00:00+00:00", "exactly at the cutoff"),
        ],
    },
    {
        "name": "prune_inactive",
        "steps": [
            {
                "sql": [
                    observation_row("local-cli.old", H_A, D60_AGO),
                    *inventory_rows("local-cli.old", H_A),
                    observation_row("local-cli.mid", H_B, D20_AGO),
                    observation_row("local-cli.new", H_C, D2),
                    observation_row("local-cli.edge", H_D, "2026-09-10T12:00:00Z"),
                ]
            },
            prune("throttled first run records the clock", throttle=True),
            prune("throttled again is skipped", throttle=True),
            prune("explicit now and a short window", now="2026-10-05T00:00:00+00:00", retention_days=7),
            prune("nothing left to prune"),
        ],
    },
]
