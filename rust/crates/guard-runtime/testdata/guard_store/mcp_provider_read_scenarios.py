"""Scenarios for the observed-MCP provider and catalog reads.

Each scenario seeds rows with `sql` steps and then calls one read. The reads
never write, so every step's `post_changed` is empty; what the vectors carry
is the exact payload or `ValueError` the Python store produced.
"""

from __future__ import annotations

import json
from hashlib import sha256

from codex_plugin_scanner.guard.runtime.observed_mcp_tools import OBSERVED_MCP_PREFIX, observed_mcp_tool

NOW = "2026-03-04T12:00:00+00:00"

HARNESS = "claude"
# The marker the provider authority parses back to this same connector.
_SOURCE = observed_mcp_tool(HARNESS, "mcp__linear__probe")
assert _SOURCE is not None
NAMESPACE = _SOURCE.namespace
MARKER = f"{OBSERVED_MCP_PREFIX}{HARNESS}:{NAMESPACE}"
IDENTITY = _SOURCE.identity.identity_hash
CLI_ID = _SOURCE.identity.cli_id
OTHER_CLI_ID = "local-cli.mcp-0123456789abcdef"


def observation(cli_id: str = CLI_ID, *, marker: str = MARKER, identity: str = IDENTITY) -> tuple:
    return (
        "insert into local_cli_observation (cli_id, identity_hash, kind, name, example_label, "
        "observed_count, last_seen_at, surface, server_identity_hash, server_command) "
        "values (?, ?, 'executable', ?, ?, 1, ?, 'mcp', ?, ?)",
        [cli_id, identity, NAMESPACE, NAMESPACE, NOW, identity, marker],
    )


def grant(cli_id: str = CLI_ID, *, state: str = "allowed") -> tuple:
    return (
        "insert into local_cli_grant (cli_id, identity_hash, state, revision, updated_at) values (?, ?, ?, 1, ?)",
        [cli_id, IDENTITY, state, NOW],
    )


def provider_grant(slug: str, state: str, cli_id: str = CLI_ID) -> tuple:
    return (
        "insert into local_mcp_provider_grant (cli_id, identity_hash, tool_slug, state, updated_at) "
        "values (?, ?, ?, ?, ?)",
        [cli_id, IDENTITY, slug, state, NOW],
    )


def action(
    slug: str,
    *,
    toolkit: str = "linear",
    description: str = "",
    schema: dict | None = None,
    full_schema: int = 1,
    revision: int = 1,
) -> tuple:
    return (
        "insert into local_mcp_provider_action (cli_id, identity_hash, provider, tool_slug, toolkit, "
        "description, input_schema_json, authority_hash, full_schema, source_tool, revision, updated_at) "
        "values (?, ?, 'composio', ?, ?, ?, ?, ?, ?, 'COMPOSIO_SEARCH', ?, ?)",
        [
            CLI_ID,
            IDENTITY,
            slug,
            toolkit,
            description,
            json.dumps(schema if schema is not None else {"type": "object"}, sort_keys=True),
            sha256(slug.encode()).hexdigest(),
            full_schema,
            revision,
            NOW,
        ],
    )


def authority(cli_id: str = CLI_ID, *, digest: str = "d" * 64) -> tuple:
    return (
        "insert into local_mcp_provider_authority (cli_id, identity_hash, digest) values (?, ?, ?)",
        [cli_id, IDENTITY, digest],
    )


def proposal(proposal_id: str, primary: list[str], supporting: list[str], *, seen_at: str = NOW) -> tuple:
    return (
        "insert into local_mcp_workflow_proposal (cli_id, identity_hash, proposal_id, proposal_json, seen_at) "
        "values (?, ?, ?, ?, ?)",
        [
            CLI_ID,
            IDENTITY,
            proposal_id,
            json.dumps(
                {"primary": primary, "supporting": supporting, "guidance_present": True},
                sort_keys=True,
            ),
            seen_at,
        ],
    )


def skill_entry(name: str, uri: str, description: str = "", *, identity: str = IDENTITY) -> dict:
    return {
        "name": name,
        "uri": uri,
        "description": description,
        "connection_identity_hash": identity,
    }


def catalog(entries: list[dict], *, revision: int = 3, complete: bool = True) -> tuple:
    snapshot = {
        "complete": complete,
        "tools": [],
        "skills_catalog": {"entries": entries},
    }
    return (
        "insert into local_mcp_catalog (cli_id, identity_hash, catalog_json, revision, updated_at) "
        "values (?, ?, ?, ?, ?)",
        [CLI_ID, IDENTITY, json.dumps(snapshot, sort_keys=True), revision, NOW],
    )


def sql(*statements: tuple) -> dict:
    return {"sql": [list(statement) for statement in statements], "label": "seed"}


def call(method: str, label: str, **kwargs: object) -> dict:
    return {"method": method, "label": label, "kwargs": kwargs}


SCENARIOS: list[dict] = [
    {
        "name": "provider_choices_empty",
        "steps": [call("read_mcp_provider_choices", "no connections")],
    },
    {
        "name": "provider_choices_saved_deny",
        "steps": [
            sql(
                observation(),
                grant(),
                provider_grant("GITHUB_CREATE_ISSUE", "block"),
                provider_grant("GITHUB_LIST_ISSUES", "review"),
            ),
            call("read_mcp_provider_choices", "only the saved denial is replayed"),
        ],
    },
    {
        "name": "provider_choices_undecided_connection",
        "steps": [
            sql(observation(), provider_grant("GITHUB_CREATE_ISSUE", "block")),
            call("read_mcp_provider_choices", "a connection with no grant contributes nothing"),
        ],
    },
    {
        "name": "provider_authority_hash_absent",
        "steps": [call("read_mcp_provider_authority_hash", "no authority rows")],
    },
    {
        "name": "provider_authority_hash_present",
        "steps": [
            sql(observation(), authority()),
            call("read_mcp_provider_authority_hash", "one observed connection"),
        ],
    },
    {
        "name": "provider_authority_hash_unobserved",
        "steps": [
            sql(authority(OTHER_CLI_ID)),
            call("read_mcp_provider_authority_hash", "an authority row with no observation"),
        ],
    },
    {
        "name": "provider_actions_page",
        "steps": [
            sql(
                observation(),
                action("GITHUB_CREATE_ISSUE", toolkit="github", description="Open an issue"),
                action("GITHUB_LIST_ISSUES", toolkit="github", description="List issues", full_schema=0),
                action("LINEAR_CREATE_TICKET", description="Create a ticket", revision=2),
                provider_grant("GITHUB_CREATE_ISSUE", "block"),
            ),
            call("read_local_mcp_provider_actions", "first page", cli_id=CLI_ID, limit=2, offset=0),
            call("read_local_mcp_provider_actions", "second page", cli_id=CLI_ID, limit=2, offset=2),
            call(
                "read_local_mcp_provider_actions",
                "search narrows to one toolkit",
                cli_id=CLI_ID,
                limit=100,
                offset=0,
                search="linear",
            ),
            call(
                "read_local_mcp_provider_actions",
                "a wildcard in the search is literal",
                cli_id=CLI_ID,
                limit=100,
                offset=0,
                search="%",
            ),
        ],
    },
    {
        "name": "provider_actions_refusals",
        "steps": [
            sql(observation(), action("GITHUB_CREATE_ISSUE", toolkit="github")),
            call(
                "read_local_mcp_provider_actions",
                "a stale token refuses the page",
                cli_id=CLI_ID,
                limit=10,
                offset=0,
                expected_token="0" * 64,
            ),
            call(
                "read_local_mcp_provider_actions",
                "an unknown connection",
                cli_id=OTHER_CLI_ID,
                limit=10,
                offset=0,
            ),
            call(
                "read_local_mcp_provider_actions",
                "a page wider than the ceiling",
                cli_id=CLI_ID,
                limit=101,
                offset=0,
            ),
            call("read_local_mcp_provider_actions", "a malformed id", cli_id="not-a-cli-id", limit=10, offset=0),
        ],
    },
    {
        "name": "workflow_proposals_page",
        "steps": [
            sql(
                observation(),
                action("GITHUB_CREATE_ISSUE", toolkit="github"),
                action("GITHUB_LIST_ISSUES", toolkit="github", full_schema=0),
                provider_grant("GITHUB_CREATE_ISSUE", "block"),
                proposal("p-1", ["GITHUB_CREATE_ISSUE"], ["GITHUB_LIST_ISSUES", "SLACK_POST"]),
                proposal("p-2", ["SLACK_POST"], [], seen_at="2026-03-03T12:00:00+00:00"),
            ),
            call("read_local_mcp_workflows", "every requirement state", cli_id=CLI_ID, offset=0),
        ],
    },
    {
        "name": "workflow_proposals_refusals",
        "steps": [
            sql(observation()),
            call("read_local_mcp_workflows", "an offset past the ceiling", cli_id=CLI_ID, offset=51),
            call("read_local_mcp_workflows", "an unknown connection", cli_id=OTHER_CLI_ID, offset=0),
            call("read_local_mcp_workflows", "a malformed id", cli_id="not-a-cli-id", offset=0),
        ],
    },
    {
        "name": "skill_page",
        "steps": [
            sql(
                observation(),
                catalog(
                    [
                        skill_entry("Zebra report", "mcp://linear/zebra", "Weekly summary"),
                        skill_entry("Alpha brief", "mcp://linear/alpha", "Daily digest"),
                        skill_entry("Triage", "mcp://linear/triage", "Sort the inbox"),
                    ]
                ),
            ),
            call("read_local_mcp_skills", "sorted by name", cli_id=CLI_ID, offset=0, search=""),
            call("read_local_mcp_skills", "search matches a description", cli_id=CLI_ID, offset=0, search="DIGEST"),
            call(
                "read_local_mcp_skills",
                "the recorded revision still matches",
                cli_id=CLI_ID,
                offset=0,
                search="",
                expected_revision=3,
            ),
            call(
                "read_local_mcp_skills",
                "a changed revision refuses the page",
                cli_id=CLI_ID,
                offset=0,
                search="",
                expected_revision=2,
            ),
            call("read_local_mcp_skills", "an offset past the end", cli_id=CLI_ID, offset=900, search=""),
        ],
    },
    {
        "name": "skill_page_refusals",
        "steps": [
            sql(observation()),
            call("read_local_mcp_skills", "no catalog recorded", cli_id=CLI_ID, offset=0, search=""),
            call("read_local_mcp_skills", "an unknown connection", cli_id=OTHER_CLI_ID, offset=0, search=""),
            call("read_local_mcp_skills", "an offset past the ceiling", cli_id=CLI_ID, offset=1001, search=""),
            call("read_local_mcp_skills", "a malformed id", cli_id="not-a-cli-id", offset=0, search=""),
        ],
    },
    {
        "name": "skill_page_foreign_entry",
        "steps": [
            sql(
                observation(),
                catalog([skill_entry("Alpha brief", "mcp://linear/alpha", identity="f" * 64)]),
            ),
            call(
                "read_local_mcp_skills",
                "an entry bound to another connection refuses the snapshot",
                cli_id=CLI_ID,
                offset=0,
                search="",
            ),
        ],
    },
]
