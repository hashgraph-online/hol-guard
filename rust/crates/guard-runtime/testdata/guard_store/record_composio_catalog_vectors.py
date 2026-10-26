#!/usr/bin/env python3
"""Record Composio discovery catalog vectors from the ORIGINAL Python writers.

Run against a checkout that still holds `write_composio_metadata` and
`write_workflow_proposals`, never against the branch under test and never from
Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

The recorder drives the two Python writers directly on a seeded connection
rather than through `GuardStore.record_composio_discovery`. The mixin's own
work — validating the observed tool name and resolving the connection through
`ensure_local_mcp_observation` — stays in Python on the branch under test, and
the connector identity it resolves is already native, so the Python path can no
longer run end to end without a resident. What crosses into Rust is exactly the
pair of writers recorded here.

The connector identity is therefore a fixture: a deterministic digest over the
observed command, standing in for the one the resident derives. The vectors
seed the matching `local_cli_observation` row, so the write is held against the
same connection Python held it against.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import store_mcp_provider_catalog, store_mcp_workflows

if not hasattr(store_mcp_provider_catalog, "write_composio_metadata"):
    sys.exit("refusing to record: the original Python Composio catalog implementation is gone")
if not hasattr(store_mcp_workflows, "write_workflow_proposals"):
    sys.exit("refusing to record: the original Python workflow proposal implementation is gone")

from composio_catalog_scenarios import NOW, SCENARIOS
from vector_support import dump, schema_sql_for_tables

from codex_plugin_scanner.guard.runtime.composio_discovery import ComposioActionSchema
from codex_plugin_scanner.guard.runtime.composio_workflows import ComposioWorkflowProposal
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_local_cli_schema import ensure_local_cli_schema

TABLES = {
    "local_cli_observation": "cli_id",
    "local_mcp_provider_action": "cli_id, identity_hash, provider, tool_slug",
    "local_mcp_provider_authority": "cli_id, identity_hash",
    "local_mcp_workflow_proposal": "cli_id, identity_hash, proposal_id",
}
OBSERVED_MCP_PREFIX = "observed-mcp:"


@dataclass(frozen=True)
class _ServerIdentity:
    identity_hash: str
    command: str


@dataclass(frozen=True)
class _Source:
    """The three fields the two writers read off an `ObservedMcpTool`."""

    harness: str
    namespace: str
    qualified_name: str

    @property
    def server_identity(self) -> _ServerIdentity:
        command = f"{OBSERVED_MCP_PREFIX}{self.harness}:{self.namespace}"
        return _ServerIdentity(sha256(command.encode()).hexdigest(), command)

    @property
    def cli_id(self) -> str:
        return f"local-cli.mcp-{self.server_identity.identity_hash[:16]}"


def source_for(tool: str) -> _Source:
    # `mcp__<namespace>__<name>`, with the Composio apps namespace carrying one
    # more segment than the bare one.
    parts = tool.removeprefix("mcp__").split("__")
    return _Source("codex", parts[0], tool)


def observation_row(source: _Source, seen_at: str) -> tuple[str, list[object]]:
    server = source.server_identity
    return (
        "insert into local_cli_observation (cli_id, identity_hash, kind, name, interpreter_name, "
        "example_label, observed_count, last_seen_at, surface, server_identity_hash, server_command, "
        "server_args_hash, source_label) "
        "values (?, ?, 'executable', ?, null, ?, 1, ?, 'mcp', ?, ?, ?, ?)",
        [
            source.cli_id,
            server.identity_hash,
            source.namespace,
            source.namespace,
            seen_at,
            server.identity_hash,
            server.command,
            sha256(b"").hexdigest(),
            "Codex · observed provider metadata",
        ],
    )


def wire(source: _Source, kwargs: dict[str, object]) -> dict[str, object]:
    server = source.server_identity
    return {
        "cli_id": source.cli_id,
        "identity_hash": server.identity_hash,
        "server_command": server.command,
        "source_tool": source.qualified_name,
        "seen_at": kwargs["seen_at"],
        "actions": kwargs["actions"],
        "proposals": kwargs.get("proposals", []),
        # The vectors hold the outcome after Python closed the policy barrier.
        "barrier_closed": True,
    }


def apply_step(path: Path, source: _Source, kwargs: dict[str, object]) -> bool:
    actions = tuple(ComposioActionSchema(**entry) for entry in kwargs["actions"])
    proposals = tuple(
        ComposioWorkflowProposal(tuple(entry["primary"]), tuple(entry["supporting"]), entry["guidance_present"])
        for entry in kwargs.get("proposals", ())
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute("begin immediate")
        changed = store_mcp_provider_catalog.write_composio_metadata(
            connection,
            source,
            actions,
            cli_id=source.cli_id,
            seen_at=kwargs["seen_at"],
        )
        store_mcp_workflows.write_workflow_proposals(
            connection,
            source.cli_id,
            source.server_identity.identity_hash,
            proposals,
            seen_at=kwargs["seen_at"],
        )
        connection.commit()
        return bool(changed)
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def prepared_store(root: Path) -> Path:
    path = Path(GuardStore(root / "guard-home", prime_policy_integrity=False).path)
    connection = sqlite3.connect(path)
    ensure_local_cli_schema(connection)
    connection.commit()
    connection.close()
    return path


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-composio-vectors-") as root:
        path = prepared_store(Path(root))
        connection = sqlite3.connect(path)
        for step in scenario["steps"]:
            source = source_for(step["kwargs"]["tool"])
            if connection.execute(
                "select 1 from local_cli_observation where cli_id = ?", (source.cli_id,)
            ).fetchone() is None:
                statement, params = observation_row(source, step["kwargs"]["seen_at"])
                connection.execute(statement, params)
        connection.commit()
        connection.close()
        previous = dump(path, TABLES)
        seed = previous
        steps: list[dict[str, object]] = []
        for step in scenario["steps"]:
            kwargs = step["kwargs"]
            source = source_for(kwargs["tool"])
            record: dict[str, object] = {"label": step.get("label", ""), "method": step["method"]}
            record["wire_args"] = wire(source, kwargs)
            try:
                record.update(native_payload={"authority_changed": apply_step(path, source, kwargs)}, error=None)
            except ValueError as error:
                record.update(
                    native_payload=None,
                    error={"type": "ValueError", "message": str(error), "message_exact": True},
                )
            current = dump(path, TABLES)
            record["post_changed"] = {t: rows for t, rows in current.items() if rows != previous[t]}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-composio-schema-") as root:
        schema = schema_sql_for_tables(prepared_store(Path(root)), TABLES)
    document = {
        "schema": "guard-store-composio-catalog-vectors.v1",
        "source": "guard",
        "now": NOW,
        "order_by": TABLES,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
