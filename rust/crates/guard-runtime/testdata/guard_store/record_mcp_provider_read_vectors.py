#!/usr/bin/env python3
"""Record observed-MCP provider and catalog read vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation of
`read_mcp_provider_choices`, `read_mcp_provider_authority_hash`,
`read_local_mcp_provider_actions`, `read_local_mcp_workflows` and
`read_local_mcp_skills`, never against the branch under test and never from
Rust output:

    cd <origin-main-worktree>
    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<runtime> \
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Unlike the other store recorders this one needs the native runtime, because the
reads themselves reparse an observed-MCP marker through
`build_mcp_server_identity`, which Guard has always answered natively. The
store methods recorded here are still pure Python: none of them routes through
`_native_store_call`, and the recorder refuses to run once they do.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import store_local_mcp
from codex_plugin_scanner.guard.store_local_cli_schema import ensure_local_cli_schema

if not hasattr(store_local_mcp, "read_provider_actions"):
    sys.exit("refusing to record: the original Python provider read implementation is gone")

from mcp_provider_read_scenarios import NOW, SCENARIOS
from vector_support import dump, schema_sql_for_tables

from codex_plugin_scanner.guard.store import GuardStore

TABLES = {
    "local_cli_schema_migration": "singleton",
    "local_cli_observation": "cli_id",
    "local_cli_grant": "cli_id",
    "local_mcp_catalog": "cli_id",
    "local_mcp_provider_action": "cli_id, identity_hash, provider, tool_slug",
    "local_mcp_provider_authority": "cli_id, identity_hash",
    "local_mcp_provider_grant": "cli_id, identity_hash, tool_slug",
    "local_mcp_workflow_proposal": "cli_id, identity_hash, proposal_id",
}
WIRE_DEFAULTS: dict[str, dict[str, object]] = {
    "read_mcp_provider_choices": {},
    "read_mcp_provider_authority_hash": {},
    "read_local_mcp_provider_actions": {
        "cli_id": "",
        "limit": 100,
        "offset": 0,
        "search": "",
        "expected_token": None,
    },
    "read_local_mcp_workflows": {"cli_id": "", "offset": 0},
    "read_local_mcp_skills": {"cli_id": "", "offset": 0, "search": "", "expected_revision": None},
}

# The native read returns the page and the declarations the caller classifies
# after the transaction ends; classification is not part of this cutover, so
# the recorder keeps the wrapper's own validation and records its input.
store_local_mcp.describe_provider_actions = lambda page, declarations, *, guard_home: {
    "page": page,
    "declarations": list(declarations),
}


def wire(method: str, kwargs: dict[str, object]) -> dict[str, object]:
    defaults = WIRE_DEFAULTS[method]
    unknown = set(kwargs) - set(defaults)
    if unknown:
        raise AssertionError(f"{method}: unexpected {sorted(unknown)}")
    return {key: kwargs.get(key, default) for key, default in defaults.items()}


def prepare(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        ensure_local_cli_schema(connection)
        connection.commit()
    finally:
        connection.close()


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-mcp-provider-read-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        prepare(path)
        previous = dump(path, TABLES)
        seed = previous
        steps: list[dict[str, object]] = []
        for step in scenario["steps"]:
            record: dict[str, object] = {"label": step.get("label", "")}
            if "sql" in step:
                connection = sqlite3.connect(path)
                for statement, params in step["sql"]:
                    connection.execute(statement, params)
                connection.commit()
                connection.close()
                record.update(method="sql", sql=step["sql"], wire_args=None, native_payload=None, error=None)
            else:
                method, kwargs = step["method"], step.get("kwargs", {})
                record.update(method=method, wire_args=wire(method, kwargs))
                try:
                    result = getattr(store, method)(**kwargs)
                    record.update(native_payload=json.loads(json.dumps(result)), error=None)
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
    with tempfile.TemporaryDirectory(prefix="guard-mcp-provider-read-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path)
        prepare(path)
        schema = schema_sql_for_tables(path, TABLES)
    document = {
        "schema": "guard-store-mcp-provider-read-vectors.v1",
        "source": "guard",
        "now": NOW,
        "order_by": TABLES,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
