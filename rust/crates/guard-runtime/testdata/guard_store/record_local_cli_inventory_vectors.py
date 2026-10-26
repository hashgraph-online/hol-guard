#!/usr/bin/env python3
"""Record local CLI inventory read vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python assembly
(`store_local_cli.list_local_cli_items` reading SQLite directly), never
against the branch under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

The read never writes, so only the seed state is recorded. The recorder runs
with the native resident off, which is what the replay normalizes around: with
no resident, `_with_suggestions` leaves every item at `suggestion_score` 0 and
`suggestable` false, and `classify_mcp_actions` raises, so Python returns the
commands undescribed. Those three fields are dropped from both sides of the
comparison; Rust covers the ranker and the classifier in their own tests.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import store_local_cli

if not hasattr(store_local_cli, "_load_commands_by_cli"):
    sys.exit("refusing to record: the original Python inventory read is gone")

from local_cli_inventory_scenarios import SCENARIOS
from vector_support import dump, schema_sql_for_tables

from codex_plugin_scanner.guard.store import GuardStore

TABLES = {
    "local_cli_observation": "cli_id",
    "local_cli_grant": "cli_id",
    "local_cli_authority": "singleton",
    "local_cli_command": "cli_id, command_id",
    "local_cli_command_grant": "cli_id, command_id",
    "local_cli_grant_capability": "cli_id, capability",
    "local_mcp_catalog": "cli_id",
    "local_mcp_provider_action": "cli_id, tool_slug",
}
WIRE = {"list_local_cli_items": ("list_local_cli_items", lambda kw: {})}


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-local-cli-inventory-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        seed = dump(path, TABLES)
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
                wire_method, wire_args = WIRE[method]
                record.update(method=wire_method, wire_args=wire_args(kwargs))
                try:
                    result = getattr(store, method)(**kwargs)
                    record.update(native_payload=json.loads(json.dumps(result)), error=None)
                except ValueError as error:
                    record.update(
                        native_payload=None,
                        error={"type": "ValueError", "message": str(error), "message_exact": True},
                    )
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-local-cli-inventory-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path)
        schema = schema_sql_for_tables(path, TABLES)
    document = {
        "schema": "guard-store-local-cli-inventory-vectors.v1",
        "source": "guard",
        "order_by": TABLES,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
