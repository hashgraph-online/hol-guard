#!/usr/bin/env python3
"""Record custom-extension grant read vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python reads
(`store_local_cli._read_command_catalog` and friends), never against the
branch under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Per step the vectors hold the request the native transport must send
(`wire_args`, translated here independently of the new code), the Python
result as the resident's payload (or the error). The reads never write, so
only the seed state is recorded; SQL steps may plant non-text cells that a
JSON table dump cannot carry.
"""

from __future__ import annotations

import dataclasses
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

if not hasattr(store_local_cli, "_read_command_catalog"):
    sys.exit("refusing to record: the original Python grant reads are gone")

from local_cli_grant_scenarios import SCENARIOS
from vector_support import dump, schema_sql_for_tables

from codex_plugin_scanner.guard.store import GuardStore

TABLES = {
    "local_cli_grant": "cli_id",
    "local_cli_authority": "singleton",
    "local_cli_command": "cli_id, command_id",
    "local_cli_command_grant": "cli_id, command_id",
}
WIRE = {
    "read_local_cli_grant": ("read_local_cli_grant", lambda kw: {"cli_id": kw["cli_id"]}),
    "read_local_cli_command_catalog": ("read_local_cli_command_catalog", lambda kw: {"cli_id": kw["cli_id"]}),
    "read_local_cli_command_states": ("read_local_cli_command_states", lambda kw: {"cli_id": kw["cli_id"]}),
}


def payload(result: object) -> object:
    if isinstance(result, list):
        return [dataclasses.asdict(item) if dataclasses.is_dataclass(item) else item for item in result]
    return result


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-local-cli-grant-vectors-") as root:
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
                    record.update(native_payload=json.loads(json.dumps(payload(result))), error=None)
                except ValueError as error:
                    record.update(
                        native_payload=None,
                        error={"type": "ValueError", "message": str(error), "message_exact": True},
                    )
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-local-cli-grant-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path)
        schema = schema_sql_for_tables(path, TABLES)
    document = {
        "schema": "guard-store-local-cli-grant-vectors.v1",
        "source": "guard",
        "order_by": TABLES,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
