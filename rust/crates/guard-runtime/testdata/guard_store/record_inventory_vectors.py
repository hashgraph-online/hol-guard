#!/usr/bin/env python3
"""Record artifact inventory/snapshot/capability vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
of `StoreInventoryMixin`, never against the branch under test and never from
Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Per step the vectors hold the Python result (or error), the post-step state of
every tracked table, the request the native transport must send (`wire_args`,
translated here independently of the new code), and `native_payload`: what the
resident must return for that request, read back with direct SQL from the
Python-written database.
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

from codex_plugin_scanner.guard import store_inventory

if not hasattr(store_inventory, "_inventory_payload_from_row"):
    sys.exit("refusing to record: the original Python inventory implementation is gone")

from inventory_scenarios import SCENARIOS, SEQUENCE_KEY, jsonable
from vector_support import schema_sql_for_tables

from codex_plugin_scanner.guard.store import GuardStore

TABLES = {
    "artifact_snapshots": "artifact_id, harness",
    "artifact_hashes": "rowid",
    "artifact_diffs": "diff_id",
    "artifact_inventory": "artifact_id, harness",
    "artifact_capabilities": "artifact_id, harness",
    "provenance_cache": "artifact_hash",
    "sync_state": "state_key",
}
WHERE = {"sync_state": f"state_key = '{SEQUENCE_KEY}'"}
WIRE_METHODS = {
    "save_snapshot": "save_artifact_snapshot",
    "get_snapshot": "get_artifact_snapshot",
    "list_snapshots": "list_artifact_snapshots",
    "delete_snapshot": "delete_artifact_snapshot",
    "record_diff": "record_artifact_diff",
    "list_inventory": "list_artifact_inventory",
    "find_inventory_item": "find_artifact_inventory_item",
}


def wire(method: str, args: tuple, kwargs: dict) -> dict[str, object]:
    if method == "save_snapshot":
        harness, artifact_id, snapshot, artifact_hash, now = args
        return {
            "harness": harness,
            "artifact_id": artifact_id,
            "snapshot_json": json.dumps(snapshot),
            "artifact_hash": artifact_hash,
            "now": now,
        }
    if method in ("get_snapshot", "delete_snapshot", "get_artifact_capability"):
        return {"harness": args[0], "artifact_id": args[1]}
    if method == "list_snapshots":
        return {"harness": args[0]}
    if method == "record_diff":
        harness, artifact_id, fields, previous, current, now = args
        return {
            "harness": harness,
            "artifact_id": artifact_id,
            "changed_fields_json": json.dumps(fields),
            "previous_hash": previous,
            "current_hash": current,
            "now": now,
        }
    if method == "record_inventory_artifact":
        art = kwargs["artifact"]
        launch = " ".join([art.command, *art.args]).strip() if art.command else None
        return {
            "artifact_id": art.artifact_id,
            "harness": art.harness,
            "artifact_name": art.name,
            "artifact_type": art.artifact_type,
            "source_scope": art.source_scope,
            "config_path": art.config_path,
            "publisher": art.publisher,
            "origin_url": art.url,
            "launch_command": launch,
            "transport": art.transport,
            "artifact_hash": kwargs["artifact_hash"],
            "policy_action": kwargs["policy_action"],
            "changed": kwargs["changed"],
            "approved": kwargs["approved"],
            "now": kwargs["now"],
        }
    if method == "mark_inventory_removed":
        return {key: kwargs[key] for key in ("harness", "artifact_id", "policy_action", "artifact_hash", "now")}
    if method == "list_inventory":
        return {"harness": args[0] if args else None}
    if method == "find_inventory_item":
        return {"artifact_id": args[0]}
    if method == "save_artifact_capability":
        return {
            "harness": kwargs["harness"],
            "artifact_id": kwargs["artifact_id"],
            "capability_json": json.dumps(kwargs["capability_snapshot"]),
            "now": kwargs["now"],
        }
    if method == "upsert_provenance_cache":
        return {
            "artifact_hash": kwargs["artifact_hash"],
            "payload_json": json.dumps(kwargs["payload"]),
            "now": kwargs["now"],
        }
    if method == "next_aibom_trust_attestation_sequence":
        return {"now": args[0]}
    raise AssertionError(method)


def rows(path: Path, sql: str, params: tuple = ()) -> list[dict[str, object]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(sql, params)]
    finally:
        connection.close()


def native_payload(path: Path, method: str, args: tuple, result: object) -> object:
    if method == "get_snapshot":
        found = rows(
            path,
            "select snapshot_json from artifact_snapshots where harness = ? and artifact_id = ?",
            (args[0], args[1]),
        )
        return found[0] if found else None
    if method == "list_snapshots":
        return rows(path, "select artifact_id, snapshot_json from artifact_snapshots where harness = ?", (args[0],))
    if method == "get_artifact_capability":
        found = rows(
            path,
            "select capability_json from artifact_capabilities where artifact_id = ? and harness = ?",
            (args[1], args[0]),
        )
        return found[0] if found else None
    if method in ("list_inventory", "find_inventory_item", "next_aibom_trust_attestation_sequence"):
        return result
    return None


def dump(path: Path) -> dict[str, list[dict[str, object]]]:
    out = {}
    for table, key in TABLES.items():
        where = f" where {WHERE[table]}" if table in WHERE else ""
        out[table] = rows(path, f"select * from {table}{where} order by {key}")
    return out


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-inventory-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        previous = dump(path)
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
                record.update(method="sql", sql=step["sql"], wire_args=None, result=None, error=None)
            else:
                method, args, kwargs = step["method"], step.get("args", ()), step.get("kwargs", {})
                record.update(method=WIRE_METHODS.get(method, method), wire_args=wire(method, args, kwargs))
                try:
                    result = getattr(store, method)(*args, **kwargs)
                    record.update(
                        result=json.loads(json.dumps(jsonable(result))),
                        native_payload=native_payload(path, method, args, result),
                        error=None,
                    )
                except (ValueError, RuntimeError, sqlite3.IntegrityError) as error:
                    kind = "ValueError" if isinstance(error, ValueError) else type(error).__name__
                    record.update(
                        result=None,
                        native_payload=None,
                        error={"type": kind, "message": str(error), "message_exact": type(error).__name__ == kind},
                    )
            current = dump(path)
            record["post_changed"] = {t: rows_ for t, rows_ in current.items() if rows_ != previous[t]}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-inventory-schema-") as root:
        schema = schema_sql_for_tables(
            Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path), TABLES
        )
    document = {
        "schema": "guard-store-inventory-vectors.v1",
        "source": "guard",
        "order_by": TABLES,
        "where": WHERE,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
