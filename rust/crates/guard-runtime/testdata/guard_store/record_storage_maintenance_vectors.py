#!/usr/bin/env python3
"""Record storage-maintenance vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
of `StoreStorageMaintenanceMixin.maintain_storage`, never against the branch
under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Per step the vectors hold the Python result, the post-step state of every
tracked table, and `wire_args`: the request the native transport must send,
translated here independently of the new code.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import store_storage_maintenance as maintenance

if not hasattr(maintenance, "_archive_receipt_batch"):
    sys.exit("refusing to record: the original Python maintenance implementation is gone")

from storage_maintenance_scenarios import NOW, SCENARIOS, SOURCE

from codex_plugin_scanner.guard.store import GuardStore

TABLES = {
    "runtime_receipts": "receipt_id",
    "runtime_receipt_envelopes": "receipt_id",
    "receipt_rollup_actions": "receipt_id",
    "guard_cloud_events": "event_id",
    "approval_requests": "request_id",
    "native_hook_decision_receipts": "decision_id",
    "native_prompt_decision_receipts": "decision_id",
    "guard_events": "event_id",
    "guard_workflow_capabilities": "capability_id",
    "guard_workflow_capability_receipts": "receipt_id",
    "guard_workflow_capability_authority_transitions": "sequence",
    "guard_storage_maintenance": "singleton",
}
DEFAULTS = {
    "detail_retain_days": 30,
    "batch_size": maintenance.DEFAULT_STORAGE_MAINTENANCE_BATCH_SIZE,
    "receipt_detail_limit": maintenance.DEFAULT_RECEIPT_DETAIL_LIMIT,
    "guard_event_limit": maintenance.DEFAULT_GUARD_EVENT_LIMIT,
    "uploaded_cloud_event_limit": maintenance.DEFAULT_UPLOADED_CLOUD_EVENT_LIMIT,
}


def wire(params: dict[str, int]) -> dict[str, object]:
    return {
        "now": NOW.isoformat(),
        "cutoff": (NOW - timedelta(days=params["detail_retain_days"])).isoformat(),
        "cloud_cutoff": (NOW - timedelta(days=maintenance.UPLOADED_CLOUD_EVENT_RETAIN_DAYS)).isoformat(),
        "batch_size": params["batch_size"],
        "receipt_detail_limit": params["receipt_detail_limit"],
        "guard_event_limit": params["guard_event_limit"],
        "uploaded_cloud_event_limit": params["uploaded_cloud_event_limit"],
    }


def rows(path: Path, sql: str) -> list[dict[str, object]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(sql)]
    finally:
        connection.close()


def dump(path: Path) -> dict[str, list[dict[str, object]]]:
    return {table: rows(path, f"select * from {table} order by {key}") for table, key in TABLES.items()}


def pragma(path: Path, name: str) -> int:
    connection = sqlite3.connect(path)
    try:
        return int(connection.execute(f"pragma {name}").fetchone()[0])
    finally:
        connection.close()


def schema(path: Path) -> tuple[list[str], list[str]]:
    names = tuple(TABLES)
    marks = ",".join("?" * len(names))
    connection = sqlite3.connect(path)
    try:
        base = [
            row[0]
            for row in connection.execute(
                f"select sql from sqlite_master where sql is not null and type in ('table', 'index') "
                f"and tbl_name in ({marks}) order by case type when 'table' then 0 else 1 end, rowid",
                names,
            )
        ]
        # Approval requests also write the review outbox, which maintenance never reads.
        triggers = [
            row[0]
            for row in connection.execute(
                f"select sql from sqlite_master where type = 'trigger' and tbl_name in ({marks}) "
                f"and tbl_name <> 'approval_requests' order by rowid",
                names,
            )
        ]
        return base, triggers
    finally:
        connection.close()


def assert_insertion_order(seed: dict[str, list[dict[str, object]]], path: Path) -> None:
    for table, key in TABLES.items():
        by_rowid = [row[key] for row in rows(path, f"select {key} from {table} order by rowid")]
        assert by_rowid == [row[key] for row in seed[table]], f"{table} rowid order differs from key order"


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-maintenance-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        if scenario.get("auto_vacuum", 2) != 2:
            connection = sqlite3.connect(path)
            connection.execute(f"pragma auto_vacuum={scenario['auto_vacuum']}")
            connection.execute("vacuum")
            connection.close()
        auto_vacuum = pragma(path, "auto_vacuum")
        assert auto_vacuum == scenario.get("auto_vacuum", 2)
        connection = sqlite3.connect(path)
        scenario["seed"](connection)
        connection.commit()
        connection.close()
        previous = dump(path)
        seed = previous
        assert_insertion_order(previous, path)
        steps: list[dict[str, object]] = []
        for step in scenario["steps"]:
            record: dict[str, object] = {"label": step["label"]}
            if "sql" in step:
                connection = sqlite3.connect(path)
                for statement, params in step["sql"]:
                    connection.execute(statement, params)
                connection.commit()
                connection.close()
                record.update(kind="sql", sql=step["sql"])
            else:
                params = {**DEFAULTS, **step["maintain"]}
                result = store.maintain_storage(now=NOW, **params)
                record.update(kind="maintain", wire_args=wire(params), result=asdict(result))
                if scenario.get("page_dependent"):
                    # The original executes `pragma incremental_vacuum(n)` without
                    # stepping it to completion, so it reclaims at most one page per
                    # call. The native port reclaims up to `batch_size` pages.
                    pages = result.pages_reclaimed
                    assert pages == 0 if auto_vacuum == 0 else pages <= 1, (scenario["name"], step["label"], pages)
            current = dump(path)
            record["post_changed"] = {t: value for t, value in current.items() if value != previous[t]}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "auto_vacuum": auto_vacuum, "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-maintenance-schema-") as root:
        base, triggers = schema(Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path))
    scenarios = [run_scenario(scenario) for scenario in SCENARIOS]
    document = {
        "schema": "guard-store-storage-maintenance-vectors.v1",
        "source": SOURCE,
        "order_by": TABLES,
        "schema_sql": base,
        "trigger_sql": triggers,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
