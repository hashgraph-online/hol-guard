#!/usr/bin/env python3
"""Record approval scope-sweep vectors from Python.

Run against a checkout whose `store_approval_facade.py` still selects and
resolves the swept rows in Python, with a native runtime for the canonical
surfaces those sweeps ask the resident for:

    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each call of a scenario (`approval_resolution_sweep_scenarios.py`) seeds a
fresh store, runs `GuardStore.resolve_matching_approval_requests` and keeps
the returned ids (or the raised error) and every row whose resolution state
the sweep changed.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

if os.environ.get("HOL_GUARD_NATIVE") != "force" or not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("refusing to record: set HOL_GUARD_NATIVE=force and HOL_GUARD_NATIVE_BINARY")

sys.path.insert(0, str(Path(__file__).resolve().parent))

import json
import sqlite3

from approval_read_scenarios import SOURCE
from approval_resolution_sweep_scenarios import SCENARIOS
from record_approval_read_vectors import insert

from codex_plugin_scanner.guard.store import GuardStore

STATE = "request_id, status, resolution_action, resolution_scope, reason, resolved_at"


def states(path: Path) -> dict[str, list[object]]:
    connection = sqlite3.connect(path)
    try:
        return {row[0]: list(row[1:]) for row in connection.execute(f"select {STATE} from approval_requests")}
    finally:
        connection.close()


def call(rows: list[dict[str, object]], args: dict[str, object]) -> dict[str, object]:
    recorded: dict[str, object] = {"args": args}
    with tempfile.TemporaryDirectory(prefix="approval-sweep-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE)
        path = Path(store.path)
        insert(path, rows, {})
        before = states(path)
        try:
            recorded["result"] = store.resolve_matching_approval_requests(**args)  # type: ignore[arg-type]
        except ValueError as error:
            recorded["error"] = {"type": type(error).__name__, "message": str(error)}
        after = states(path)
    recorded["changed"] = [
        [request_id, *state] for request_id, state in sorted(after.items()) if before[request_id] != state
    ]
    return recorded


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="approval-sweep-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE).path)
        connection = sqlite3.connect(path)
        schema = [
            item[0]
            for item in connection.execute(
                "select sql from sqlite_master where sql is not null and name not like 'sqlite_%' order by rowid"
            )
        ]
        connection.close()
    scenarios = [
        {
            "name": scenario["name"],
            "rows": scenario["rows"],
            "calls": [call(scenario["rows"], args) for args in scenario["calls"]],  # type: ignore[attr-defined]
        }
        for scenario in SCENARIOS
    ]
    document = {
        "schema": "guard-store-approval-resolution-sweep-vectors.v1",
        "source": SOURCE,
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
