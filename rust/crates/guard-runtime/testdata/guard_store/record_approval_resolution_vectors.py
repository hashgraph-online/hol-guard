#!/usr/bin/env python3
"""Record single-request and duplicate-group approval resolution vectors.

Run against a checkout whose `store_approval_facade.py` still resolves
requests in Python, with a native runtime for the canonical surfaces those
resolutions ask the resident for:

    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each call of a scenario (`approval_resolution_scenarios.py`) seeds a fresh
store opened with the call's source, runs the named `GuardStore` method and
keeps its result (or the raised error) and every row whose resolution state
the call changed.
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

from approval_read_scenarios import SOURCE
from approval_resolution_scenarios import SCENARIOS
from record_approval_read_vectors import insert
from record_approval_resolution_sweep_vectors import states

from codex_plugin_scanner.guard.store import GuardStore


def call(rows: list[dict[str, object]], spec: dict[str, object]) -> dict[str, object]:
    recorded: dict[str, object] = dict(spec)
    with tempfile.TemporaryDirectory(prefix="approval-resolution-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=str(spec["source"]))
        path = Path(store.path)
        insert(path, rows, {})
        before = states(path)
        try:
            recorded["result"] = getattr(store, str(spec["method"]))(**spec["args"])  # type: ignore[arg-type]
        except ValueError as error:
            recorded["error"] = {"type": type(error).__name__, "message": str(error)}
        after = states(path)
    recorded["changed"] = [
        [request_id, *state] for request_id, state in sorted(after.items()) if before[request_id] != state
    ]
    return recorded


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="approval-resolution-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE).path)
        import sqlite3

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
            "calls": [call(scenario["rows"], spec) for spec in scenario["calls"]],  # type: ignore[attr-defined]
        }
        for scenario in SCENARIOS
    ]
    document = {
        "schema": "guard-store-approval-resolution-vectors.v1",
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
