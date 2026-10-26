#!/usr/bin/env python3
"""Record approval metadata vectors: the extension allow hint, the desktop
notification marker and the oldest request time.

Run against a checkout whose `store_approval_queries.py` still answers these
in Python:

    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each call of a scenario (`approval_metadata_scenarios.py`) seeds a fresh store
opened with the call's source, runs the named `GuardStore` method and keeps
its result and every row whose `desktop_notified_at` the call changed.
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

from approval_metadata_scenarios import SCENARIOS
from approval_read_scenarios import SOURCE
from record_approval_read_vectors import insert

from codex_plugin_scanner.guard.store import GuardStore


def notified(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(path)
    try:
        return dict(connection.execute("select request_id, desktop_notified_at from approval_requests").fetchall())
    finally:
        connection.close()


def call(scenario: dict[str, object], spec: dict[str, object]) -> dict[str, object]:
    recorded: dict[str, object] = dict(spec)
    with tempfile.TemporaryDirectory(prefix="approval-metadata-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=str(spec["source"]))
        path = Path(store.path)
        insert(path, scenario["rows"], {})  # type: ignore[arg-type]
        if scenario.get("legacy_hint_column"):
            connection = sqlite3.connect(path)
            connection.execute("alter table approval_requests drop column extension_allow_hint_json")
            connection.commit()
            connection.close()
        before = notified(path)
        recorded["result"] = getattr(store, str(spec["method"]))(**spec["args"])  # type: ignore[arg-type]
        after = notified(path)
    recorded["changed"] = [
        [request_id, value] for request_id, value in sorted(after.items()) if before[request_id] != value
    ]
    return recorded


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="approval-metadata-schema-") as root:
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
            **{key: value for key, value in scenario.items() if key != "calls"},
            "calls": [call(scenario, spec) for spec in scenario["calls"]],  # type: ignore[attr-defined]
        }
        for scenario in SCENARIOS
    ]
    document = {
        "schema": "guard-store-approval-metadata-vectors.v1",
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
