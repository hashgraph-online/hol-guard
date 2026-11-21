#!/usr/bin/env python3
"""Record queue-result and native workspace-review resolution vectors.

Run against a checkout whose `GuardStore.resolve_request_with_queue_result`
and `resolve_native_workspace_review_request` still resolve requests in
Python, with a native runtime for the canonical surfaces those resolutions
ask the resident for:

    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each call of a scenario (`approval_queue_result_scenarios.py`) seeds a fresh
store opened with the call's source, runs the named `GuardStore` method and
keeps its result, every row whose resolution state the call changed and every
`sync_state` entry it wrote. A workspace-review call also keeps the
arguments the store hands the resident: the expected request snapshot and the
receipt text, both as Python encodes them.
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

from approval_queue_result_scenarios import SCENARIOS
from approval_read_scenarios import SOURCE
from record_approval_read_vectors import insert
from record_approval_resolution_sweep_vectors import states

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_native_workspace_review import _receipt_payload


def sync_state(path: Path) -> dict[str, list[object]]:
    connection = sqlite3.connect(path)
    try:
        return {item[0]: list(item) for item in connection.execute("select * from sync_state")}
    finally:
        connection.close()


def review_args(store: GuardStore, spec_args: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    request_id = str(spec_args["request_id"])
    current = store.get_approval_request(request_id) or {"request_id": request_id}
    expected = dict(current, risk_summary="stale") if spec_args["expected_request"] == "stale" else current
    receipt = spec_args["native_receipt"]
    args = {**spec_args, "expected_request": expected}
    native_args = {
        "request_id": request_id,
        "resolution_action": spec_args["resolution_action"],
        "expected_snapshot": json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        "resolved_at": spec_args["resolved_at"],
        "native_replayed": spec_args["native_replayed"],
        "native_receipt_json": (
            _receipt_payload(receipt, request_id, str(spec_args["resolution_action"]))  # type: ignore[arg-type]
            if receipt is not None
            else None
        ),
    }
    return args, native_args


def call(scenario: dict[str, object], spec: dict[str, object]) -> dict[str, object]:
    recorded: dict[str, object] = {"method": spec["method"], "source": spec["source"]}
    with tempfile.TemporaryDirectory(prefix="approval-queue-result-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=str(spec["source"]))
        path = Path(store.path)
        insert(path, scenario["rows"], {})  # type: ignore[arg-type]
        connection = sqlite3.connect(path)
        connection.executemany(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
            scenario.get("sync_state", []),  # type: ignore[arg-type]
        )
        connection.commit()
        connection.close()
        args = dict(spec["args"])  # type: ignore[call-overload]
        if spec["method"] == "resolve_native_workspace_review_request":
            args, recorded["args"] = review_args(store, args)
        else:
            recorded["args"] = args
        before = states(path)
        state_before = sync_state(path)
        try:
            recorded["result"] = getattr(store, str(spec["method"]))(**args)
        except ValueError as error:
            recorded["error"] = {"type": type(error).__name__, "message": str(error)}
        after = states(path)
        state_after = sync_state(path)
    recorded["changed"] = [
        [request_id, *state] for request_id, state in sorted(after.items()) if before[request_id] != state
    ]
    recorded["sync_state_changed"] = [
        entry for key, entry in sorted(state_after.items()) if state_before.get(key) != entry
    ]
    return recorded


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="approval-queue-result-schema-") as root:
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
            "sync_state": scenario.get("sync_state", []),
            "calls": [call(scenario, spec) for spec in scenario["calls"]],  # type: ignore[attr-defined]
        }
        for scenario in SCENARIOS
    ]
    document = {
        "schema": "guard-store-approval-queue-result-vectors.v1",
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
