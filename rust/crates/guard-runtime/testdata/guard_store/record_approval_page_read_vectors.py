#!/usr/bin/env python3
"""Record approval queue page, count and next-request vectors from Python.

Run against a checkout whose `store_approvals.py` still holds the Python
page reads, with a native runtime for the canonical surfaces and scope
contracts those reads ask the resident for:

    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario (`approval_page_read_scenarios.py`) seeds `approval_requests`,
then reads through `GuardStore.list_approval_request_page`,
`list_pending_approval_summaries`, `count_approval_requests` and
`get_next_pending_request`. Per call the vectors hold the result (a string
past `LONG_STRING` as its length and digest) or the raised error. A page call
also holds the marker its cursor decodes to, since Python decodes the cursor
before the resident reads.
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

from approval_page_read_scenarios import SCENARIOS
from approval_read_scenarios import SOURCE, encode_page_cursor
from record_approval_read_vectors import LONG_STRING, insert, mark_long

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import _decode_page_cursor

PAGE_DEFAULTS: dict[str, object] = {
    "status": "pending",
    "limit": 50,
    "cursor": None,
    "harness": None,
    "search": None,
    "include_totals": True,
    "exclude_watch_only": False,
}
COUNT_DEFAULTS: dict[str, object] = {
    "status": "pending",
    "harness": None,
    "search": None,
    "resolved_at_from": None,
    "resolved_at_before": None,
    "exclude_watch_only": False,
}


def page_args(method: str, args: dict[str, object], rows: list[dict[str, object]]) -> dict[str, object]:
    resolved = {**PAGE_DEFAULTS, **args}
    if method == "pending":
        resolved["status"] = "pending"
    cursor_of = resolved.pop("cursor_of", None)
    if cursor_of is not None:
        anchor = next(item for item in rows if item["request_id"] == cursor_of)
        resolved["cursor"] = encode_page_cursor(anchor)
    return resolved


def call(store: GuardStore, spec: dict[str, object], rows: list[dict[str, object]]) -> dict[str, object]:
    method = str(spec["method"])
    args = dict(spec["args"])  # type: ignore[arg-type]
    recorded: dict[str, object] = {"method": method}
    if method in {"page", "pending"}:
        args = page_args(method, args, rows)
        cursor = args["cursor"]
        marker = _decode_page_cursor(cursor) if isinstance(cursor, str) else None
        recorded["cursor_marker"] = None if marker is None else [marker["last_seen_at"], marker["request_id"]]
        call_args = dict(args)
        if method == "pending":
            del call_args["status"]
        invoke = getattr(store, "list_approval_request_page" if method == "page" else "list_pending_approval_summaries")
    elif method == "count":
        args = {**COUNT_DEFAULTS, **args}
        call_args = dict(args)
        invoke = store.count_approval_requests
    else:
        call_args = {"exclude_ids": set(args["exclude_ids"])}  # type: ignore[arg-type]
        invoke = store.get_next_pending_request
    recorded["args"] = args
    try:
        recorded["result"] = mark_long(invoke(**call_args))
    except ValueError as error:
        recorded["error"] = {"type": type(error).__name__, "message": str(error)}
    return recorded


def run(scenario: dict[str, object]) -> dict[str, object]:
    rows: list[dict[str, object]] = scenario["rows"]  # type: ignore[assignment]
    pads: dict[str, object] = dict(scenario.get("pads", {}))  # type: ignore[arg-type]
    with tempfile.TemporaryDirectory(prefix="approval-page-read-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE)
        insert(Path(store.path), rows, pads)
        calls = [call(store, spec, rows) for spec in scenario["calls"]]  # type: ignore[attr-defined]
    return {"name": scenario["name"], "rows": rows, "pads": pads, "calls": calls}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="approval-page-read-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE).path)
        connection = sqlite3.connect(path)
        schema = [
            item[0]
            for item in connection.execute(
                "select sql from sqlite_master where sql is not null and name not like 'sqlite_%' order by rowid"
            )
        ]
        connection.close()
    document = {
        "schema": "guard-store-approval-page-read-vectors.v1",
        "source": SOURCE,
        "long_string": LONG_STRING,
        "schema_sql": schema,
        "scenarios": [run(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
