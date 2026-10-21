#!/usr/bin/env python3
"""Record approval queue read vectors from the Python implementation.

Run against a checkout from before the Rust read landed, whose
`store_approvals.py` still holds the Python reads, with a native runtime for
the canonical surfaces and scope contracts the reads ask the resident for:

    cd <origin-main-worktree>
    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario (`approval_read_scenarios.py`) seeds `approval_requests`, then
reads through `GuardStore.get_approval_request` and
`GuardStore.list_approval_requests`. Per call the vectors hold the returned
payloads (a string past `LONG_STRING` as its length and digest) or the
raised error. A list call also holds the page marker its
cursor decodes to, since Python decodes the cursor before the resident reads.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

if os.environ.get("HOL_GUARD_NATIVE") != "force" or not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("refusing to record: set HOL_GUARD_NATIVE=force and HOL_GUARD_NATIVE_BINARY")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from approval_read_scenarios import PAD, SCENARIOS, SOURCE, encode_page_cursor, expand, padded_envelope

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import _decode_page_cursor

LONG_STRING = 65_536


def insert(path: Path, rows: list[dict[str, object]], pads: dict[str, object]) -> None:
    connection = sqlite3.connect(path)
    try:
        for item in rows:
            values = {
                key: padded_envelope(pads[str(item["request_id"])]) if value == PAD else expand(value)  # type: ignore[arg-type]
                for key, value in item.items()
            }
            columns = ",".join(values)
            marks = ",".join("?" * len(values))
            connection.execute(f"insert into approval_requests ({columns}) values ({marks})", tuple(values.values()))
        connection.commit()
    finally:
        connection.close()


def list_args(args: dict[str, object], rows: list[dict[str, object]]) -> dict[str, object]:
    resolved = {"status": "pending", "harness": None, "limit": 50, "cursor": None, "search": None, **args}
    cursor_of = resolved.pop("cursor_of", None)
    if cursor_of is not None:
        anchor = next(item for item in rows if item["request_id"] == cursor_of)
        resolved["cursor"] = encode_page_cursor(anchor)
    return resolved


def mark_long(value: object) -> object:
    """Spell each string past `LONG_STRING` as `__long__:<length>:<sha256>`."""

    if isinstance(value, str) and len(value) > LONG_STRING:
        return f"__long__:{len(value)}:{hashlib.sha256(value.encode()).hexdigest()}"
    if isinstance(value, dict):
        return {key: mark_long(item) for key, item in value.items()}
    if isinstance(value, list):
        return [mark_long(item) for item in value]
    return value


def call(store: GuardStore, spec: dict[str, object], rows: list[dict[str, object]]) -> dict[str, object]:
    if spec["method"] == "get":
        recorded: dict[str, object] = dict(spec)
        invoke = lambda: store.get_approval_request(  # noqa: E731
            str(spec["request_id"]), derive_scope=bool(spec["derive_scope"])
        )
    else:
        args = list_args(dict(spec["args"]), rows)  # type: ignore[arg-type]
        cursor = args["cursor"]
        marker = _decode_page_cursor(cursor) if isinstance(cursor, str) else None
        recorded = {
            "method": "list",
            "args": args,
            "cursor_marker": None if marker is None else [marker["last_seen_at"], marker["request_id"]],
        }
        invoke = lambda: store.list_approval_requests(**args)  # type: ignore[arg-type]  # noqa: E731
    try:
        recorded["result"] = mark_long(invoke())
    except ValueError as error:
        recorded["error"] = {"type": type(error).__name__, "message": str(error)}
    return recorded


def run(scenario: dict[str, object]) -> dict[str, object]:
    rows: list[dict[str, object]] = scenario["rows"]  # type: ignore[assignment]
    pads: dict[str, object] = dict(scenario.get("pads", {}))  # type: ignore[arg-type]
    with tempfile.TemporaryDirectory(prefix="approval-read-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE)
        insert(Path(store.path), rows, pads)
        calls = [call(store, spec, rows) for spec in scenario["calls"]]  # type: ignore[attr-defined]
    return {"name": scenario["name"], "rows": rows, "pads": pads, "calls": calls}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="approval-read-schema-") as root:
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
        "schema": "guard-store-approval-read-vectors.v1",
        "source": SOURCE,
        "long_string": LONG_STRING,
        "schema_sql": schema,
        "scenarios": [run(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
