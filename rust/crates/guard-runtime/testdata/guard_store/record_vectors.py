#!/usr/bin/env python3
"""Record `guard_store` parity vectors from the ORIGINAL Python store.

Run against a checkout that still contains the pre-native Python
implementation (origin/main before the `guard_store` op), never against the
branch under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario seeds a real `guard.db` created by the Python `GuardStore`, then
replays steps through the Python store methods while the wall clock and
`uuid4` are frozen. The vectors hold the database schema, the seed rows, and
for every step the method result plus the full post-step state of every table
the outbox methods may touch. The recorder fails if any other table changes.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

try:
    import codex_plugin_scanner.guard.native_guard_store  # noqa: F401
except ImportError:
    pass
else:
    sys.exit("refusing to record: native_guard_store exists, point PYTHONPATH at origin/main")

from vector_scenarios import SCENARIOS, SOURCE, Context, Step

from codex_plugin_scanner.guard import (
    store_connection_schema,
    store_review_event_outbox,
    store_review_event_outbox_schema,
    store_review_event_outbox_writes,
)
from codex_plugin_scanner.guard.store import GuardStore

FROZEN_NOW = "2026-09-01T12:00:00+00:00"
SEED_UUID_BASE = 0x1000
STEP_UUID_BASE = 0xA000
TABLES = (
    "approval_requests",
    "guard_devices",
    "guard_review_outbox_cursors",
    "guard_review_outbox_events",
    "guard_review_outbox_request_sequences",
    "guard_review_outbox_wake_state",
    "sync_state",
)


class _Uuid:
    counter = SEED_UUID_BASE

    def __init__(self, value: int) -> None:
        self.hex = f"{value:032x}"


def _fake_uuid4() -> _Uuid:
    _Uuid.counter += 1
    return _Uuid(_Uuid.counter - 1)


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return datetime.fromisoformat(FROZEN_NOW)


def rows_of(path: Path, table: str) -> list[dict[str, object]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        order = "rowid"
        try:
            rows = connection.execute(f"select * from {table} order by {order}").fetchall()
        except sqlite3.OperationalError:
            rows = connection.execute(f"select * from {table} order by 1").fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def all_tables(path: Path) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    names = [
        row[0]
        for row in connection.execute(
            "select name from sqlite_master where type = 'table' and name not like 'sqlite_%' order by name"
        )
    ]
    connection.close()
    return {name: rows_of(path, name) for name in names}


def schema_sql(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                "select sql from sqlite_master where sql is not null and name not like 'sqlite_%' "
                "order by case type when 'table' then 0 when 'index' then 1 else 2 end, rowid"
            )
        ]
    finally:
        connection.close()


def identity_kwargs(ctx: Context, **extra: object) -> dict[str, object]:
    return {**ctx.ident(), **extra}


# ---- wire translation: what the Python wrapper must send to the resident ----


def _ident(kwargs: dict[str, object]) -> dict[str, object]:
    return {
        "oauth_subject_hash": kwargs.get("oauth_subject_hash"),
        "workspace_id": kwargs.get("workspace_id"),
        "machine_id": kwargs.get("machine_id"),
        "machine_installation_id": kwargs.get("machine_installation_id"),
    }


def wire(method: str, kwargs: dict[str, object]) -> dict[str, object]:
    if method in {"get_review_event_oauth_binding", "refresh_review_event_outbox_binding"}:
        return {}
    if method == "count_recoverable_unbound_review_events":
        return {}
    if method == "list_review_event_snapshots":
        return {"request_id": kwargs["request_id"]}
    if method == "review_event_outbox_status":
        return {"now": kwargs["now"], **_ident(kwargs)}
    if method == "list_ready_review_events":
        return {"now": kwargs["now"], "limit": kwargs["limit"], **_ident(kwargs)}
    if method == "list_pending_review_request_ids":
        return {
            "binding": kwargs["binding"],
            "limit": kwargs["limit"],
            "after_request_id": kwargs.get("after_request_id"),
            "through_request_id": kwargs.get("through_request_id"),
            "descending": kwargs.get("descending", False),
        }
    if method == "refresh_review_event_outbox_binding_for_identity":
        return _ident(kwargs)
    if method == "reassign_quarantined_review_events":
        return {
            "approved_source": kwargs["approved_source"],
            "approved_workspace_id": kwargs["approved_workspace_id"],
            "only_unbound": kwargs.get("only_unbound", False),
        }
    if method == "acknowledge_review_events":
        return {
            "sequences": sorted({int(s) for s in kwargs["sequences"] if int(s) > 0}),
            "acknowledged_at": FROZEN_NOW,
            **_ident(kwargs),
        }
    if method == "retry_review_events":
        return {
            "sequences": sorted({int(s) for s in kwargs["sequences"] if int(s) > 0}),
            "now": kwargs["now"],
            "fallback_now": FROZEN_NOW,
            "error": kwargs["error"],
            **_ident(kwargs),
        }
    if method == "quarantine_review_event":
        return {
            "sequence": int(kwargs["sequence"]),
            "reason": kwargs["reason"],
            "error": kwargs["error"],
            **_ident(kwargs),
        }
    if method == "requeue_pending_review_events":
        ids = kwargs.get("request_ids")
        return {
            "changed_at": kwargs["changed_at"],
            "require_binding": kwargs.get("require_binding", False),
            "snapshot_repair_sequences": kwargs.get("snapshot_repair_sequences"),
            "request_ids": None if ids is None else sorted(ids),
            "request_snapshots": kwargs.get("request_snapshots"),
        }
    if method == "requeue_pending_review_events_with_marker":
        ids = kwargs.get("request_ids")
        payload = kwargs["marker_payload"]
        sentinel = "\u0000requeued\u0000"
        rendered = json.dumps({**payload, "requeued": sentinel})
        token = json.dumps(sentinel)
        before, _, after = rendered.partition(token)
        return {
            "changed_at": kwargs["changed_at"],
            "marker_key": kwargs["marker_key"],
            "marker_json_parts": [before, after],
            "require_binding": kwargs.get("require_binding", False),
            "only_retry_identity_drift": kwargs.get("only_retry_identity_drift", False),
            "request_ids": None if ids is None else sorted(ids),
            "request_snapshots": kwargs.get("request_snapshots"),
            "native_replay": payload.get("native_replay") is True
            or payload.get("schema") == "guard-cloud-review-native-workspace-review-request.v1",
        }
    if method == "repair_rejected_review_correlation":
        return {
            "event_sequence": kwargs["event_sequence"],
            "binding": kwargs["binding"],
            "changed_at": kwargs["changed_at"],
        }
    if method == "recover_review_snapshot_sequences":
        collisions = kwargs["collisions"]
        return {
            "collisions": [[int(seq), event_id] for seq, event_id in collisions.items()],
            "acknowledged_through": kwargs["acknowledged_through"],
            "binding": kwargs["binding"],
        }
    raise KeyError(method)


def jsonable(value: object) -> object:
    if isinstance(value, set):
        return sorted(value)
    return value


def native_result(method: str, value: object) -> object:
    """Native payload shape for a Python return value."""
    if method == "recover_review_snapshot_sequences":
        assert isinstance(value, dict)
        return [[old, new] for old, new in sorted(value.items())]
    return value


def call_python(store: GuardStore, method: str, kwargs: dict[str, object]) -> object:
    call_kwargs = dict(kwargs)
    if method == "acknowledge_review_events":
        sequences = call_kwargs.pop("sequences")
        return store.acknowledge_review_events(sequences, **call_kwargs)
    if method == "retry_review_events":
        sequences = call_kwargs.pop("sequences")
        return store.retry_review_events(sequences, **call_kwargs)
    if method == "quarantine_review_event":
        sequence = call_kwargs.pop("sequence")
        return store.quarantine_review_event(sequence, **call_kwargs)
    if method == "refresh_review_event_outbox_binding_for_identity":
        workspace = call_kwargs.pop("workspace_id")
        return store.refresh_review_event_outbox_binding_for_identity(workspace, **call_kwargs)
    if method == "list_review_event_snapshots":
        return store.list_review_event_snapshots(call_kwargs["request_id"])
    if method in {"requeue_pending_review_events", "requeue_pending_review_events_with_marker"}:
        ids = call_kwargs.get("request_ids")
        if ids is not None:
            call_kwargs["request_ids"] = set(ids)
    return getattr(store, method)(**call_kwargs)


# ---- scenarios ----


def tracked(path: Path) -> dict[str, list[dict[str, object]]]:
    return {table: rows_of(path, table) for table in TABLES}


RANDOM = "<random>"
FAKE_ID_PREFIX = "0" * 20


def normalize_random_ids(
    tables: dict[str, list[dict[str, object]]], seen: set[str], seed_ids: set[str]
) -> dict[str, list[dict[str, object]]]:
    """Mask event ids drawn by SQLite triggers (`randomblob`), which no hook can freeze.

    Ids that predate the step, or come from the frozen counter, stay literal.
    """

    out: dict[str, list[dict[str, object]]] = {}
    for table, rows in tables.items():
        masked = []
        for row in rows:
            event_id = row.get("event_id") if table == "guard_review_outbox_events" else None
            if isinstance(event_id, str) and event_id not in seed_ids and not event_id.startswith(FAKE_ID_PREFIX):
                row = {**row, "event_id": RANDOM}
                seen.add(event_id)
            masked.append(row)
        out[table] = masked
    return out


def mask_result(value: object, seen: set[str]) -> object:
    if isinstance(value, str):
        return RANDOM if value in seen else value
    if isinstance(value, list):
        return [mask_result(item, seen) for item in value]
    if isinstance(value, dict):
        return {key: mask_result(item, seen) for key, item in value.items()}
    return value


def record_scenario(name: str, seed: Callable[[Context], None], build: Callable[[Context], list[Step]]) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        store = GuardStore(Path(directory) / "guard-home", source=SOURCE)
        ctx = Context(store)
        _Uuid.counter = SEED_UUID_BASE
        seed(ctx)
        path = Path(store.path)
        seed_rows = tracked(path)
        known = seed_rows
        seed_ids = {str(row["event_id"]) for row in seed_rows["guard_review_outbox_events"]}
        seen_random: set[str] = set()
        steps_out = []
        for method, make in build(ctx):
            kwargs = make(ctx)
            _Uuid.counter = STEP_UUID_BASE
            pre_all = all_tables(path)
            try:
                result: object = native_result(method, call_python(store, method, kwargs))
                error = None
            except Exception as exc:
                result, error = None, {"type": type(exc).__name__, "message": str(exc)}
            post_all = all_tables(path)
            for table, rows in post_all.items():
                if table not in TABLES and rows != pre_all.get(table):
                    raise SystemExit(f"{name}/{method}: untracked table {table} changed")
            now_rows = normalize_random_ids(tracked(path), seen_random, seed_ids)
            delta = {table: rows for table, rows in now_rows.items() if rows != known[table]}
            known = now_rows
            steps_out.append(
                {
                    "method": method,
                    "kwargs": json.loads(json.dumps(kwargs, default=jsonable)),
                    "wire_args": json.loads(json.dumps(wire(method, kwargs), default=jsonable)),
                    "uuid_start": STEP_UUID_BASE,
                    "result": mask_result(result, seen_random),
                    "error": error,
                    "post_changed": delta,
                }
            )
        return {"name": name, "seed": seed_rows, "steps": steps_out, "schema_sql": schema_sql(path)}


def main() -> None:
    out = Path(sys.argv[1])
    for module in (store_review_event_outbox_writes, store_review_event_outbox_schema, store_connection_schema):
        module.uuid4 = _fake_uuid4  # type: ignore[attr-defined]
    store_review_event_outbox.datetime = _FrozenDatetime  # type: ignore[attr-defined]
    scenarios = [record_scenario(name, seed, build) for name, seed, build in SCENARIOS]
    schema = scenarios[0]["schema_sql"]
    for scenario in scenarios:
        assert scenario.pop("schema_sql") == schema, "schema differs between scenarios"
    document = {
        "schema": "guard-store-parity-vectors.v1",
        "recorded_from": "origin/main python GuardStore",
        "frozen_now": FROZEN_NOW,
        "source": SOURCE,
        "tracked_tables": list(TABLES),
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    out.write_text(
        json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
