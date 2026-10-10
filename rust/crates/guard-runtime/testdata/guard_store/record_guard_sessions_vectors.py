#!/usr/bin/env python3
"""Record guard sessions/operations/attachments vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
of `StoreSessionsMixin`, never against the branch under test and never from
Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario replays `guard_sessions_scenarios.SCENARIOS` through the Python
store methods on a real `guard.db`. Per step the vectors hold the Python
result (or error), the post-step state of every table, the request the native
transport must send (`wire_args`, translated here independently of the new
code), and `native_payload`: the raw rows the resident must return, read back
with direct SQL from the Python-written database.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import store_sessions

if not hasattr(store_sessions, "preserve_retry_lineage"):
    sys.exit("refusing to record: the original Python sessions implementation is gone")

from guard_sessions_scenarios import NOW, SCENARIOS, wire_json
from vector_support import dump

from codex_plugin_scanner.guard.store import GuardStore

TABLES = {
    "guard_sessions": "session_id",
    "guard_operations": "operation_id",
    "guard_operation_items": "item_id",
    "guard_client_attachments": "client_id",
    "guard_surface_opens": "surface, open_key",
}
SESSION_COLUMNS = (
    "session_id, harness, surface, status, client_name, client_title, client_version, workspace, "
    "capabilities_json, created_at, updated_at"
)
OPERATION_COLUMNS = (
    "operation_id, session_id, harness, operation_type, status, approval_request_ids_json, "
    "resume_token, metadata_json, created_at, updated_at"
)
ITEM_COLUMNS = "item_id, operation_id, item_type, lifecycle, payload_json, created_at"
ATTACHMENT_COLUMNS = (
    "client_id, surface, session_id, metadata_json, lease_id, lease_expires_at, attached_at, last_seen_at"
)


def wire(method: str, args: tuple, kwargs: dict) -> dict[str, object]:
    if method == "upsert_guard_session":
        keys = ("session_id", "harness", "surface", "status", "client_name", "client_title", "client_version")
        out = {key: kwargs[key] for key in keys}
        out.update(
            workspace=kwargs["workspace"],
            capabilities_json=wire_json(kwargs["capabilities"]),
            now=kwargs["now"],
        )
        return out
    if method == "get_guard_session":
        return {"session_id": args[0]}
    if method == "list_guard_sessions":
        return {"status": kwargs.get("status"), "limit": kwargs.get("limit", 100)}
    if method == "upsert_guard_operation":
        keys = ("operation_id", "session_id", "harness", "operation_type", "status", "resume_token", "now")
        out = {key: kwargs[key] for key in keys}
        out.update(
            approval_request_ids_json=wire_json(kwargs["approval_request_ids"]),
            metadata_json=wire_json(kwargs["metadata"]),
        )
        return out
    if method == "get_guard_operation":
        return {"operation_id": args[0]}
    if method == "list_guard_operations":
        return {"session_id": kwargs.get("session_id"), "limit": kwargs.get("limit", 100)}
    if method == "get_guard_operation_for_approval_request":
        return {"request_id": args[0]}
    if method == "add_guard_operation_item":
        keys = ("item_id", "operation_id", "item_type", "lifecycle", "now")
        return {**{key: kwargs[key] for key in keys}, "payload_json": wire_json(kwargs["payload"])}
    if method == "list_guard_operation_items":
        return {"operation_id": args[0]}
    if method == "attach_guard_client":
        keys = ("client_id", "surface", "session_id", "lease_seconds", "now")
        out = {key: kwargs[key] for key in keys}
        out.update(metadata_json=wire_json(kwargs["metadata"]), lease_id="<RECORDED>")
        return out
    if method == "renew_guard_client_attachment":
        return {key: kwargs[key] for key in ("client_id", "lease_id", "lease_seconds", "now")}
    if method == "get_guard_client_attachment":
        return {"client_id": args[0]}
    if method == "list_guard_client_attachments":
        return {
            "surface": kwargs.get("surface"),
            "session_id": kwargs.get("session_id"),
            "active_within_seconds": kwargs.get("active_within_seconds", 60),
            "now": "<NOW>",
        }
    if method == "record_guard_surface_open":
        return {key: kwargs[key] for key in ("surface", "open_key", "now")}
    if method == "has_guard_surface_open":
        return {"surface": kwargs["surface"], "open_key": kwargs["open_key"]}
    raise AssertionError(method)


def rows(path: Path, sql: str, params: tuple = ()) -> list[dict[str, object]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(sql, params)]
    finally:
        connection.close()


def native_payload(path: Path, method: str, args: tuple, kwargs: dict, result: object) -> object:
    """What the resident must return, read back from the Python-written database."""

    if method in ("upsert_guard_session", "get_guard_session"):
        session_id = kwargs["session_id"] if method == "upsert_guard_session" else args[0]
        found = rows(path, f"select {SESSION_COLUMNS} from guard_sessions where session_id = ?", (session_id,))
        return found[0] if found else None
    if method == "list_guard_sessions":
        return [
            rows(path, f"select {SESSION_COLUMNS} from guard_sessions where session_id = ?", (item["session_id"],))[0]
            for item in result  # type: ignore[attr-defined]
        ]
    if method in ("upsert_guard_operation", "get_guard_operation"):
        operation_id = kwargs["operation_id"] if method == "upsert_guard_operation" else args[0]
        found = rows(path, f"select {OPERATION_COLUMNS} from guard_operations where operation_id = ?", (operation_id,))
        return found[0] if found else None
    if method == "list_guard_operations":
        return [
            rows(
                path,
                f"select {OPERATION_COLUMNS} from guard_operations where operation_id = ?",
                (item["operation_id"],),
            )[0]
            for item in result  # type: ignore[attr-defined]
        ]
    if method == "get_guard_operation_for_approval_request":
        if result is None:
            return None
        return rows(
            path,
            f"select {OPERATION_COLUMNS} from guard_operations where operation_id = ?",
            (result["operation_id"],),  # type: ignore[index]
        )[0]
    if method == "add_guard_operation_item":
        return rows(path, f"select {ITEM_COLUMNS} from guard_operation_items where item_id = ?", (kwargs["item_id"],))[
            0
        ]
    if method == "list_guard_operation_items":
        return rows(
            path,
            f"select {ITEM_COLUMNS} from guard_operation_items where operation_id = ? "
            "order by created_at asc, item_id asc",
            (args[0],),
        )
    if method in ("attach_guard_client", "renew_guard_client_attachment", "get_guard_client_attachment"):
        if method != "get_guard_client_attachment" and result is None:
            return None
        client_id = args[0] if method == "get_guard_client_attachment" else kwargs["client_id"]
        found = rows(
            path, f"select {ATTACHMENT_COLUMNS} from guard_client_attachments where client_id = ?", (client_id,)
        )
        return found[0] if found else None
    if method == "list_guard_client_attachments":
        return [
            rows(
                path,
                f"select {ATTACHMENT_COLUMNS} from guard_client_attachments where client_id = ?",
                (item["client_id"],),
            )[0]
            for item in result  # type: ignore[attr-defined]
        ]
    if method == "has_guard_surface_open":
        return bool(result)
    if method == "record_guard_surface_open":
        return None
    raise AssertionError(method)


def schema_sql(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                f"select sql from sqlite_master where sql is not null and tbl_name in ({','.join('?' * len(TABLES))}) "
                "order by case type when 'table' then 0 when 'index' then 1 else 2 end, rowid",
                tuple(TABLES),
            )
        ]
    finally:
        connection.close()


def run_scenario(scenario: dict) -> dict[str, object]:
    counter = iter(range(1, 1000))
    store_sessions.uuid4 = lambda: SimpleNamespace(hex=f"{next(counter):032x}")
    with tempfile.TemporaryDirectory(prefix="guard-sessions-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        previous = dump(path, TABLES)
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
                record.update(method=method, wire_args=wire(method, args, kwargs))
                try:
                    result = getattr(store, method)(*args, **kwargs)
                    payload = native_payload(path, method, args, kwargs, result)
                    if method == "attach_guard_client":
                        record["wire_args"]["lease_id"] = payload["lease_id"]  # type: ignore[index]
                    record.update(result=json.loads(json.dumps(result)), native_payload=payload, error=None)
                except (ValueError, RuntimeError, sqlite3.IntegrityError) as error:
                    # A JSONDecodeError is a ValueError whose text only CPython can spell.
                    kind = "ValueError" if isinstance(error, ValueError) else type(error).__name__
                    record.update(
                        result=None,
                        native_payload=None,
                        error={"type": kind, "message": str(error), "message_exact": type(error).__name__ == kind},
                    )
            current = dump(path, TABLES)
            record["post_changed"] = {t: rows_ for t, rows_ in current.items() if rows_ != previous[t]}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-sessions-schema-") as root:
        schema = schema_sql(Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path))
    document = {
        "schema": "guard-store-guard-sessions-vectors.v1",
        "source": "guard",
        "now": NOW,
        "order_by": TABLES,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
