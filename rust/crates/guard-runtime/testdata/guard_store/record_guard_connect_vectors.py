#!/usr/bin/env python3
"""Record guard connect-state vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
of the connect-state methods, never against the branch under test and never
from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario replays `guard_connect_scenarios.SCENARIOS` through the Python
store methods on a real `guard.db`. Per step the vectors hold the Python
result (or error), the post-step state of every table, and the request the
native transport must send (`wire_args`, translated here independently of the
new code). The recorded result is also the payload the resident must return.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import store_oauth

if not hasattr(store_oauth.StoreOAuthConnectMixin, "_coerce_guard_connect_state_status"):
    sys.exit("refusing to record: the original Python connect-state implementation is gone")

from guard_connect_scenarios import NOW, SCENARIOS

from codex_plugin_scanner.guard.store import GuardStore

# GuardStore startup writes wall-clock bookkeeping rows into `sync_state`; only the
# row the connect methods read is part of the comparison.
ROW_FILTER = {"sync_state": "state_key = 'sync_summary'"}


def dump(path: Path, order: dict[str, str]) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return {
            table: [
                dict(row)
                for row in connection.execute(
                    f"select * from {table} where {ROW_FILTER.get(table, '1')} order by {key}"
                )
            ]
            for table, key in order.items()
        }
    finally:
        connection.close()


def schema_sql_for_tables(path: Path, tables: tuple[str, ...]) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                f"select sql from sqlite_master where sql is not null and tbl_name in ({','.join('?' * len(tables))}) "
                "order by case type when 'table' then 0 when 'index' then 1 else 2 end, rowid",
                tables,
            )
        ]
    finally:
        connection.close()


TABLES = {
    "guard_connect_states": "request_id",
    "guard_connect_requests": "request_id",
    "sync_state": "state_key",
}
NATIVE_METHODS = {
    "get_latest_guard_connect_state": "guard_connect_latest_state",
    "get_effective_guard_connect_state": "guard_connect_effective_state",
    "record_guard_connect_pairing_completed": "guard_connect_record_pairing",
    "record_latest_guard_connect_sync_result": "guard_connect_record_sync_result",
    "record_latest_guard_connect_sync_success": "guard_connect_record_sync_result",
}


def allowed_origin(sync_url: str) -> str | None:
    parsed = urlparse(sync_url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def wire(method: str, kwargs: dict, profile: object, result: object) -> dict[str, object]:
    if method == "get_latest_guard_connect_state":
        return {"now": kwargs["now"]}
    if method == "get_effective_guard_connect_state":
        cloud = None
        if profile is not None:
            cloud = {"sync_url": profile["sync_url"], "allowed_origin": allowed_origin(profile["sync_url"])}  # type: ignore[index]
        return {"now": kwargs["now"], "cloud_profile": cloud}
    if method == "record_guard_connect_pairing_completed":
        supplied = kwargs.get("request_id")
        request_id = supplied.strip() if isinstance(supplied, str) and supplied.strip() else None
        if request_id is None:
            request_id = result["request_id"] if isinstance(result, dict) else "<GENERATED>"
        return {
            "request_id": request_id,
            "sync_url": kwargs["sync_url"],
            "allowed_origin": kwargs["allowed_origin"],
            "now": kwargs["now"],
        }
    if method == "record_latest_guard_connect_sync_success":
        kwargs = {**kwargs, "status": "connected", "milestone": "first_sync_succeeded", "reason": None}
    return {
        "status": kwargs["status"],
        "milestone": kwargs["milestone"],
        "now": kwargs["now"],
        "reason": kwargs.get("reason"),
        "request_id": kwargs.get("request_id"),
        "sync_payload": kwargs.get("sync_payload"),
    }


def run_scenario(scenario: dict) -> dict[str, object]:
    counter = iter(range(1, 1000))
    store_oauth.uuid4 = lambda: SimpleNamespace(hex=f"{next(counter):032x}")
    with tempfile.TemporaryDirectory(prefix="guard-connect-vectors-") as root:
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
                record.update(
                    method="sql", native_method="sql", sql=step["sql"], wire_args=None, result=None, error=None
                )
            else:
                method, kwargs, profile = step["method"], step.get("kwargs", {}), step.get("profile")
                store.get_cloud_sync_profile = lambda profile=profile: profile  # type: ignore[method-assign]
                record.update(method=method, native_method=NATIVE_METHODS[method])
                try:
                    result = getattr(store, method)(**kwargs)
                    record.update(
                        wire_args=wire(method, kwargs, profile, result),
                        result=json.loads(json.dumps(result)),
                        error=None,
                    )
                    record["native_payload"] = record["result"]
                except (ValueError, RuntimeError, sqlite3.IntegrityError) as error:
                    # A JSONDecodeError is a ValueError whose text only CPython can spell.
                    kind = "ValueError" if isinstance(error, ValueError) else type(error).__name__
                    record.update(
                        wire_args=wire(method, kwargs, profile, None),
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
    with tempfile.TemporaryDirectory(prefix="guard-connect-schema-") as root:
        schema = schema_sql_for_tables(
            Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path), tuple(TABLES)
        )
    document = {
        "schema": "guard-store-guard-connect-vectors.v1",
        "source": "guard",
        "now": NOW,
        "order_by": TABLES,
        "row_filter": ROW_FILTER,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
