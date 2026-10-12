#!/usr/bin/env python3
"""Record artifact-diff, OAuth-source and keyring-mirror vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation of
these methods, never against the branch under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario replays `state_ops_scenarios.SCENARIOS` through the Python store
methods on a real `guard.db`. Per step the vectors hold the Python result (or
error), the post-step rows of every compared table, and the request the native
transport must send (`wire_args`, translated here independently of the new
code). The recorded result is also the payload the resident must return. A step
Python rejects before any store call has `native_method` null.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import store_oauth
from codex_plugin_scanner.guard.store_policy import _canonical_utc_timestamp

if not hasattr(store_oauth.StoreOAuthConnectMixin, "list_oauth_sources") or "_native_store_call" in (
    store_oauth.StoreOAuthConnectMixin.list_oauth_sources.__code__.co_names
):
    sys.exit("refusing to record: the original Python implementation is gone")

from state_ops_scenarios import NOW, SCENARIOS
from vector_support import schema_sql_for_tables

from codex_plugin_scanner.guard.store import GuardStore

# GuardStore startup writes wall-clock bookkeeping rows into `sync_state`; only the
# rows these methods read or write are part of the comparison.
ROW_FILTER = {
    "sync_state": "state_key like 'oauth_local_credentials%' or state_key like 'OAUTH_LOCAL_CREDENTIALS%' "
    "or state_key like 'oauth-local-credentials%' or state_key like 'managed_policy_bundle_keyring_%' "
    "or state_key = 'policy_bundle_keyring'",
}
TABLES = {"artifact_diffs": "diff_id", "sync_state": "state_key"}
NATIVE_METHODS = {
    "get_latest_diff": "artifact_latest_diff",
    "list_oauth_sources": "oauth_sources_list",
    "reconcile_managed_policy_bundle_keyring_state": "managed_keyring_reconcile",
}


def dump(path: Path) -> dict[str, list[dict[str, object]]]:
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
            for table, key in TABLES.items()
        }
    finally:
        connection.close()


def wire(method: str, kwargs: dict) -> dict[str, object] | None:
    if method == "get_latest_diff":
        return {"harness": kwargs["harness"], "artifact_id": kwargs["artifact_id"]}
    if method == "list_oauth_sources":
        return {}
    parts = (kwargs["provenance"], kwargs["managed_keyring"], kwargs["quarantined_local_keyring"])
    present = [part is not None for part in parts]
    if any(present) and not all(present):
        return None
    base = {
        "configured": all(present),
        "force_clear": kwargs.get("force_clear", False),
        "now": _canonical_utc_timestamp(kwargs["now"]),
    }
    if not all(present):
        return base
    try:
        encoded = [json.dumps(dict(part), allow_nan=False) for part in parts]
    except ValueError:
        return None
    return {
        **base,
        "provenance_json": encoded[0],
        "managed_keyring_json": encoded[1],
        "local_keyring_json": encoded[2],
    }


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-state-ops-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        previous = dump(path)
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
                method, kwargs = step["method"], step.get("kwargs", {})
                record.update(method=method)
                wire_args = wire(method, kwargs)
                record.update(native_method=NATIVE_METHODS[method] if wire_args is not None else None)
                try:
                    result = getattr(store, method)(**kwargs)
                    record.update(wire_args=wire_args, result=json.loads(json.dumps(result)), error=None)
                    record["native_payload"] = record["result"]
                except (ValueError, RuntimeError, sqlite3.IntegrityError) as error:
                    # A JSONDecodeError is a ValueError whose text only CPython can spell.
                    kind = "ValueError" if isinstance(error, ValueError) else type(error).__name__
                    record.update(
                        wire_args=wire_args,
                        result=None,
                        native_payload=None,
                        error={"type": kind, "message": str(error), "message_exact": type(error).__name__ == kind},
                    )
            current = dump(path)
            record["post_changed"] = {t: rows_ for t, rows_ in current.items() if rows_ != previous[t]}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-state-ops-schema-") as root:
        schema = schema_sql_for_tables(
            Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path), TABLES
        )
    document = {
        "schema": "guard-store-state-ops-vectors.v1",
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
