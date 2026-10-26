#!/usr/bin/env python3
"""Record guard receipt vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
(`store_receipts.py` / `store_receipt_rollups.py` / `decision_boundaries.py`),
never against the branch under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output receipts_vectors.json>

Each scenario replays the receipt write and read scenarios through the Python
store methods on a real `guard.db`. Per step the vectors hold the Python
result (or error), the post-step state of every receipt-related table, the
request the native transport must send (`wire_args`, translated here
independently of the new code) and `native_payload`: what the resident must
return (the Python return value for reads, null for writes).
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import (
    store_cloud_events,
    store_connection_schema,
    store_receipt_rollups,
    store_receipts,
)

if not hasattr(store_receipt_rollups, "canonical_receipt_rollup_action"):
    sys.exit("refusing to record: the original Python receipt implementation is gone")

from receipts_mutator_scenarios import MUTATOR_SCENARIOS
from receipts_read_scenarios import READ_SCENARIOS
from receipts_scenario_support import NOW, QUEUE_LIMIT
from receipts_write_scenarios import WRITE_SCENARIOS
from vector_support import dump, schema_sql_for_tables

from codex_plugin_scanner.guard.store import GuardStore

TABLES = {
    "runtime_receipts": "rowid",
    "runtime_receipt_envelopes": "receipt_id",
    "receipt_aggregate_totals": "totals_key",
    "receipt_daily_rollups": "day_key",
    "receipt_harness_rollups": "harness",
    "receipt_artifact_rollups": "artifact_key",
    "receipt_rollup_actions": "receipt_id",
    "guard_cloud_events": "idempotency_key",
    "sync_state": "state_key",
    "guard_devices": "device_key",
    "approval_requests": "request_id",
    "guard_storage_maintenance": "singleton",
}
UNUSED_DEVICE_ID = "f" * 32
NOW_VALUE = datetime.fromisoformat(NOW)


class _FixedDatetime(datetime):
    @classmethod
    def now(cls, tz: object = None) -> datetime:  # type: ignore[override]
        return NOW_VALUE if tz is not None else NOW_VALUE.replace(tzinfo=None)


def _receipt_wire(receipt: object) -> dict[str, object]:
    return {
        "receipt_id": receipt.receipt_id,  # type: ignore[attr-defined]
        "timestamp": receipt.timestamp,  # type: ignore[attr-defined]
        "harness": receipt.harness,  # type: ignore[attr-defined]
        "artifact_id": receipt.artifact_id,  # type: ignore[attr-defined]
        "artifact_hash": receipt.artifact_hash,  # type: ignore[attr-defined]
        "policy_decision": receipt.policy_decision,  # type: ignore[attr-defined]
        "capabilities_summary": receipt.capabilities_summary,  # type: ignore[attr-defined]
        "changed_capabilities": list(receipt.changed_capabilities),  # type: ignore[attr-defined]
        "provenance_summary": receipt.provenance_summary,  # type: ignore[attr-defined]
        "user_override": receipt.user_override,  # type: ignore[attr-defined]
        "artifact_name": receipt.artifact_name,  # type: ignore[attr-defined]
        "source_scope": receipt.source_scope,  # type: ignore[attr-defined]
        "diff_summary": receipt.diff_summary,  # type: ignore[attr-defined]
        "approval_source": receipt.approval_source,  # type: ignore[attr-defined]
        "approval_request_id": receipt.approval_request_id,  # type: ignore[attr-defined]
        "scanner_evidence": [dict(item) for item in receipt.scanner_evidence],  # type: ignore[attr-defined]
        "raw_command_text": receipt.raw_command_text,  # type: ignore[attr-defined]
    }


def wire(method: str, args: tuple, kwargs: dict, device_id: str) -> dict[str, object]:
    if method == "add_receipt":
        envelope = kwargs.get("action_envelope")
        return {
            "receipt": _receipt_wire(args[0]),
            "action_envelope": envelope.to_dict() if envelope is not None else None,
            "now": NOW,
            "new_device_id": device_id,
            "event_queue_limit": QUEUE_LIMIT,
        }
    if method == "set_receipt_action_envelope":
        return {"receipt_id": args[0], "action_envelope": args[1]}
    if method == "update_receipt_policy_decision":
        return {"receipt_id": args[0], "policy_decision": args[1]}
    if method == "update_receipt_approval_context":
        return {
            "receipt_id": args[0],
            "approval_source": kwargs["approval_source"],
            "approval_request_id": kwargs["approval_request_id"],
        }
    if method == "list_receipts":
        names = ("limit", "harness")
        values = {**dict(zip(names, args, strict=False)), **kwargs}
        return {"limit": values.get("limit", 50), "harness": values.get("harness")}
    if method == "list_receipts_since_rowid":
        return {
            "after_rowid": kwargs["after_rowid"],
            "limit": kwargs.get("limit", 200),
            "harness": kwargs.get("harness"),
        }
    if method == "list_receipts_for_command_detail_backfill":
        return {
            "limit": kwargs.get("limit", 2000),
            "days": kwargs.get("days", 7),
            "before_rowid": kwargs.get("before_rowid"),
            "now": NOW,
        }
    if method == "latest_receipt_rowid":
        return {"harness": kwargs.get("harness")}
    if method == "get_receipt":
        return {"receipt_id": args[0]}
    if method == "get_receipt_for_approval_request":
        return {"request_id": args[0], "policy_decision": kwargs["policy_decision"]}
    if method == "get_latest_receipt":
        return {"harness": args[0], "artifact_id": args[1]}
    if method == "count_receipts":
        return {"harness": kwargs.get("harness")}
    if method == "receipt_summary_between":
        return {"start_at": kwargs["start_at"], "before_at": kwargs["before_at"]}
    if method == "receipt_analytics":
        return {
            "activity_days": kwargs.get("activity_days", 90),
            "trend_days": kwargs.get("trend_days", 7),
            "top_limit": kwargs.get("top_limit", 10),
            "now": NOW,
        }
    if method == "receipt_decision_counts":
        return {"harness": args[0], "artifact_id": args[1]}
    if method == "reconcile_receipt_events":
        return {}
    raise AssertionError(method)


WRITES = {
    "add_receipt",
    "set_receipt_action_envelope",
    "update_receipt_policy_decision",
    "update_receipt_approval_context",
    "reconcile_receipt_events",
}


def _call(store: GuardStore, method: str, args: tuple, kwargs: dict) -> object:
    if method == "reconcile_receipt_events":
        store.list_guard_events_v1(limit=1)
        return None
    return getattr(store, method)(*args, **kwargs)


def run_scenario(scenario: dict) -> dict[str, object]:
    counter = iter(range(1, 1000))
    consumed = {"last": None}

    def fake_uuid4() -> SimpleNamespace:
        value = f"{next(counter):032x}"
        consumed["last"] = value
        return SimpleNamespace(hex=value)

    store_connection_schema.uuid4 = fake_uuid4
    store_connection_schema._now = lambda: NOW
    for module in (store_receipts, store_receipt_rollups, store_cloud_events):
        module.datetime = _FixedDatetime
    with tempfile.TemporaryDirectory(prefix="guard-receipts-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, guard_event_queue_limit=QUEUE_LIMIT)
        path = Path(store.path)
        # The device row is created by the first add_receipt (the schema does not seed it
        # before the vectors start recording).
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
                consumed["last"] = None
                try:
                    result = _call(store, method, args, kwargs)
                    record.update(result=json.loads(json.dumps(result)), error=None)
                    record["native_payload"] = record["result"] if method not in WRITES else None
                except (ValueError, RuntimeError, sqlite3.IntegrityError) as error:
                    # A JSONDecodeError is a ValueError whose text only CPython can spell.
                    kind = "ValueError" if isinstance(error, ValueError) else type(error).__name__
                    record.update(
                        result=None,
                        native_payload=None,
                        error={"type": kind, "message": str(error), "message_exact": type(error).__name__ == kind},
                    )
                device_id = consumed["last"] if consumed["last"] is not None else UNUSED_DEVICE_ID
                record.update(method=method, wire_args=wire(method, args, kwargs, device_id))
            current = dump(path, TABLES)
            record["post_changed"] = {t: rows_ for t, rows_ in current.items() if rows_ != previous[t]}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-receipts-schema-") as root:
        schema = schema_sql_for_tables(
            Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path), TABLES
        )
    document = {
        "schema": "guard-store-receipts-vectors.v1",
        "source": "guard",
        "now": NOW,
        "queue_limit": QUEUE_LIMIT,
        "order_by": TABLES,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in [*WRITE_SCENARIOS, *MUTATOR_SCENARIOS, *READ_SCENARIOS]],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
