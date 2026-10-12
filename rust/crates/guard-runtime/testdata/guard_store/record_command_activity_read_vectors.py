#!/usr/bin/env python3
"""Record command-activity read, feedback and privacy vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
of the API, privacy and shadow-read store mixins, never against the branch
under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario seeds a real `guard.db` created by the Python `GuardStore` with
raw SQL, then replays calls through the original Python methods. Per step the
vectors hold the Python result (or error), the post-step state of every
command-activity table, the request the native transport must send
(`wire_args`, translated here from the call), and `native_payload`: the Python
result minus the fields the Python caller adds (`schema_version`, `schemas`),
which is exactly what the resident must return.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from codex_plugin_scanner.guard.store_command_activity_api import StoreCommandActivityApiMixin  # noqa: F401
except ImportError:
    sys.exit("refusing to record: the original Python read implementation is gone")

from command_activity_read_scenarios import SCENARIOS, seed_statements
from vector_support import dump, schema_sql, shadow_wire, tracked_tables

from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    COMMAND_ACTIVITY_HARNESSES,
    CommandProofLevel,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore

API_SCHEMA = "guard.command-activity-api.v1"
ERROR_CLASSES = [
    "cursor_observer_verify_failed",
    "maintenance_failed",
    "post_record_failed",
    "pre_record_failed",
    "shadow_evaluation_failed",
]


def _midnight(day: date) -> str:
    return datetime.combine(day, time.min, tzinfo=timezone.utc).isoformat()


def wire(method: str, args: tuple, kwargs: dict) -> dict[str, object]:
    if method == "list_command_activity_page":
        query = args[0]
        cursor = kwargs.get("cursor")
        until = None
        inclusive = False
        if query.occurred_through is not None:
            if query.occurred_through == date.max:
                until, inclusive = "9999-12-31T23:59:59.999999+00:00", True
            else:
                until = _midnight(query.occurred_through + timedelta(days=1))
        return {
            "filters": {
                "harness": query.harness,
                "execution_status": query.execution_status,
                "proof_level": query.proof_level,
                "approval_reuse_status": query.approval_reuse_status,
                "prompted": query.prompted,
                "extension_id": query.extension_id,
                "rule_id": query.rule_id,
                "occurred_from": _midnight(query.occurred_from) if query.occurred_from else None,
                "occurred_until": until,
                "until_inclusive": inclusive,
            },
            "cursor": list(cursor) if cursor else None,
            "limit": query.limit,
        }
    if method == "command_activity_analytics":
        query, as_of = args[0], kwargs["as_of"]
        start = as_of - timedelta(days=query.days - 1)
        return {
            "start": start.isoformat(),
            "end": as_of.isoformat(),
            "days": query.days,
            "top_limit": query.top_limit,
            "dimension": query.dimension,
            "dimension_value": query.dimension_value,
            "feedback_from": _midnight(start),
            "feedback_before": _midnight(as_of + timedelta(days=1)),
        }
    if method == "record_command_activity_feedback":
        return {
            "activity_id": kwargs["activity_id"],
            "label": kwargs["label"].value,
            "recorded_at": kwargs["recorded_at"].isoformat(),
            "schema_version": API_SCHEMA,
        }
    if method == "list_command_activity_invalidations":
        return {"cursor": args[0], "limit": kwargs.get("limit", 100)}
    if method == "clear_command_activity_evidence":
        return {}
    if method == "command_activity_diagnostics":
        extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        return {
            "harnesses": sorted(COMMAND_ACTIVITY_HARNESSES),
            "extension_ids": sorted({extension.extension_id for extension in extensions}),
            "rule_ids": sorted({rule.rule_id for extension in extensions for rule in extension.rules}),
            "proof_levels": [level.value for level in CommandProofLevel],
            "error_classes": ERROR_CLASSES,
        }
    if method == "list_command_shadow_observations":
        return {"limit": kwargs.get("limit", 10_000)}
    if method == "count_command_shadow_observations":
        return {}
    raise AssertionError(method)


def to_json(method: str, value: object) -> object:
    if method == "list_command_shadow_observations":
        return [shadow_wire(item) for item in value]  # type: ignore[attr-defined]
    return json.loads(json.dumps(value, default=list))


def native_payload(method: str, result: object) -> object:
    if isinstance(result, dict):
        return {key: item for key, item in result.items() if key not in {"schema_version", "schemas"}}
    return result


def run_scenario(scenario: dict, order: dict[str, str]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="command-activity-read-vectors-") as root:
        home = Path(root) / "guard-home"
        store = GuardStore(home, prime_policy_integrity=False)
        path = Path(store.path)
        if scenario["seed"]:
            connection = sqlite3.connect(path)
            for statement, params in seed_statements():
                connection.execute(statement, params)
            connection.commit()
            connection.close()
        previous = dump(path, order)
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
                method, args, kwargs = step["method"], step["args"], step["kwargs"]
                record.update(method=method, python_side=bool(step["python_side"]))
                record["wire_args"] = None if step["python_side"] else wire(method, args, kwargs)
                try:
                    result = to_json(method, getattr(store, method)(*args, **kwargs))
                    record.update(result=result, native_payload=native_payload(method, result), error=None)
                except (ValueError, RuntimeError, sqlite3.Error) as error:
                    record.update(
                        result=None, native_payload=None, error={"type": type(error).__name__, "message": str(error)}
                    )
            current = dump(path, order)
            record["post_changed"] = {t: rows for t, rows in current.items() if rows != previous[t]}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="command-activity-schema-") as root:
        probe = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        order = tracked_tables(Path(probe.path))
        schema = schema_sql(Path(probe.path))
    scenarios = [run_scenario(scenario, order) for scenario in SCENARIOS]
    document = {
        "schema": "guard-store-command-activity-read-vectors.v1",
        "source": "guard",
        "order_by": order,
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
