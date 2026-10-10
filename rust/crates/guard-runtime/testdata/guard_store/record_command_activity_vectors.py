#!/usr/bin/env python3
"""Record command-activity parity vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
of the command-activity store mixins, never against the branch under test and
never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario starts from a real `guard.db` created by the Python
`GuardStore` and replays steps through the Python store methods. The vectors
hold the command-activity schema, the initial singleton rows, and for every
step the method result (or error) plus the full post-step state of every
command-activity table. `wire_args` is the request the native transport must
send; it is translated here from the call, independently of the new code.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from datetime import date, datetime, timedelta
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from codex_plugin_scanner.guard.store_command_activity_rollups import (  # noqa: F401
        record_command_activity_rollups,
    )
except ImportError:
    sys.exit("refusing to record: the original Python rollup implementation is gone")

from command_activity_scenarios import SCENARIOS
from vector_support import dump, schema_sql, shadow_wire, tracked_tables

from codex_plugin_scanner.guard.runtime.command_activity_contract import CommandActivity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity_maintenance import (
    CommandActivityMaintenanceResult,
)

ACTIVITY_COLUMNS = [
    "activity_id",
    "occurred_at",
    "harness",
    "hook_phase",
    "execution_status",
    "proof_level",
    "policy_action",
    "decision_reason_code",
    "controlling_rule_id",
    "parse_confidence",
    "uncertainty_class",
    "match_count",
    "prompted",
    "approval_reuse_status",
    "receipt_link_status",
    "receipt_id",
    "evaluation_latency_bucket",
    "persistence_latency_bucket",
    "schema_version",
]


def _enum(value: object) -> object:
    return getattr(value, "value", value)


def handle_wire(handle: object) -> dict[str, str] | None:
    if handle is None:
        return None
    return {
        "kind": str(_enum(handle.kind)),  # type: ignore[attr-defined]
        "harness": handle.harness,  # type: ignore[attr-defined]
        "key_id": handle.key_id,  # type: ignore[attr-defined]
        "digest": handle.digest,  # type: ignore[attr-defined]
    }


def activity_wire(activity: CommandActivity) -> dict[str, object]:
    wire: dict[str, object] = {}
    for column in ACTIVITY_COLUMNS:
        value = getattr(activity, column)
        if column == "occurred_at":
            value = value.isoformat()
        elif column == "prompted":
            value = int(value)
        wire[column] = _enum(value)
    wire["request_correlation"] = handle_wire(activity.request_correlation)
    wire["session_correlation"] = handle_wire(activity.session_correlation)
    return wire


def evidence_wire(evidence: object) -> dict[str, object]:
    matches = []
    for match in evidence.matches:  # type: ignore[attr-defined]
        matches.append(
            {
                "activity_id": match.activity_id,
                "ordinal": match.ordinal,
                "extension_id": match.identity.extension_id,
                "extension_version": match.identity.extension_version,
                "rule_id": match.identity.rule_id,
                "rule_version": match.identity.rule_version,
                "match_class": match.match_class.value,
                "severity": match.severity.value,
                "default_floor": match.default_floor,
                "safe_variant_id": match.safe_variant_id,
                "schema_version": match.schema_version,
                "effects": sorted(effect.value for effect in match.effect_claims),
            }
        )
    return {"activity": activity_wire(evidence.activity), "matches": matches}  # type: ignore[attr-defined]


def _aggregate_cutoff(now: datetime) -> str:
    month_index = now.year * 12 + now.month - 1 - 12
    return date(month_index // 12, month_index % 12 + 1, 1).isoformat()


def wire(method: str, args: tuple, kwargs: dict) -> dict[str, object]:
    if method == "record_command_activity":
        preview = kwargs.get("invocation_preview")
        return {
            "evidence": evidence_wire(args[0]),
            "shadow": shadow_wire(kwargs.get("shadow")),
            "shadow_evaluation_succeeded": kwargs.get("shadow_evaluation_succeeded", False),
            "invocation_preview": preview.strip() if preview is not None else None,
        }
    if method == "probe_command_activity_persistence":
        return {
            "evidence": evidence_wire(args[0]),
            "shadow": shadow_wire(kwargs.get("shadow")),
            "shadow_evaluation_succeeded": kwargs.get("shadow_evaluation_succeeded", True),
        }
    if method == "transition_command_activity":
        return {"current": activity_wire(args[0])}
    if method == "get_command_activity_by_request_correlation":
        return {"correlation": handle_wire(args[0])}
    if method == "is_exact_command_activity_pre_replay":
        return {"evidence": evidence_wire(args[0])}
    if method == "record_command_activity_persistence_failure":
        return {"error_code": kwargs["error_code"], "occurred_at": kwargs["occurred_at"].isoformat()}
    if method == "record_command_activity_observation_conflict":
        return {"occurred_at": kwargs["occurred_at"].isoformat()}
    if method == "maintain_command_activity":
        now: datetime = kwargs["now"]
        return {
            "now": now.isoformat(),
            "today": now.date().isoformat(),
            "detail_cutoff": (now - timedelta(days=kwargs["detail_retain_days"])).isoformat(),
            "aggregate_cutoff": _aggregate_cutoff(now),
            "batch_size": kwargs.get("batch_size", 1000),
        }
    if method == "rebuild_command_activity_rollups":
        return {"now": kwargs["now"].isoformat()}
    if method == "command_activity_rollups_are_reconciled":
        return {}
    raise AssertionError(method)


def to_json(value: object) -> object:
    if isinstance(value, CommandActivity):
        return activity_wire(value)
    if isinstance(value, CommandActivityMaintenanceResult):
        return [
            value.ran,
            value.completed,
            value.backfilled_rows,
            value.detail_rows_deleted,
            value.correlation_rows_deleted,
            value.aggregate_rows_deleted,
        ]
    return value


def run_scenario(scenario: dict, order: dict[str, str]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="command-activity-vectors-") as root:
        home = Path(root) / "guard-home"
        store = GuardStore(home, prime_policy_integrity=False)
        path = Path(store.path)
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
                method, args, kwargs = step["method"], step.get("args", ()), step.get("kwargs", {})
                record.update(method=method, python_side=bool(step.get("python_side")))
                record["wire_args"] = None if step.get("python_side") else wire(method, args, kwargs)
                try:
                    result = getattr(store, method)(*args, **kwargs)
                    record.update(result=to_json(result), error=None)
                except (ValueError, RuntimeError, sqlite3.IntegrityError) as error:
                    record.update(result=None, error={"type": type(error).__name__, "message": str(error)})
            current = dump(path, order)
            record["post_changed"] = {t: rows for t, rows in current.items() if rows != previous[t]}
            previous = current
            steps.append(record)
        if "final_check" in scenario:
            scenario["final_check"](steps)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="command-activity-schema-") as root:
        probe = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        order = tracked_tables(Path(probe.path))
        schema = schema_sql(Path(probe.path))
    scenarios = [run_scenario(scenario, order) for scenario in SCENARIOS]
    document = {
        "schema": "guard-store-command-activity-vectors.v1",
        "source": "guard",
        "order_by": order,
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
