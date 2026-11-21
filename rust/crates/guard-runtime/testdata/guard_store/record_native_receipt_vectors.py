#!/usr/bin/env python3
"""Record native decision receipt write vectors from the Python implementation.

    cd <checkout>
    PYTHONPATH=$PWD/src python3 <this-file> <output native_receipt_vectors.json>

Each scenario records one or more ``record_native_decision_receipt`` calls on a
fresh database and the rows both receipt tables hold afterwards, or the error
the call raised. The receipt crosses the wire as JSON text in insertion order
with non-ASCII characters left alone, a different spelling from the sorted,
compact one the store writes into ``command_extensions_json``, so the resident
cannot pass by echoing what it was handed. ``recorded_at`` is pinned, since
Python takes it from the wall clock and the resident takes it from the request.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard.native_decision_receipt import (
    canonical_receipt_bytes,
    validate_native_decision_receipt,
)
from codex_plugin_scanner.guard.store_native_decision_receipts import (
    native_decision_receipt_schema_statements,
)

RECORDED_AT = "2026-03-01T12:00:00.123456+00:00"
TABLES = ("native_hook_decision_receipts", "native_prompt_decision_receipts")
DIGEST_A, DIGEST_B = "a" * 64, "b" * 64


COLUMNS = (
    "decision_id",
    "schema",
    "version",
    "authority",
    "request_id",
    "request_digest",
    "harness",
    "event_name",
    "payload_kind",
    "policy_generation",
    "policy_digest",
    "rule_digest",
    "runtime_identity",
    "decision",
    "model_output_action",
    "policy_action",
    "observed_policy_action",
    "reason_code",
    "workspace_bound",
    "source_ref_external_allowed",
    "reviewed_output_sha256",
    "observe_mode",
    "deadline_budget_ms",
    "command_extensions_json",
    "recorded_at",
)


def compact(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def flag(value: object) -> int:
    if not isinstance(value, bool):
        raise ValueError("native decision receipt boolean is invalid")
    return int(value)


def bound_values(receipt: Mapping[str, object]) -> tuple[object, ...]:
    """The bound values, in the order ``COLUMNS`` names them."""
    return (
        receipt["decision_id"],
        receipt["schema"],
        receipt["version"],
        receipt["authority"],
        receipt["request_id"],
        receipt["request_digest"],
        receipt["harness"],
        receipt["event_name"],
        receipt["payload_kind"],
        receipt["policy_generation"],
        receipt["policy_digest"],
        receipt["rule_digest"],
        receipt["runtime_identity"],
        receipt["decision"],
        receipt["model_output_action"],
        receipt["policy_action"],
        receipt["observed_policy_action"],
        receipt["reason_code"],
        flag(receipt["workspace_bound"]),
        flag(receipt["source_ref_external_allowed"]),
        receipt["reviewed_output_sha256"],
        flag(receipt["observe_mode"]),
        receipt["deadline_budget_ms"],
        compact(receipt["command_extensions"]) if "command_extensions" in receipt else None,
        RECORDED_AT,
    )


class _Store:
    """The Python write path these vectors pin, kept here as the reference.

    The shipping store now hands the receipt text to the resident, so the rows
    a vector expects have to come from an implementation that does not call the
    code under test.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def record_native_decision_receipt(self, receipt: Mapping[str, object]) -> None:
        validated = validate_native_decision_receipt(receipt)
        if validated is None:
            raise ValueError("native decision receipt is invalid")
        # The command binding is nested. Detach it before writing so a caller
        # cannot mutate that mapping after validation and change the stored
        # binding without changing the receipt identity.
        detached = validate_native_decision_receipt(json.loads(compact(validated)))
        if detached is None:
            raise ValueError("native decision receipt changed during capture")
        prompt = detached["event_name"] == "UserPromptSubmit"
        columns = COLUMNS + (("prompt_risk_classes_json",) if prompt else ())
        values = bound_values(detached) + ((compact(detached.get("prompt_risk_classes", [])),) if prompt else ())
        table = "native_prompt_decision_receipts" if prompt else "native_hook_decision_receipts"
        connection = sqlite3.connect(self._path)
        try:
            connection.execute(
                f"insert or ignore into {table} ({', '.join(columns)}) values ({', '.join('?' * len(columns))})",
                values,
            )
            connection.commit()
        finally:
            connection.close()


def binding(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "guard.native-command-receipt-binding.v1",
        "program_digest": DIGEST_A,
        "catalog_digest": DIGEST_B,
        "trust_digest": "c" * 64,
        "control_revision": 4,
        "managed_control_revision": 0,
        "control_effective_digest": "d" * 64,
        "observations_digest": "e" * 64,
        "observation_count": 2,
        "uncertainty_count": 0,
    }
    value.update(overrides)
    return value


def receipt(**overrides: object) -> dict[str, object]:
    """One receipt with its content-bound decision ID recomputed."""
    value: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "req.1",
        "request_digest": DIGEST_A,
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 7,
        "policy_digest": DIGEST_B,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_allow",
        "workspace_bound": True,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 750,
    }
    for key, item in overrides.items():
        if item is None and key in {"command_extensions", "prompt_risk_classes"}:
            value.pop(key, None)
            continue
        value[key] = item
    value["decision_id"] = hashlib.sha256(canonical_receipt_bytes(value)).hexdigest()
    return value


def prompt_receipt(**overrides: object) -> dict[str, object]:
    return receipt(
        event_name="UserPromptSubmit",
        model_output_action="not_applicable",
        reason_code="native_prompt_review",
        **overrides,
    )


SCENARIOS: list[dict[str, object]] = [
    {"name": "pre_tool_minimal", "receipts": [receipt()]},
    {
        "name": "post_tool_every_optional_field",
        "receipts": [
            receipt(
                event_name="PostToolUse",
                decision="deny",
                model_output_action="block",
                policy_action="block",
                observed_policy_action="review",
                rule_digest="f" * 64,
                runtime_identity="1" * 64,
                reviewed_output_sha256="2" * 64,
                observe_mode=True,
                command_extensions=binding(),
                origin_authentication="3" * 64,
                execution_intent_digest="4" * 64,
                review_anchor_digest="5" * 64,
                business_review_binding="6" * 64,
            )
        ],
    },
    {
        "name": "prompt_with_risk_classes",
        "receipts": [prompt_receipt(prompt_risk_classes=["local_env_read", "exfil_intent", "guard_bypass_intent"])],
    },
    {"name": "prompt_without_risk_classes", "receipts": [prompt_receipt()]},
    {
        "name": "both_tables_in_one_database",
        "receipts": [receipt(), prompt_receipt(), receipt(event_name="PostToolUse")],
    },
    {"name": "repeated_receipt_is_ignored", "receipts": [receipt(), receipt()]},
    {
        "name": "payload_kind_keeps_its_own_row",
        "receipts": [receipt(), receipt(payload_kind="source_file_ref")],
    },
    {
        "name": "unbound_deadline_and_no_policy_digest",
        "receipts": [receipt(deadline_budget_ms=None, policy_digest=None)],
    },
    {
        "name": "decision_id_does_not_match_the_body",
        "receipts": [{**receipt(), "decision_id": "7" * 64}],
        "expect_error": True,
    },
    {
        "name": "unknown_field",
        "receipts": [{**receipt(), "unexpected": "value"}],
        "expect_error": True,
    },
    {
        "name": "binding_digest_is_not_hex",
        "receipts": [receipt(command_extensions=binding(trust_digest="not-hex"))],
        "expect_error": True,
    },
    {
        "name": "prompt_risk_classes_out_of_order",
        "receipts": [prompt_receipt(prompt_risk_classes=["exfil_intent", "local_env_read"])],
        "expect_error": True,
    },
]


def build_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        "create table if not exists schema_migrations (version integer primary key, applied_at text not null)"
    )
    for statement in native_decision_receipt_schema_statements():
        connection.executescript(statement)
    connection.commit()


def dump(path: Path) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return {
            table: [dict(row) for row in connection.execute(f"select * from {table} order by decision_id")]
            for table in TABLES
        }
    finally:
        connection.close()


def wire(value: Mapping[str, object]) -> str:
    return json.dumps(value, ensure_ascii=False)


def record(scenario: Mapping[str, object]) -> dict[str, object]:
    receipts = scenario["receipts"]
    assert isinstance(receipts, list)
    with tempfile.TemporaryDirectory(prefix="guard-native-receipt-") as root:
        path = Path(root) / "guard.db"
        connection = sqlite3.connect(path)
        try:
            build_schema(connection)
        finally:
            connection.close()
        store = _Store(path)
        error: str | None = None
        for item in receipts:
            try:
                store.record_native_decision_receipt(item)
            except ValueError as failure:
                error = str(failure)
                break
        after = dump(path)
    if bool(scenario.get("expect_error")) != (error is not None):
        sys.exit(f"{scenario['name']}: expected error {scenario.get('expect_error')}, got {error!r}")
    return {
        "name": scenario["name"],
        "receipt_texts": [wire(item) for item in receipts],
        "error": error,
        "after": after,
    }


def schema_sql() -> list[str]:
    with tempfile.TemporaryDirectory(prefix="guard-native-receipt-schema-") as root:
        path = Path(root) / "guard.db"
        connection = sqlite3.connect(path)
        try:
            build_schema(connection)
            return [
                str(row[0])
                for row in connection.execute(
                    f"select sql from sqlite_master where tbl_name in {TABLES} and sql is not null order by rowid"
                )
            ]
        finally:
            connection.close()


def main(output: Path) -> None:
    document = {
        "schema": "guard-store-native-receipt-vectors.v1",
        "recorded_at": RECORDED_AT,
        "schema_sql": schema_sql(),
        "scenarios": [record(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: record_native_receipt_vectors.py <output.json>")
    main(Path(sys.argv[1]))
