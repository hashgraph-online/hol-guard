#!/usr/bin/env python3
"""Record Guard event write vectors from the Python implementation.

    cd <checkout>
    PYTHONPATH=$PWD/src python3 <this-file> <output guard_event_vectors.json>

Three groups, all produced by the real Python code:

* ``add_event``: each scenario writes its events in order through
  ``GuardStore.add_event`` on a fresh home and records the resulting
  ``guard_events`` and ``sqlite_sequence`` rows (or the raised error). Every
  other table's row count is checked unchanged, so the write has no outbox or
  cloud-queue side effect. The resident receives each payload as
  order-preserving JSON text in a different spelling from the stored one.
* ``approval_created``: ``_record_silent_native_review_event`` writes the
  ``approval.created`` event for a queued request, with its clock pinned for
  the missing ``created_at`` fallback.
* ``safe_alternative_reason``: inputs and the text the formatter returns.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from codex_plugin_scanner.guard.blocked_request_mode import safe_alternative_reason
from codex_plugin_scanner.guard.daemon import hook_native_review_approval
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-03-01T12:00:00+00:00"
LATER = "2026-03-01T12:05:00.123456+00:00"
PINNED_CLOCK = "2026-03-01T13:00:00.654321+00:00"
SOURCES = ("guard", "Cloud-Sync")
UNICODE = 'caf\u00e9 \u2014 \u65e5\u672c \U0001f512 \u0007\u001f\t\n\r"\\/ \u2028\ufeff'


class _PinnedDatetime(datetime):
    @classmethod
    def now(cls, tz: object = None) -> datetime:  # type: ignore[override]
        return datetime.fromisoformat(PINNED_CLOCK)


def event(name: str, payload: dict[str, object], now: str = NOW) -> dict[str, object]:
    return {"event_name": name, "payload": payload, "now": now}


ADD_EVENT_SCENARIOS: list[dict[str, object]] = [
    {"name": "empty_payload", "events": [event("approval.created", {})]},
    {
        "name": "scalar_values",
        "events": [
            event(
                "approval.created",
                {"z": None, "a": "text", "m": 7, "neg": -12, "t": True, "f": False, "empty": ""},
            )
        ],
    },
    {
        "name": "floats",
        "events": [
            event(
                "metric",
                {
                    "half": 0.5,
                    "whole": 2.0,
                    "tiny": 1e-07,
                    "big": 1e16,
                    "neg_zero": -0.0,
                    "pi": 3.141592653589793,
                    "nan": float("nan"),
                    "inf": float("inf"),
                    "ninf": float("-inf"),
                },
            )
        ],
    },
    {
        "name": "large_integer",
        "events": [event("metric", {"n": 10**40, "m": -(10**30)})],
    },
    {
        "name": "unicode_values_and_keys",
        "events": [event("approval.created", {UNICODE: UNICODE, "plain": "\u00e9\U0001f600"})],
    },
    {"name": "unicode_event_name", "events": [event("evt.\u00e9\U0001f512", {"k": "v"})]},
    {"name": "empty_event_name", "events": [event("", {"k": "v"})]},
    {
        "name": "nested_insertion_order",
        "events": [
            event(
                "policy.cloud.applied",
                {
                    "zeta": {"b": 1, "a": [3, {"y": None, "x": "\u00e9"}], "c": {}},
                    "alpha": [],
                    "mid": [[], [1, 2.5, "s"], {"q": False}],
                },
            )
        ],
    },
    {
        "name": "repeated_events",
        "events": [
            event("approval.created", {"request_id": "r-1"}),
            event("approval.created", {"request_id": "r-1"}),
            event("approval.resolved", {"request_id": "r-1"}, LATER),
        ],
    },
    {"name": "arbitrary_now_text", "events": [event("x", {"k": 1}, "not-a-timestamp \u00e9")]},
]

_MISSING = object()

QUEUED_BASE: dict[str, object] = {
    "request_id": "req-1",
    "harness": "codex",
    "artifact_id": "native-review:codex:cmd",
    "artifact_name": "Bash",
    "artifact_type": "native_review",
    "policy_action": "require-reapproval",
    "recommended_scope": "once",
    "source_scope": "workspace",
    "workspace": "/work/space",
    "publisher": None,
    "created_at": NOW,
    "status": "pending",
    "launch_target": "rm -rf build",
}


def queued(**overrides: object) -> dict[str, object]:
    base = dict(QUEUED_BASE)
    for key, value in overrides.items():
        if value is _MISSING:
            base.pop(key, None)
        else:
            base[key] = value
    return base


APPROVAL_CREATED_SCENARIOS: list[dict[str, object]] = [
    {"name": "stored_request", "queued": queued()},
    {"name": "publisher_and_unicode", "queued": queued(publisher="acme \u00e9", artifact_name=UNICODE)},
    {"name": "missing_fields", "queued": {"request_id": "req-2", "created_at": LATER}},
    {"name": "integer_and_bool_values", "queued": queued(workspace=12, publisher=True)},
    {"name": "list_value", "queued": queued(publisher=["a", 1, None])},
    {"name": "float_value", "queued": queued(publisher=1.5)},
    {"name": "created_at_missing", "queued": queued(created_at=_MISSING)},
    {"name": "created_at_empty", "queued": queued(created_at="")},
    {"name": "created_at_not_text", "queued": queued(created_at=5)},
    {"name": "created_at_none", "queued": queued(created_at=None)},
    {"name": "object_value", "queued": queued(publisher={"b": 1, "a": 2}), "native_defers": True},
]

REASONS = [
    "HOL Guard blocked this action.",
    "",
    "   ",
    "\u3000\u2003 padded \u00e9 \t\n",
    "\x1c\x1d\x1e\x1f inner  spaces \x85",
    "\U0001f512 locked",
]
REASON_CODES: list[str | None] = [
    None,
    "",
    "unknown",
    "native_destructive_command",
    "native_package_review",
    "native_network_review",
    "native_file_read_review",
    "native_pre_tool_unknown_review",
    "native_command_review_required",
]
QUEUED_FLAGS: list[bool | None] = [None, True, False]


def table_counts(connection: sqlite3.Connection) -> dict[str, int]:
    names = [
        str(row[0])
        for row in connection.execute(
            "select name from sqlite_master where type = 'table' and name not like 'sqlite_%' order by name"
        )
    ]
    return {name: int(connection.execute(f'select count(*) from "{name}"').fetchone()[0]) for name in names}


def dump(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        events = [dict(row) for row in connection.execute("select * from guard_events order by event_id")]
        sequence = [
            dict(row) for row in connection.execute("select name, seq from sqlite_sequence where name = 'guard_events'")
        ]
        return {"guard_events": events, "sqlite_sequence": sequence}
    finally:
        connection.close()


def counts_without_events(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(path)
    try:
        counts = table_counts(connection)
    finally:
        connection.close()
    counts.pop("guard_events", None)
    return counts


def fresh_store(root: Path, source: str) -> GuardStore:
    return GuardStore(root / "guard-home", prime_policy_integrity=False, source=source)


def record_add_event(scenario: dict[str, object], source: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-event-") as root:
        store = fresh_store(Path(root), source)
        path = Path(store.path)
        before = counts_without_events(path)
        events = scenario["events"]
        assert isinstance(events, list)
        for item in events:
            store.add_event(str(item["event_name"]), item["payload"], str(item["now"]))
        if counts_without_events(path) != before:
            sys.exit(f"{scenario['name']}: add_event touched another table")
        recorded = dump(path)
    wire_events = [
        {
            "event_name": item["event_name"],
            "payload_text": json.dumps(item["payload"], ensure_ascii=False, separators=(",", ":")),
            "now": item["now"],
        }
        for item in events
    ]
    return {"name": scenario["name"], "source": source, "events": wire_events, "after": recorded}


def record_digit_limit() -> dict[str, object]:
    digits = 4301
    with tempfile.TemporaryDirectory(prefix="guard-event-digits-") as root:
        store = fresh_store(Path(root), SOURCES[0])
        try:
            store.add_event("metric", {"n": int("9" * digits)}, NOW)
        except ValueError:
            error = "ValueError"
        else:
            sys.exit("expected json.dumps to refuse an integer past the digit limit")
        recorded = dump(Path(store.path))
    return {"int_digits": digits, "error": error, "after": recorded}


def record_approval_created(scenario: dict[str, object]) -> dict[str, object]:
    original = hook_native_review_approval.datetime
    hook_native_review_approval.datetime = _PinnedDatetime  # type: ignore[misc]
    try:
        with tempfile.TemporaryDirectory(prefix="guard-event-approval-") as root:
            store = fresh_store(Path(root), SOURCES[0])
            hook_native_review_approval._record_silent_native_review_event(store, scenario["queued"])
            recorded = dump(Path(store.path))
    finally:
        hook_native_review_approval.datetime = original  # type: ignore[misc]
    return {
        "name": scenario["name"],
        "queued_text": json.dumps(scenario["queued"]),
        "native_defers": bool(scenario.get("native_defers")),
        "after": recorded,
    }


def record_reasons() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for reason in REASONS:
        for code in REASON_CODES:
            for flag in QUEUED_FLAGS:
                text = safe_alternative_reason(reason, reason_code=code, approval_queued=flag)
                out.append({"reason": reason, "reason_code": code, "approval_queued": flag, "text": text})
    return out


def schema_sql() -> list[str]:
    with tempfile.TemporaryDirectory(prefix="guard-event-schema-") as root:
        path = Path(fresh_store(Path(root), SOURCES[0]).path)
        connection = sqlite3.connect(path)
        try:
            return [
                str(row[0])
                for row in connection.execute(
                    "select sql from sqlite_master where tbl_name = 'guard_events' and sql is not null order by rowid"
                )
            ]
        finally:
            connection.close()


def main(output: Path) -> None:
    add_event = [record_add_event(scenario, source) for scenario in ADD_EVENT_SCENARIOS for source in SOURCES]
    names = {(item["name"], json.dumps(item["after"], sort_keys=True)) for item in add_event}
    if len(names) != len(ADD_EVENT_SCENARIOS):
        sys.exit("the store source changed an add_event row")
    document = {
        "schema": "guard-store-guard-event-vectors.v1",
        "pinned_clock": PINNED_CLOCK,
        "schema_sql": schema_sql(),
        "add_event": add_event,
        "add_event_digit_limit": record_digit_limit(),
        "approval_created": [record_approval_created(scenario) for scenario in APPROVAL_CREATED_SCENARIOS],
        "safe_alternative_reason": record_reasons(),
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: record_guard_event_vectors.py <output.json>")
    main(Path(sys.argv[1]))
