#!/usr/bin/env python3
"""Record silent native review vectors from the Python implementation.

The safe-alternative branch of `pause_native_pre_tool_for_approval` queues the
review (`GuardStore.add_approval_request`), reads the queued row back
(`GuardStore.get_approval_request`, which derives the scope contract) and
writes its `approval.created` event (`_record_silent_native_review_event`).
Run with a native runtime for the surfaces, queue identity and scope contract
those calls ask the resident for:

    cd <checkout>
    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output silent_review_vectors.json>

Per scenario the vectors hold the queued request id (or the raised error), the
fields the event reads from the queued row, and the resulting
`approval_requests`, `guard_review_outbox_events` and `guard_events` rows.
Scenarios flagged `native_defers` seed legacy rows the daemon backfills first;
the resident answers `null` for them and writes nothing.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from record_approval_request_write_vectors import GROUP, NOW, SOURCE, build, insert, request, row

from codex_plugin_scanner.guard.daemon import hook_native_review_approval
from codex_plugin_scanner.guard.store import GuardStore

PINNED_CLOCK = "2026-03-01T13:00:00.654321+00:00"
TABLES = {
    "approval_requests": "request_id",
    "guard_review_outbox_events": "stream_sequence",
    "guard_events": "event_id",
}
EVENT_FIELDS = (
    "request_id",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "policy_action",
    "recommended_scope",
    "source_scope",
    "workspace",
    "publisher",
    "created_at",
)
TOOL_ACTION = {
    "artifact_id": "codex:tool:tool-action:bash",
    "artifact_type": "tool_action_request",
    "artifact_hash": "tool-action-hash-1",
    "policy_action": "review",
    "raw_command_text": "rm -rf build",
}
NATIVE_TOOL_CALL = {
    "artifact_id": "codex:native-pretool:Bash",
    "artifact_type": "tool_call",
    "policy_action": "review",
    "recommended_scope": "artifact",
    "source_scope": "project",
    "config_path": "/work/space",
    "raw_command_text": "rm -rf build",
    "changed_fields": ["native_pre_tool"],
}


class _PinnedDatetime(datetime):
    @classmethod
    def now(cls, tz: object = None) -> datetime:  # type: ignore[override]
        return datetime.fromisoformat(PINNED_CLOCK)


SCENARIOS: list[dict[str, object]] = [
    {"name": "fresh_native_tool_call", "request": request("r-new", **NATIVE_TOOL_CALL)},
    {"name": "fresh_native_review", "request": request("r-new")},
    {
        "name": "fresh_unicode_publisher",
        "request": request("r-new", artifact_name="Bash café — 日本 \U0001f512", publisher="acme ✓"),
    },
    {"name": "fresh_no_workspace", "request": request("r-new", workspace=None, source_scope="harness")},
    {"name": "scope_workspace_recommended", "request": request("r-new", **TOOL_ACTION)},
    {
        "name": "scope_workspace_from_config_path",
        "request": request(
            "r-new", workspace=None, launch_target=None, config_path="/cfg/.codex/config.toml", **TOOL_ACTION
        ),
    },
    {
        "name": "scope_unknown_hash_artifact_only",
        "request": request("r-new", **{**TOOL_ACTION, "artifact_hash": "unknown"}),
    },
    {
        "name": "scope_guard_control_approvable",
        "request": request("r-new", policy_action="review", action_envelope_json={"action_type": "guard_control"}),
    },
    {"name": "scope_block_not_overridable", "request": request("r-new", policy_action="block")},
    {
        "name": "dedupe_keeps_stored_fields",
        "rows": [
            row(
                "r-old",
                artifact_name="OldBash",
                publisher="old-publisher",
                recommended_scope="workspace",
                source_scope="harness",
                created_at="2026-03-01T10:00:00+00:00",
            )
        ],
        "request": request("r-new", queue_group_id=GROUP, publisher="new-publisher", artifact_name="NewBash"),
    },
    {
        "name": "dedupe_tool_action_row",
        "rows": [
            row(
                "r-old",
                **{**TOOL_ACTION, "policy_action": "review"},
                publisher=None,
                created_at="2026-03-01T09:30:00+00:00",
            )
        ],
        "request": request("r-new", queue_group_id=GROUP, **TOOL_ACTION),
    },
    {
        "name": "contradicted_request_rejected",
        "request": request("r-new", action_envelope_json={"policy_action": "allow"}),
    },
    {
        "name": "legacy_row_defers",
        "native_defers": True,
        "rows": [row("r-legacy", action_identity=None, queue_group_id=None)],
        "request": request("r-new"),
    },
]


def dump(path: Path) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return {
            table: [dict(item) for item in connection.execute(f"select * from {table} order by {order}")]
            for table, order in TABLES.items()
        }
    finally:
        connection.close()


def queue_silently(store: GuardStore, fields: dict[str, object]) -> dict[str, object]:
    """The daemon's persist, lookup and event write for a silent review."""

    persisted_id = store.add_approval_request(build(fields), NOW)
    queued = store.get_approval_request(persisted_id)
    if not isinstance(queued, dict):
        sys.exit(f"queued request {persisted_id} did not read back")
    hook_native_review_approval._record_silent_native_review_event(store, queued)
    return {"result": persisted_id, "queued": {field: queued.get(field) for field in EVENT_FIELDS}}


def run(scenario: dict[str, object]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="silent-review-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE)
        path = Path(store.path)
        insert(path, "approval_requests", scenario.get("rows", []))  # type: ignore[arg-type]
        before = dump(path)
        fields = scenario["request"]  # type: ignore[assignment]
        try:
            outcome = queue_silently(store, fields)  # type: ignore[arg-type]
        except ValueError as error:
            outcome = {"error": str(error)}
        return {
            "name": scenario["name"],
            "native_defers": bool(scenario.get("native_defers")),
            "rows": scenario.get("rows", []),
            "request": build(fields).to_dict(),  # type: ignore[arg-type]
            "now": NOW,
            **outcome,
            "before": before,
            "after": dump(path),
        }


def main(output: Path) -> None:
    original = hook_native_review_approval.datetime
    hook_native_review_approval.datetime = _PinnedDatetime  # type: ignore[misc]
    try:
        with tempfile.TemporaryDirectory(prefix="silent-review-schema-") as root:
            path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE).path)
            connection = sqlite3.connect(path)
            schema = [
                item[0]
                for item in connection.execute(
                    "select sql from sqlite_master where sql is not null and name not like 'sqlite_%' order by rowid"
                )
            ]
            connection.close()
        scenarios = [run(scenario) for scenario in SCENARIOS]
    finally:
        hook_native_review_approval.datetime = original  # type: ignore[misc]
    document = {
        "schema": "guard-store-silent-review-vectors.v1",
        "source": SOURCE,
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
