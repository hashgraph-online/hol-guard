#!/usr/bin/env python3
"""Record approval queue write vectors from the Python implementation.

Run against a checkout whose `store_approval_writes.py` still holds the
Python write, with a native runtime for the canonical surfaces and queue
identity the write asks the resident for:

    cd <origin-main-worktree>
    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario seeds `approval_requests` (and, for the OAuth binding, the
credential state and device rows), then writes one request through
`GuardStore.add_approval_request`. Per scenario the vectors hold the
returned request id or the raised error, and the resulting
`approval_requests` and `guard_review_outbox_events` rows. Scenarios flagged
`native_defers` seed legacy rows the daemon backfills first; the resident
answers `null` for them and writes nothing.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

if os.environ.get("HOL_GUARD_NATIVE") != "force" or not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("refusing to record: set HOL_GUARD_NATIVE=force and HOL_GUARD_NATIVE_BINARY")

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-03-01T12:00:00+00:00"
LATER = "2026-03-01T12:05:00+00:00"
SOURCE = "guard"
GROUP = "qg-seeded"
TABLES = {
    "approval_requests": "request_id",
    "guard_review_outbox_events": "stream_sequence",
}


def request(request_id: str, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "request_id": request_id,
        "harness": "codex",
        "artifact_id": "native-review:codex:cmd",
        "artifact_name": "Bash",
        "artifact_hash": "native-review-v4:" + "a" * 64,
        "policy_action": "require-reapproval",
        "recommended_scope": "once",
        "changed_fields": ["command"],
        "source_scope": "workspace",
        "config_path": "/cfg/config.toml",
        "review_command": f"hol-guard approvals approve {request_id}",
        "approval_url": f"http://127.0.0.1:4781/approvals/{request_id}",
        "workspace": "/work/space",
        "artifact_type": "native_review",
        "launch_target": "rm -rf build",
        "risk_summary": "Deletes files",
        "risk_signals": ["destructive", "filesystem"],
        "artifact_label": "Bash command",
        "trigger_summary": "PreToolUse",
        "guard_version": "3.42.0",
    }
    base.update(overrides)
    return base


def row(request_id: str, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "request_id": request_id,
        "harness": "codex",
        "artifact_id": "native-review:codex:cmd",
        "artifact_name": "Bash",
        "artifact_type": "native_review",
        "artifact_hash": "native-review-v4:" + "a" * 64,
        "policy_action": "require-reapproval",
        "recommended_scope": "once",
        "changed_fields_json": "[]",
        "source_scope": "workspace",
        "oauth_source": SOURCE,
        "config_path": "/cfg/config.toml",
        "workspace": "/work/space",
        "launch_target": "rm -rf build",
        "normalized_identity_key": "rm -rf build",
        "action_identity": "seeded-identity",
        "queue_group_id": GROUP,
        "dedupe_count": 1,
        "last_seen_at": "2026-03-01T11:00:00+00:00",
        "review_command": f"hol-guard approvals approve {request_id}",
        "approval_url": f"http://127.0.0.1:4781/approvals/{request_id}",
        "status": "pending",
        "created_at": "2026-03-01T11:00:00+00:00",
        "guard_version": "3.41.0",
        "first_seen_guard_version": "3.40.0",
        "last_seen_guard_version": "3.41.0",
    }
    base.update(overrides)
    return base


BINDING_SEED = {
    "sync_state": [
        {
            "state_key": f"oauth_local_credentials:{SOURCE}",
            "payload_json": json.dumps(
                {"grant_id": "grant-1", "workspace_id": "ws-1", "machine_id": "machine-1"}, sort_keys=True
            ),
            "updated_at": NOW,
        }
    ],
    "guard_devices": [
        {
            "device_key": "local-device",
            "installation_id": "install-1",
            "device_label": "Test device",
            "created_at": NOW,
            "updated_at": NOW,
        }
    ],
}
CONTRADICTED = json.dumps({"policy_action": "allow"})
SNAPSHOT = {
    "capability": "session-resume",
    "correlationId": "gcr_0123abcd-0000-4000-8000-00000000abcd",
    "hookAttached": False,
    "opaqueTargetId": "target-1",
    "waitDeadline": None,
}
# A retry-only snapshot may not carry a target: invalid, so the write freezes a
# non-resumable one that still keeps its correlation.
INVALID_SNAPSHOT = {**SNAPSHOT, "capability": "retry-only"}

SCENARIOS: list[dict[str, object]] = [
    {"name": "fresh_insert", "request": request("r-new")},
    {
        "name": "fresh_insert_full_fields",
        "request": request(
            "r-new",
            transport="stdio",
            publisher="acme",
            source_label="Codex",
            why_now="first run",
            launch_summary="runs rm",
            risk_headline="Deletes build",
            decision_v2_json={"action": "ask", "guard_action": "require-reapproval", "reason": "destructive é"},
            action_envelope_json={"action_type": "shell", "policy_action": "require-reapproval"},
            fallback_cli_command="hol-guard approvals approve r-new",
            dedupe_count=0,
            last_seen_at="2026-03-01T11:59:00+00:00",
            scanner_evidence=[{"source": "observe_mode_inbox", "b": 2, "a": 1}],
            browser_intent={"z": 1, "a": "x"},
            raw_command_text="rm -rf build",
            first_seen_guard_version="3.39.0",
            extension_allow_hint={"kind": "tool", "allow": True},
            continuation_snapshot=INVALID_SNAPSHOT,
        ),
    },
    {
        "name": "fresh_insert_correlation_from_decision",
        "request": request(
            "r-new",
            harness=" Claude-Code ",
            decision_v2_json={"correlationId": " gcr_feedface-1111-4222-8333-444455556666 "},
        ),
    },
    {
        "name": "fresh_insert_unshaped_correlation_ignored",
        "request": request("r-new", harness="cursor", decision_v2_json={"correlationId": "corr-not-shaped"}),
    },
    {"name": "fresh_insert_frozen_snapshot", "request": request("r-new", continuation_snapshot=SNAPSHOT)},
    {"name": "fresh_insert_no_workspace", "request": request("r-new", workspace=None, launch_target=None)},
    {"name": "fresh_insert_blank_guard_version", "request": request("r-new", guard_version=None)},
    {
        "name": "dedupe_on_queue_group",
        "rows": [row("r-old")],
        "request": request("r-new", queue_group_id=GROUP, fallback_cli_command="hol-guard approvals approve r-new"),
    },
    {
        "name": "dedupe_keeps_frozen_correlation",
        "rows": [row("r-old", continuation_snapshot_json=json.dumps(SNAPSHOT, sort_keys=True, separators=(",", ":")))],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "dedupe_frozen_correlation_overrides_request_snapshot",
        "rows": [row("r-old", continuation_snapshot_json=json.dumps(SNAPSHOT, sort_keys=True, separators=(",", ":")))],
        "request": request(
            "r-new",
            queue_group_id=GROUP,
            continuation_snapshot={**SNAPSHOT, "correlationId": "gcr_feedface-1111-4222-8333-444455556666"},
        ),
    },
    {
        "name": "dedupe_watch_only_stays_when_both",
        "rows": [row("r-old", watch_only_observation=1)],
        "request": request("r-new", queue_group_id=GROUP, scanner_evidence=[{"source": "observe_mode_inbox"}]),
    },
    {
        "name": "dedupe_watch_only_cleared",
        "rows": [row("r-old", watch_only_observation=1)],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "dedupe_newest_of_group",
        "rows": [
            row("r-a", last_seen_at="2026-03-01T11:00:00+00:00"),
            row("r-b", last_seen_at="2026-03-01T11:30:00+00:00"),
        ],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "group_ignores_other_source",
        "rows": [row("r-old", oauth_source="other")],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "group_ignores_resolved",
        "rows": [row("r-old", status="resolved", resolution_action="allow", resolution_scope="once", resolved_at=NOW)],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "inconsistent_group_row_expired",
        "rows": [row("r-old", action_envelope_json=CONTRADICTED)],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "inconsistent_older_row_expired_newer_wins",
        "rows": [
            row("r-a", last_seen_at="2026-03-01T11:00:00+00:00", action_envelope_json=CONTRADICTED),
            row("r-b", last_seen_at="2026-03-01T11:30:00+00:00"),
        ],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "unparseable_group_row_expired",
        "rows": [row("r-old", decision_v2_json="{not json")],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "non_object_envelope_row_expired",
        "rows": [row("r-old", action_envelope_json="[1]")],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "same_id_inconsistent_requires_fresh",
        "rows": [row("r-old", action_envelope_json=CONTRADICTED)],
        "request": request("r-old", queue_group_id=GROUP),
    },
    {
        "name": "same_id_consistent_updates",
        "rows": [row("r-old")],
        "request": request("r-old", queue_group_id=GROUP),
    },
    {
        "name": "contradicted_request_rejected",
        "request": request("r-new", action_envelope_json={"policy_action": "allow"}),
    },
    {
        "name": "binds_first_event_to_oauth",
        "seed": BINDING_SEED,
        "request": request("r-new"),
    },
    {
        "name": "binding_on_dedupe",
        "seed": BINDING_SEED,
        "rows": [row("r-old")],
        "request": request("r-new", queue_group_id=GROUP),
    },
    {
        "name": "legacy_row_defers",
        "native_defers": True,
        "rows": [row("r-legacy", action_identity=None, queue_group_id=None)],
        "request": request("r-new"),
    },
    {
        "name": "legacy_dedupe_count_defers",
        "native_defers": True,
        "rows": [row("r-legacy", dedupe_count=0)],
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


def insert(path: Path, table: str, rows: list[dict[str, object]]) -> None:
    connection = sqlite3.connect(path)
    try:
        for item in rows:
            columns = ",".join(item)
            marks = ",".join("?" * len(item))
            connection.execute(f"insert or replace into {table} ({columns}) values ({marks})", tuple(item.values()))
        connection.commit()
    finally:
        connection.close()


def build(fields: dict[str, object]) -> GuardApprovalRequest:
    values = dict(fields)
    for key in ("changed_fields", "risk_signals", "scanner_evidence"):
        if key in values:
            values[key] = tuple(values[key])  # type: ignore[arg-type]
    return GuardApprovalRequest(**values)  # type: ignore[arg-type]


def run(scenario: dict[str, object]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="approval-write-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE)
        path = Path(store.path)
        seed = dict(scenario.get("seed", {}))  # type: ignore[arg-type]
        for table, rows in seed.items():
            insert(path, table, rows)
        insert(path, "approval_requests", scenario.get("rows", []))  # type: ignore[arg-type]
        before = dump(path)
        fields = scenario["request"]  # type: ignore[assignment]
        try:
            outcome: dict[str, object] = {"result": store.add_approval_request(build(fields), NOW)}
        except ValueError as error:
            outcome = {"error": str(error)}
        return {
            "name": scenario["name"],
            "native_defers": bool(scenario.get("native_defers")),
            "seed": seed,
            "rows": scenario.get("rows", []),
            "request": build(fields).to_dict(),
            "now": NOW,
            **outcome,
            "before": before,
            "after": dump(path),
        }


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="approval-write-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False, source=SOURCE).path)
        connection = sqlite3.connect(path)
        schema = [
            item[0]
            for item in connection.execute(
                "select sql from sqlite_master where sql is not null and name not like 'sqlite_%' order by rowid"
            )
        ]
        connection.close()
    document = {
        "schema": "guard-store-approval-request-write-vectors.v1",
        "source": SOURCE,
        "schema_sql": schema,
        "scenarios": [run(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
