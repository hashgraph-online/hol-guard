"""Scenarios for the guard sessions/operations/attachments parity vectors.

Shared by the recorder (which runs them through the ORIGINAL Python store) and
the Python parity test (which replays them through the new wrappers). Steps are
either `{"sql": [(statement, params), ...]}` or `{"method", "args", "kwargs"}`.
"""

from __future__ import annotations

import json

from codex_plugin_scanner.guard.retry_lineage import capture_retry_lineage

T1 = "2026-07-18T20:00:00+00:00"
T2 = "2026-07-18T20:05:00+00:00"
T3 = "2026-07-18T20:10:00+00:00"
FUTURE = "2099-01-01T00:00:00+00:00"
PAST = "2000-01-01T00:00:00+00:00"
#: The clock the vectors assume. Recorded outcomes hold for any instant between
#: `PAST` and `FUTURE`; the Python test pins the wrapper clock to this value.
NOW = "2026-10-10T12:00:00+00:00"

LINEAGE = capture_retry_lineage(
    {"session_id": "provider-session", "tool_call_id": "call-1", "cwd": "/work/space"},
    harness="codex",
    original_request_id="req-orig",
)
assert LINEAGE is not None
TAMPERED_LINEAGE = {**LINEAGE, "harness": "claude-code"}


def session(session_id: str, now: str, **overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "session_id": session_id,
        "harness": "codex",
        "surface": "cli",
        "status": "started",
        "client_name": "guard-cli",
        "client_title": "Guard CLI",
        "client_version": "1.2.3",
        "workspace": "/work/space",
        "capabilities": ["approvals", "resume"],
        "now": now,
    }
    kwargs.update(overrides)
    return {"method": "upsert_guard_session", "kwargs": kwargs}


def operation(operation_id: str, now: str, **overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "operation_id": operation_id,
        "session_id": "s1",
        "harness": "codex",
        "operation_type": "approval",
        "status": "pending",
        "approval_request_ids": ["req-1", "req-12"],
        "resume_token": None,
        "metadata": {"note": "café", "nested": {"n": 1, "ok": True}, "items": [1, 2.5, None]},
        "now": now,
    }
    kwargs.update(overrides)
    return {"method": "upsert_guard_operation", "kwargs": kwargs}


def call(method: str, label: str = "", *args: object, **kwargs: object) -> dict[str, object]:
    return {"method": method, "label": label, "args": args, "kwargs": kwargs}


def sql(label: str, *statements: tuple[str, tuple[object, ...]]) -> dict[str, object]:
    return {"label": label, "sql": list(statements)}


def _insert_attachment(
    client_id: str, surface: str, session_id: str | None, lease_expires_at: str | None, last_seen_at: str
) -> tuple[str, tuple[object, ...]]:
    return (
        "insert into guard_client_attachments (client_id, surface, session_id, metadata_json, lease_id, "
        "lease_expires_at, attached_at, last_seen_at) values (?, ?, ?, '{}', ?, ?, ?, ?)",
        (client_id, surface, session_id, f"lease-{client_id}", lease_expires_at, T1, last_seen_at),
    )


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "sessions",
        "steps": [
            {**session("s1", T1), "label": "insert"},
            {
                **session("s1", T2, status="attached", client_title=None, workspace=None, capabilities=[]),
                "label": "update keeps created_at",
            },
            {**session("s2", T2, harness="claude-code", surface="dashboard"), "label": "second"},
            {**session("s3", T2, status="attached", capabilities=["café"]), "label": "tie on updated_at"},
            call("get_guard_session", "present", "s1"),
            call("get_guard_session", "missing", "nope"),
            call("list_guard_sessions", "all"),
            call("list_guard_sessions", "status filter", status="attached"),
            call("list_guard_sessions", "limit one", limit=1),
            call("list_guard_sessions", "status and limit", status="attached", limit=1),
            call("list_guard_sessions", "no match", status="closed"),
        ],
    },
    {
        "name": "operations",
        "steps": [
            {**operation("op-1", T1), "label": "insert"},
            {**operation("op-1", T2, status="resolved", resume_token="tok-1"), "label": "update no lineage"},
            {
                **operation("op-2", T2, metadata={"retry_lineage": LINEAGE, "keep": "yes"}),
                "label": "insert with valid lineage",
            },
            {
                **operation("op-2", T3, status="resolved", metadata={"other": 1}),
                "label": "valid lineage preserved",
            },
            {
                **operation("op-2", T3, metadata={"retry_lineage": {"stale": True}, "other": 2}),
                "label": "requested lineage replaced by existing valid one",
            },
            {**operation("op-3", T1, metadata={"retry_lineage": TAMPERED_LINEAGE}), "label": "insert tampered"},
            {**operation("op-3", T2, metadata={"fresh": True}), "label": "tampered lineage dropped"},
            sql(
                "malformed existing metadata",
                (
                    "insert into guard_operations (operation_id, session_id, harness, operation_type, status, "
                    "metadata_json, created_at, updated_at) values ('op-4', 's1', 'codex', 'approval', "
                    "'pending', '{not json', ?, ?)",
                    (T1, T1),
                ),
            ),
            {**operation("op-4", T2, metadata={"after": "malformed"}), "label": "malformed existing treated as empty"},
            sql(
                "list-shaped existing metadata",
                (
                    "insert into guard_operations (operation_id, session_id, harness, operation_type, status, "
                    "metadata_json, created_at, updated_at) values ('op-5', 's1', 'codex', 'approval', "
                    "'pending', '[1, 2]', ?, ?)",
                    (T1, T1),
                ),
            ),
            {**operation("op-5", T2, metadata={"after": "list"}), "label": "non-dict existing ignored"},
            {
                **operation("op-6", T1, session_id="s2", approval_request_ids=["req-9"], metadata={}),
                "label": "other session",
            },
            call("get_guard_operation", "present", "op-1"),
            call("get_guard_operation", "missing", "nope"),
            call("list_guard_operations", "all"),
            call("list_guard_operations", "by session", session_id="s2"),
            call("list_guard_operations", "limit", limit=2),
            call("list_guard_operations", "session and limit", session_id="s1", limit=1),
            call("get_guard_operation_for_approval_request", "exact member", "req-12"),
            call("get_guard_operation_for_approval_request", "prefix is not a member", "req"),
            call("get_guard_operation_for_approval_request", "underscore wildcard is not a member", "req_1"),
            call("get_guard_operation_for_approval_request", "percent wildcard is not a member", "%"),
            call("get_guard_operation_for_approval_request", "other session member", "req-9"),
            call("get_guard_operation_for_approval_request", "unknown", "req-404"),
            sql(
                "non-string request ids",
                (
                    "insert into guard_operations (operation_id, session_id, harness, operation_type, status, "
                    "approval_request_ids_json, metadata_json, created_at, updated_at) values "
                    "('op-7', 's1', 'codex', 'approval', 'pending', '[7, true, null, \"x\"]', '{}', ?, ?)",
                    (T3, T3),
                ),
            ),
            call("get_guard_operation_for_approval_request", "integer id", "7"),
            call("get_guard_operation_for_approval_request", "boolean id", "True"),
            call("get_guard_operation_for_approval_request", "null id", "None"),
            call("get_guard_operation_for_approval_request", "string id after others", "x"),
            sql(
                "two operations share a request id",
                (
                    "insert into guard_operations (operation_id, session_id, harness, operation_type, status, "
                    "approval_request_ids_json, metadata_json, created_at, updated_at) values "
                    "('op-8', 's1', 'codex', 'approval', 'pending', '[\"shared\"]', '{}', ?, ?)",
                    (T1, T2),
                ),
                (
                    "insert into guard_operations (operation_id, session_id, harness, operation_type, status, "
                    "approval_request_ids_json, metadata_json, created_at, updated_at) values "
                    "('op-9', 's1', 'codex', 'approval', 'pending', '[\"shared\"]', '{}', ?, ?)",
                    (T1, T2),
                ),
            ),
            call("get_guard_operation_for_approval_request", "newest then largest id wins", "shared"),
            sql(
                "malformed request ids",
                (
                    "insert into guard_operations (operation_id, session_id, harness, operation_type, status, "
                    "approval_request_ids_json, metadata_json, created_at, updated_at) values "
                    "('op-10', 's1', 'codex', 'approval', 'pending', 'broken-id', '{}', ?, ?)",
                    (T3, T3),
                ),
            ),
            call("get_guard_operation_for_approval_request", "malformed ids raise", "broken-id"),
        ],
    },
    {
        "name": "operation_items",
        "steps": [
            call(
                "add_guard_operation_item",
                "first",
                item_id="i-1",
                operation_id="op-1",
                item_type="note",
                lifecycle="open",
                payload={"text": "café", "n": 2},
                now=T2,
            ),
            call(
                "add_guard_operation_item",
                "same time later id",
                item_id="i-0",
                operation_id="op-1",
                item_type="note",
                lifecycle="open",
                payload={},
                now=T2,
            ),
            call(
                "add_guard_operation_item",
                "earlier time",
                item_id="i-2",
                operation_id="op-1",
                item_type="event",
                lifecycle="closed",
                payload={"k": [1, 2]},
                now=T1,
            ),
            call(
                "add_guard_operation_item",
                "other operation",
                item_id="i-3",
                operation_id="op-2",
                item_type="note",
                lifecycle="open",
                payload={"o": 2},
                now=T3,
            ),
            call(
                "add_guard_operation_item",
                "duplicate id",
                item_id="i-1",
                operation_id="op-1",
                item_type="note",
                lifecycle="open",
                payload={},
                now=T3,
            ),
            call("list_guard_operation_items", "ordered by time then id", "op-1"),
            call("list_guard_operation_items", "other operation", "op-2"),
            call("list_guard_operation_items", "unknown operation", "op-404"),
        ],
    },
    {
        "name": "client_attachments",
        "steps": [
            call(
                "attach_guard_client",
                "insert",
                client_id="c1",
                surface="approval-center",
                session_id="s1",
                metadata={"pid": 7, "name": "café"},
                lease_seconds=60,
                now=T1,
            ),
            call(
                "attach_guard_client",
                "upsert keeps attached_at and issues a new lease",
                client_id="c1",
                surface="dashboard",
                session_id=None,
                metadata={},
                lease_seconds=120,
                now=T2,
            ),
            call(
                "attach_guard_client",
                "lease floor of one second",
                client_id="c2",
                surface="approval-center",
                session_id="s1",
                metadata={},
                lease_seconds=0,
                now=T1,
            ),
            call(
                "attach_guard_client",
                "negative lease floors to one second",
                client_id="c3",
                surface="approval-center",
                session_id="s2",
                metadata={},
                lease_seconds=-5,
                now="2026-07-18T20:00:00.250000+02:00",
            ),
            call("get_guard_client_attachment", "present", "c1"),
            call("get_guard_client_attachment", "missing", "nope"),
            call(
                "renew_guard_client_attachment",
                "matching lease",
                client_id="c1",
                lease_id="00000000000000000000000000000002",
                lease_seconds=30,
                now=T3,
            ),
            call(
                "renew_guard_client_attachment",
                "wrong lease",
                client_id="c1",
                lease_id="stale",
                lease_seconds=30,
                now=T3,
            ),
            call(
                "renew_guard_client_attachment",
                "unknown client",
                client_id="ghost",
                lease_id="stale",
                lease_seconds=30,
                now=T3,
            ),
            call(
                "attach_guard_client",
                "far future lease",
                client_id="live-1",
                surface="approval-center",
                session_id="s1",
                metadata={"live": True},
                lease_seconds=3_000_000_000,
                now=T1,
            ),
            sql(
                "attachments with and without a lease",
                _insert_attachment("old-lease", "approval-center", "s1", PAST, FUTURE),
                _insert_attachment("new-lease", "approval-center", "s1", FUTURE, PAST),
                _insert_attachment("null-fresh", "approval-center", "s1", None, FUTURE),
                _insert_attachment("null-stale", "approval-center", "s1", None, PAST),
                _insert_attachment("null-stale-other", "dashboard", "s2", None, PAST),
            ),
            call("list_guard_client_attachments", "everything live"),
            call("list_guard_client_attachments", "surface filter", surface="approval-center"),
            call("list_guard_client_attachments", "session filter", session_id="s1"),
            call("list_guard_client_attachments", "surface and session", surface="dashboard", session_id="s2"),
            call("list_guard_client_attachments", "zero window", active_within_seconds=0),
            call("list_guard_client_attachments", "negative window", active_within_seconds=-30),
            call("list_guard_client_attachments", "wide window keeps stale null lease", active_within_seconds=10**10),
            call("list_guard_client_attachments", "no match", surface="nowhere"),
            sql(
                "attachment with an unparsable timestamp",
                _insert_attachment("bad-time", "broken", None, "not-a-time", T1),
            ),
            call("list_guard_client_attachments", "bad lease timestamp raises", surface="broken"),
        ],
    },
    {
        "name": "surface_opens",
        "steps": [
            call("record_guard_surface_open", "first", surface="approval-center", open_key="k1", now=T1),
            call("record_guard_surface_open", "update opened_at", surface="approval-center", open_key="k1", now=T2),
            call("record_guard_surface_open", "other key", surface="approval-center", open_key="k2", now=T2),
            call("record_guard_surface_open", "other surface", surface="dashboard", open_key="k1", now=T3),
            call("has_guard_surface_open", "present", surface="approval-center", open_key="k1"),
            call("has_guard_surface_open", "other surface present", surface="dashboard", open_key="k1"),
            call("has_guard_surface_open", "missing key", surface="dashboard", open_key="k2"),
            call("has_guard_surface_open", "missing surface", surface="nowhere", open_key="k1"),
        ],
    },
]

JSON_COLUMNS = ("capabilities_json", "approval_request_ids_json", "metadata_json", "payload_json")


def wire_json(value: object) -> str:
    """How the wrapper hands structured values to the resident: `json.dumps`."""

    return json.dumps(value)
