"""Approval metadata scenarios for `record_approval_metadata_vectors.py`.

Each scenario seeds `approval_requests` rows; every call runs against a fresh
copy of them. `legacy_hint_column` scenarios drop `extension_allow_hint_json`
first, as a store from before the column existed.
"""

from __future__ import annotations

from approval_read_scenarios import SOURCE, row

HINT = '{"extension_id": "ext.deploy", "matcher": "npm run deploy", "scope": "workspace"}'
NOTIFIED_AT = "2026-03-02T10:00:00+00:00"


def method(name: str, **args: object) -> dict[str, object]:
    return {"method": name, "source": SOURCE, "args": args}


def hint(request_id: str) -> dict[str, object]:
    return method("get_approval_extension_allow_hint", request_id=request_id)


def notified(request_id: str) -> dict[str, object]:
    return method("approval_desktop_notified_at", request_id=request_id)


def mark(request_id: str, notified_at: str = NOTIFIED_AT) -> dict[str, object]:
    return method("mark_approval_desktop_notified", request_id=request_id, notified_at=notified_at)


def oldest(status: str = "pending") -> dict[str, object]:
    return method("oldest_approval_request_created_at", status=status)


HINT_ROWS = [
    row("h-object", extension_allow_hint_json=HINT),
    row("h-null"),
    row("h-empty", extension_allow_hint_json=""),
    row("h-list", extension_allow_hint_json='["ext.deploy"]'),
    row("h-string", extension_allow_hint_json='"ext.deploy"'),
    row("h-number", extension_allow_hint_json="7"),
    row("h-invalid", extension_allow_hint_json="{not json"),
    row("h-empty-object", extension_allow_hint_json="{}"),
    row(
        "h-nested",
        extension_allow_hint_json='{"a": {"b": [1, 2.5, true, null]}, "big": 123456789012345678901234567890}',
    ),
    row("h-unicode", extension_allow_hint_json='{"name": "d\\u00e9ploy \\ud83d\\ude80", "dup": 1, "dup": 2}'),
    row("h-whitespace", extension_allow_hint_json='  {"k": "v"}\n'),
    row("h-int-cell", extension_allow_hint_json=42),
]
HINT_IDS = [str(item["request_id"]) for item in HINT_ROWS] + ["missing"]

NOTIFY_ROWS = [
    row("n-fresh"),
    row("n-done", desktop_notified_at="2026-03-01T12:00:00+00:00"),
    row("n-empty", desktop_notified_at=""),
    row("n-int", desktop_notified_at=17),
]
NOTIFY_IDS = [str(item["request_id"]) for item in NOTIFY_ROWS] + ["missing"]

OLDEST_ROWS = [
    row("o-a", created_at="2026-03-01T10:00:00+00:00"),
    row("o-b", created_at="2026-02-28T09:00:00+00:00"),
    row("o-resolved", status="resolved", created_at="2026-01-01T00:00:00+00:00"),
    row("o-approved", status="approved", created_at=""),
    row("o-mixed-a", status="mixed", created_at=5),
    row("o-mixed-b", status="mixed", created_at="2026-01-02T00:00:00+00:00"),
]

SCENARIOS: list[dict[str, object]] = [
    {"name": "extension_allow_hint", "rows": HINT_ROWS, "calls": [hint(request_id) for request_id in HINT_IDS]},
    {
        "name": "extension_allow_hint_legacy_column",
        "legacy_hint_column": True,
        "rows": [row("h-legacy")],
        "calls": [hint("h-legacy"), hint("missing")],
    },
    {"name": "extension_allow_hint_empty_store", "rows": [], "calls": [hint("missing"), hint("")]},
    {
        "name": "desktop_notified_at",
        "rows": NOTIFY_ROWS,
        "calls": [notified(request_id) for request_id in NOTIFY_IDS]
        + [mark(request_id) for request_id in NOTIFY_IDS]
        + [mark("n-fresh", ""), mark("n-fresh", "later")],
    },
    {
        "name": "oldest_created_at",
        "rows": OLDEST_ROWS,
        "calls": [oldest(), oldest("resolved"), oldest("approved"), oldest("mixed"), oldest("unknown"), oldest("")],
    },
    {"name": "oldest_created_at_empty_store", "rows": [], "calls": [oldest(), oldest("resolved")]},
]
