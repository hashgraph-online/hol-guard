"""Approval queue page, count and next-request scenarios for
`record_approval_page_read_vectors.py`.

Rows come from `approval_read_scenarios`, so the page reads see the same
legacy, malformed, browser and transport-limit shapes as the request reads.
"""

from __future__ import annotations

import json

from approval_read_scenarios import (
    BROWSER_ROWS,
    MIXED_ROWS,
    PAD,
    SHAPE_ROWS,
    TRANSPORT_ROWS,
    repeat,
    row,
)


def page(**args: object) -> dict[str, object]:
    return {"method": "page", "args": args}


def pending(**args: object) -> dict[str, object]:
    return {"method": "pending", "args": args}


def count(**args: object) -> dict[str, object]:
    return {"method": "count", "args": args}


def next_pending(*exclude_ids: str) -> dict[str, object]:
    return {"method": "next", "args": {"exclude_ids": list(exclude_ids)}}


def envelope(**fields: object) -> str:
    return json.dumps({"schema_version": 1, "action_type": "shell", **fields})


RESOLVED = {"status": "resolved", "resolution_action": "allow", "resolution_scope": "artifact"}
PAGE_ROWS = [
    *MIXED_ROWS,
    row("r-res-1", **RESOLVED, resolved_at="2026-03-01T12:00:00+00:00", last_seen_at="2026-03-01T08:00:00+00:00"),
    row("r-res-2", **RESOLVED, resolved_at="2026-03-01T13:00:00+00:00", last_seen_at="2026-03-01T08:00:00+00:00"),
    row("r-res-3", **RESOLVED, resolved_at=None, harness="claude"),
    row("r-watch", watch_only_observation=1, last_seen_at="2026-03-01T13:00:00+00:00"),
    row("r-watch-text", watch_only_observation="yes", last_seen_at="2026-03-01T07:00:00+00:00"),
    row("r-percent", artifact_name="100% safe", launch_target="echo ok", last_seen_at="2026-03-01T06:00:00+00:00"),
    row("r-under", artifact_name="under_score", harness="", last_seen_at="2026-03-01T05:00:00+00:00"),
    row("r-ünï", artifact_name="Bàsh ✓", status="", last_seen_at="2026-03-01T04:00:00+00:00"),
    row("r-weird", status="weird", last_seen_at="2026-03-01T03:00:00+00:00"),
]
PAGE_CALLS = [
    page(),
    page(limit=2),
    page(limit=0),
    page(limit=-5),
    page(limit=1000),
    page(status=None),
    page(status=None, limit=3),
    page(status="resolved"),
    page(status="resolved", limit=1),
    page(status="approved"),
    page(status="expired"),
    page(status=""),
    page(status="weird"),
    page(status="missing"),
    page(harness="claude"),
    page(status=None, harness=""),
    page(status=None, search="deploy"),
    page(status=None, search="DEPLOY NOW"),
    page(status=None, search="%"),
    page(status=None, search="_"),
    page(status=None, search="100%"),
    page(status=None, search="under_score"),
    page(status=None, search=""),
    page(status=None, search="BÀSH"),
    page(status=None, search="bàsh"),
    page(include_totals=False),
    page(status=None, include_totals=False, limit=2),
    page(exclude_watch_only=True),
    page(status=None, exclude_watch_only=True, search="deploy"),
    page(cursor_of="r-c"),
    page(status=None, cursor_of="r-b", limit=2),
    page(status=None, cursor_of="r-ünï"),
    page(status=None, cursor_of="r-e"),
    page(cursor="!!!"),
    page(cursor="e30"),
    page(cursor="eyJsYXN0X3NlZW5fYXQiOjEsInJlcXVlc3RfaWQiOiJ4In0"),
    page(status=None, cursor="eyJsYXN0X3NlZW5fYXQiOiI5OTk5IiwicmVxdWVzdF9pZCI6InotZ2hvc3QifQ"),
    pending(),
    pending(limit=1, exclude_watch_only=True),
    pending(harness="codex", search="deploy", include_totals=False),
    pending(cursor_of="r-a"),
    pending(limit=10),
    pending(cursor="!!!"),
    count(),
    count(status=None),
    count(status="resolved"),
    count(status=""),
    count(status=None, harness="claude"),
    count(search="deploy"),
    count(status=None, search="%"),
    count(status=None, search="_"),
    count(status=None, resolved_at_from="2026-03-01T12:00:00+00:00"),
    count(status=None, resolved_at_before="2026-03-01T12:30:00+00:00"),
    count(status=None, resolved_at_from="2026-03-01T12:00:00+00:00", resolved_at_before="2026-03-01T13:00:00+00:00"),
    count(exclude_watch_only=True),
    count(status=None, exclude_watch_only=True, harness="codex", search="deploy"),
    next_pending(),
    next_pending("r-watch"),
    next_pending("r-watch", "r-c", "missing"),
    next_pending("r-watch", "r-c", "r-a", "r-b", "r-f", "r-percent", "r-watch-text"),
]

CHAIN_ROWS = [
    row(
        f"r-chain-{index:02d}",
        last_seen_at=f"2026-03-01T10:{index // 2:02d}:00+00:00",
        harness=("codex", "claude")[index % 2],
    )
    for index in range(12)
]
CHAIN_CALLS = [
    page(limit=5),
    page(limit=5, cursor_of="r-chain-07"),
    page(limit=5, cursor_of="r-chain-06"),
    page(limit=5, cursor_of="r-chain-02"),
    page(limit=5, cursor_of="r-chain-00"),
    page(limit=4, harness="claude"),
    page(limit=4, harness="claude", cursor_of="r-chain-05"),
    page(limit=12),
    page(limit=11),
    count(),
    next_pending(),
    next_pending("r-chain-11", "r-chain-10"),
]

PREVIEW_ROWS = [
    row("p-long", action_envelope_json=envelope(command="x" * 600, command_category="command.deploy")),
    row("p-512", action_envelope_json=envelope(command="y" * 512, command_category="other")),
    row("p-513", action_envelope_json=envelope(command="z" * 513, command_category=7)),
    row("p-padded", action_envelope_json=envelope(command="  \t padded cmd \n", command_category="command.")),
    row("p-unicode-long", action_envelope_json=envelope(command="é" * 700 + "ü")),
    row("p-blank-command", action_envelope_json=envelope(command=" 　 "), launch_target="  launch here  "),
    row("p-int-command", action_envelope_json=envelope(command=5), launch_target="target"),
    row("p-blank-both", action_envelope_json=envelope(command=""), launch_target="   "),
    row("p-null-target", action_envelope_json=envelope(), launch_target=None),
    row("p-null-envelope", action_envelope_json=None, launch_target="from target"),
    row("p-long-target", action_envelope_json=None, launch_target="t" * 1000),
    row("p-browser", action_envelope_json=None, launch_target="playwright browser_click unknown"),
]

BIG_ROWS = [
    row(
        f"r-wide-{index}",
        raw_command_text=repeat("", "r", 400_000, f"-{index}"),
        last_seen_at=f"2026-03-01T09:{index:02d}:00+00:00",
    )
    for index in range(8)
]

LIMIT_ROWS = [
    row(f"r-many-{index:03d}", last_seen_at=f"2026-03-01T{10 + index // 60:02d}:{index % 60:02d}:00+00:00")
    for index in range(205)
]

SCENARIOS: list[dict[str, object]] = [
    {"name": "page_mixed", "rows": PAGE_ROWS, "calls": PAGE_CALLS},
    {"name": "page_chain", "rows": CHAIN_ROWS, "calls": CHAIN_CALLS},
    {
        "name": "page_previews",
        "rows": PREVIEW_ROWS,
        "calls": [page(limit=200), *[page(search=f"identity-{item['request_id']}") for item in PREVIEW_ROWS]],
    },
    {
        "name": "page_browser",
        "rows": BROWSER_ROWS,
        "calls": [page(status=None, limit=200), next_pending()],
    },
    {
        "name": "page_shapes",
        "rows": SHAPE_ROWS,
        "calls": [
            page(status=None, limit=200),
            count(status=None),
            next_pending(),
            *[page(status=None, search=f"identity-{item['request_id']}") for item in SHAPE_ROWS],
        ],
    },
    {
        "name": "page_dedupe_text",
        "rows": [row("r-ok"), row("r-dedupe-text", dedupe_count="abc", last_seen_at="2026-03-01T12:00:00+00:00")],
        "calls": [page(), page(include_totals=False, limit=1), count(), next_pending(), next_pending("r-dedupe-text")],
    },
    {
        "name": "page_empty",
        "rows": [],
        "calls": [page(), page(status=None, search="x"), pending(), count(), count(status=None), next_pending()],
    },
    {
        "name": "page_limit_clamp",
        "rows": LIMIT_ROWS,
        "calls": [page(limit=500), page(limit=200, cursor_of="r-many-005"), count(), next_pending()],
    },
    {
        # Summaries past one reply's byte budget; the read must still return
        # the whole page.
        "name": "page_wide_rows",
        "rows": BIG_ROWS,
        "calls": [page(limit=10), page(limit=3), pending(limit=8, include_totals=False)],
    },
    {
        "name": "page_oversized",
        "rows": [
            row("r-big", action_envelope_json=PAD, last_seen_at="2026-03-01T11:00:00+00:00"),
            row("r-huge", action_envelope_json=PAD, last_seen_at="2026-03-01T12:00:00+00:00"),
            row("r-small", last_seen_at="2026-03-01T10:00:00+00:00"),
        ],
        "pads": {"r-big": 1_200_000, "r-huge": 2_500_000},
        "calls": [
            page(limit=200),
            page(search="identity-r-big"),
            page(search="identity-r-huge"),
            page(search="identity-r-small"),
            next_pending(),
            next_pending("r-huge"),
        ],
    },
    {
        "name": "page_transport_limits",
        "rows": TRANSPORT_ROWS,
        "pads": {"r-request-big": [900_000, 5], "r-response-big": [900_000, 3], "r-near-string": 1_000_000},
        "calls": [page(search=f"identity-{item['request_id']}") for item in TRANSPORT_ROWS],
    },
]
