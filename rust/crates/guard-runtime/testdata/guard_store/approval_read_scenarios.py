"""Approval queue read scenarios for `record_approval_read_vectors.py`.

Each scenario seeds `approval_requests` rows and lists the reads replayed
against them. Paths stay under a directory that does not exist, so resolving
a config path is lexical on every runner.
"""

from __future__ import annotations

import base64
import json

ROOT = "/hol-guard-read-vectors"
GROUP = "qg-seeded"
SOURCE = "guard"
# A row cell spelled `PAD` is replaced on seed by `padded_envelope` of the
# row's `pads` entry: a string size, or `[size, copies]`.
PAD = "__pad__"
DECISION = json.dumps(
    {
        "action": "ask",
        "approval_scopes": ["artifact", "workspace", "publisher", "harness"],
        "confidence": "likely",
        "guard_action": "require-reapproval",
        "reason": "require-reapproval",
        "signals": [],
        "user_title": "Fresh approval required",
    }
)
ENVELOPE = json.dumps(
    {
        "schema_version": 1,
        "action_type": "shell",
        "harness": "codex",
        "tool_name": "Bash",
        "command": "npm run deploy",
        "command_category": "command.deploy",
        "target_paths": [f"{ROOT}/proj/dist"],
        "raw_payload_redacted": {"permission_mode": "default", "body": "dropped"},
        "tool_input": {"ignored": True},
    }
)


def encode_page_cursor(item: dict[str, object]) -> str:
    """The queue page cursor for `item`, frozen from `store_approvals._encode_page_cursor`."""

    raw = json.dumps(
        {"last_seen_at": item["last_seen_at"], "request_id": item["request_id"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def padded_envelope(pad: int | list[int]) -> str:
    size, copies = (pad, 1) if isinstance(pad, int) else pad
    fields = "".join(f',"pad{index or ""}":"' + "a" * size + '"' for index in range(copies))
    return '{"command":"x"' + fields + "}"


def repeat(prefix: str, unit: str, count: int, suffix: str) -> dict[str, list[object]]:
    """A cell expanded on seed to `prefix + unit * count + suffix`."""

    return {"repeat": [prefix, unit, count, suffix]}


def expand(value: object) -> object:
    if isinstance(value, dict):
        prefix, unit, count, suffix = value["repeat"]
        return prefix + unit * count + suffix
    return value


def nested(depth: int) -> str:
    """JSON text of a scalar inside `depth` arrays."""

    return "[" * depth + "1" + "]" * depth


def row(request_id: str, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "request_id": request_id,
        "harness": "codex",
        "artifact_id": "native-review:codex:cmd",
        "artifact_name": "Bash",
        "artifact_type": "native_review",
        "artifact_hash": "native-review-v4:" + "a" * 64,
        "publisher": None,
        "policy_action": "require-reapproval",
        "recommended_scope": "once",
        "changed_fields_json": '["command"]',
        "source_scope": "workspace",
        "oauth_source": SOURCE,
        "config_path": f"{ROOT}/proj/.codex/config.toml",
        "workspace": f"{ROOT}/proj",
        "launch_target": "npm run deploy",
        "normalized_identity_key": "npm run deploy",
        "action_identity": f"identity-{request_id}",
        "queue_group_id": GROUP,
        "dedupe_count": 1,
        "last_seen_at": "2026-03-01T11:00:00+00:00",
        "transport": "stdio",
        "risk_summary": "Deploys the project",
        "risk_signals_json": '["network", "deploy"]',
        "artifact_label": "Bash command",
        "source_label": "Codex",
        "trigger_summary": "PreToolUse",
        "why_now": "first run",
        "launch_summary": "runs deploy",
        "risk_headline": "Deploys build",
        "action_envelope_json": ENVELOPE,
        "decision_v2_json": DECISION,
        "fallback_cli_command": f"hol-guard approvals approve {request_id}",
        "raw_command_text": "npm run deploy",
        "guard_version": "3.44.0",
        "first_seen_guard_version": "3.43.0",
        "last_seen_guard_version": "3.44.0",
        "review_command": f"hol-guard approvals approve {request_id}",
        "approval_url": f"http://127.0.0.1:4781/approvals/{request_id}",
        "status": "pending",
        "created_at": "2026-03-01T10:00:00+00:00",
    }
    base.update(overrides)
    return base


def get(request_id: str, *, derive_scope: bool = True) -> dict[str, object]:
    return {"method": "get", "request_id": request_id, "derive_scope": derive_scope}


def listing(**args: object) -> dict[str, object]:
    return {"method": "list", "args": args}


RESOLVED = {"status": "approved", "resolution_action": "allow", "resolution_scope": "artifact"}
MIXED_ROWS = [
    row("r-a", last_seen_at="2026-03-01T11:00:00+00:00"),
    row("r-b", last_seen_at="2026-03-01T11:00:00+00:00", harness="claude", launch_target="Deploy NOW"),
    row("r-c", last_seen_at="2026-03-01T12:00:00+00:00", created_at="2026-03-01T09:00:00+00:00"),
    row("r-d", **RESOLVED, resolved_at="2026-03-01T12:30:00+00:00", reason="operator approved"),
    row("r-e", status="expired", reason="expired_after_ttl", last_seen_at=None),
    row("r-f", publisher="acme", resolution_action="block", status="pending", raw_command_text=None),
]
SUPERSEDED_ROWS = [
    row("r-new", last_seen_at="2026-03-01T12:00:00+00:00"),
    row("r-old", status="expired", reason="superseded_by_fresh_review:r-new"),
    row("r-old-resolved-candidate", status="expired", reason="superseded_by_fresh_review:r-done"),
    row("r-done", **RESOLVED),
    row("r-old-other-workspace", status="expired", reason="superseded_by_fresh_review:r-elsewhere"),
    row("r-elsewhere", workspace=f"{ROOT}/other"),
    row("r-old-bad-candidate", status="expired", reason="superseded_by_fresh_review:r-broken"),
    row("r-broken", decision_v2_json=json.dumps({"action": "allow", "guard_action": "allow"})),
    row("r-old-bad-id", status="expired", reason="superseded_by_fresh_review:bad id!"),
    row("r-old-long-id", status="expired", reason="superseded_by_fresh_review:" + "x" * 65),
    row("r-old-missing", status="expired", reason="superseded_by_fresh_review:r-gone"),
    row("r-pending-reason", reason="superseded_by_fresh_review:r-new"),
    row("r-null-ws-old", status="expired", reason="superseded_by_fresh_review:r-null-ws", workspace=None),
    row("r-null-ws", workspace=None, queue_group_id=None, oauth_source=None),
    row("r-null-group-old", status="expired", reason="superseded_by_fresh_review:r-null-group", queue_group_id=None),
    row("r-null-group", queue_group_id=None),
]
BROWSER_OPERATIONS = [
    ("network-activity", "playwright", "browser_network_requests"),
    ("network-request", "chrome-devtools", "get_network_request"),
    ("console-messages", "chrome-devtools", "list_console_messages"),
    ("console-message", "chrome-devtools", "get_console_message"),
    ("elements", "playwright", "browser_drag"),
    ("element", "playwright", "browser_click"),
    ("open-pages", "chrome-devtools", "list_pages"),
    ("browser-page", "chrome-devtools", "select_page"),
    ("current-page", "playwright", "browser_navigate"),
    ("unclassified", "playwright", "frobnicate"),
    ("not-browser", "github", "create_issue"),
]
BROWSER_ROWS = [
    row(
        f"r-browser-{label}",
        artifact_type="mcp_tool",
        launch_target=f"{server} {operation} unknown",
        risk_signals_json=json.dumps(["Touches unknown target", 7, "unknown target twice: unknown target"]),
        last_seen_at=f"2026-03-01T11:{index:02d}:00+00:00",
    )
    for index, (label, server, operation) in enumerate(BROWSER_OPERATIONS)
] + [
    row("r-browser-tabs", launch_target="playwright\tbrowser_click\x1funknown"),
    row("r-browser-four-parts", launch_target="playwright browser_click unknown extra"),
    row("r-browser-known", launch_target="playwright browser_click button"),
    row("r-browser-null", launch_target=None),
]
TRUSTED_TOOL = {
    "source": "trusted_local_tool",
    "eligible": True,
    "tool_name": "rg",
    "tool_identity_hash": "b" * 64,
    "capability": "search",
    "read_only_reason": "reads files",
}
BROWSER_INTENT = {
    "mcp_server_identity_hash": "c" * 64,
    "mcp_server_name": "playwright",
    "intent": "browser.navigation",
    "risk_categories": ["browser_navigation", "browser_external_domain"],
    "target_domain": "example.com",
}
PACKAGE_ENVELOPE = json.dumps(
    {
        "action_type": "package_install",
        "command": "npm install left-pad",
        "package_manager": "npm",
        "package_name": "left-pad",
        "package_intent_kind": "install",
        "package_targets": ["left-pad@1.3.0"],
        "command_category": "command.package_install",
    }
)
SHAPE_ROWS = [
    row(
        "r-package",
        artifact_type="package_request",
        artifact_id="npm:package-request:left-pad",
        action_envelope_json=PACKAGE_ENVELOPE,
        launch_target="npm install left-pad",
    ),
    row("r-ws-dot-dir", workspace=None, config_path=f"{ROOT}/proj/.codex/config.toml"),
    row("r-ws-plain-dir", workspace=None, config_path=f"{ROOT}/proj/config.toml"),
    row("r-ws-blank", workspace="  \t", config_path=f"{ROOT}/blank/.claude/settings.json"),
    row("r-ws-empty-config", workspace=None, config_path=""),
    row("r-ws-dotdot", workspace=None, config_path=f"{ROOT}/a/../b/./.cursor//mcp.json"),
    row("r-ws-root", workspace=None, config_path="/config.toml"),
    row("r-ws-root-dot", workspace=None, config_path="/.codex/config.toml"),
    row(
        "r-malformed",
        changed_fields_json="not json",
        risk_signals_json='{"a": 1}',
        decision_v2_json="{bad",
        action_envelope_json="[1, 2]",
        scanner_evidence_json='[1, {"source": "x", "dup": 1, "dup": 2}, "s"]',
        browser_intent_json="[]",
        continuation_snapshot_json='"text"',
    ),
    row("r-decision-list", decision_v2_json='["ask"]', action_envelope_json="null"),
    row("r-decision-nan", decision_v2_json='{"action": "ask", "score": NaN}'),
    row("r-envelope-infinity", action_envelope_json='{"command": "x", "n": -Infinity}'),
    row("r-decision-null", decision_v2_json=None, action_envelope_json=None, policy_action="block"),
    row("r-unknown-action", policy_action="frobnicate", decision_v2_json=None),
    row("r-long-unknown-action", policy_action="z" * 70, decision_v2_json='{"score": NaN}'),
    row(
        "r-huge-int",
        risk_signals_json="[" + "9" * 4301 + "]",
        changed_fields_json="[2.5, -0.0, 1e16, 1E-7, 100000000000000000000000]",
    ),
    row(
        "r-evidence",
        scanner_evidence_json=json.dumps([TRUSTED_TOOL, {"source": "scanner", "rule": "x"}, "skip"]),
        browser_intent_json=json.dumps(BROWSER_INTENT),
        continuation_snapshot_json=json.dumps({"capability": "retry-only", "correlationId": "c-1"}),
    ),
    row("r-watch-only", watch_only_observation=1),
    row("r-watch-text", watch_only_observation="yes"),
    row("r-dedupe-zero", dedupe_count=0),
    row("r-dedupe-negative", dedupe_count=-3),
    row("r-dedupe-float", dedupe_count=2.7),
    row("r-dedupe-empty", dedupe_count=""),
    row("r-dedupe-text-int", dedupe_count=" 12 "),
    row("r-unicode", artifact_name="Bàsh ✓", why_now="naïve", risk_signals_json='["\\u00e9", "\\ud83d\\ude00"]'),
    row("r-legacy-null-scope", source_scope="user", publisher="acme", raw_command_text=None, action_identity=None),
]

TRANSPORT_ROWS = [
    row("r-deep-decision-ok", decision_v2_json='{"action": "ask", "n": ' + nested(26) + "}"),
    row("r-deep-decision-over", decision_v2_json='{"action": "ask", "n": ' + nested(27) + "}"),
    row("r-deep-envelope-over", action_envelope_json='{"command": "x", "target_paths": ' + nested(27) + "}"),
    row("r-wide-envelope-ok", action_envelope_json=json.dumps({f"k{index}": index for index in range(4096)})),
    row("r-wide-envelope-over", action_envelope_json=json.dumps({f"k{index}": index for index in range(4097)})),
    row("r-wide-evidence-ok", scanner_evidence_json=json.dumps([{"source": "s"}] * 4096)),
    row("r-wide-evidence-over", scanner_evidence_json=json.dumps([{"source": "s"}] * 4097)),
    row("r-deep-evidence-ok", scanner_evidence_json='[{"source": "s", "n": ' + nested(26) + "}]"),
    row("r-deep-evidence-over", scanner_evidence_json='[{"source": "s", "n": ' + nested(27) + "}]"),
    row("r-deep-display", risk_signals_json=nested(60), changed_fields_json=nested(40)),
    row("r-surrogate-decision", decision_v2_json='{"action": "ask", "s": "\\ud800"}'),
    row("r-surrogate-evidence", scanner_evidence_json='[{"source": "\\udfff"}]'),
    row("r-infinity-evidence", scanner_evidence_json='[{"source": "s", "n": Infinity}]'),
    row("r-raw-decision-text", decision_v2_json=repeat('["', "b", 1_100_000, '"]')),
    row("r-long-config", workspace=None, config_path=repeat(f"{ROOT}/", "c", 1_100_000, "")),
    row("r-request-big", action_envelope_json=PAD),
    row("r-response-big", action_envelope_json=PAD),
    row("r-near-string", action_envelope_json=PAD),
]

SCENARIOS: list[dict[str, object]] = [
    {
        "name": "mixed_queue",
        "rows": MIXED_ROWS,
        "calls": [
            listing(),
            listing(status=None, limit=None),
            listing(status="approved"),
            listing(status="expired", limit=None),
            listing(harness="claude"),
            listing(harness="codex", limit=2),
            listing(status=None, search="deploy now"),
            listing(status=None, search="DEPLOY", limit=3),
            listing(status=None, search="no-such-text"),
            listing(status=None, search="%"),
            listing(limit=1),
            listing(limit=0),
            listing(limit=-1),
            listing(status=None, cursor_of="r-c"),
            listing(status=None, cursor_of="r-b", limit=2),
            listing(cursor="!!!"),
            listing(cursor="e30"),
            listing(cursor="eyJsYXN0X3NlZW5fYXQiOjEsInJlcXVlc3RfaWQiOiJ4In0"),
            get("r-a"),
            get("r-d"),
            get("r-e"),
            get("r-f"),
            get("r-a", derive_scope=False),
            get("missing"),
        ],
    },
    {
        "name": "superseded_lookup",
        "rows": SUPERSEDED_ROWS,
        "calls": [
            *[get(str(item["request_id"])) for item in SUPERSEDED_ROWS],
            get("r-old", derive_scope=False),
            get("r-old-bad-candidate", derive_scope=False),
            listing(status="expired", limit=None),
        ],
    },
    {
        "name": "browser_display",
        "rows": BROWSER_ROWS,
        "calls": [
            listing(status=None, limit=None),
            *[get(str(item["request_id"])) for item in BROWSER_ROWS],
        ],
    },
    {
        "name": "row_shapes",
        "rows": SHAPE_ROWS,
        "calls": [
            listing(status=None, limit=None),
            *[get(str(item["request_id"])) for item in SHAPE_ROWS],
            *[get(str(item["request_id"]), derive_scope=False) for item in SHAPE_ROWS],
        ],
    },
    {
        "name": "dedupe_text_fails",
        "rows": [row("r-ok"), row("r-dedupe-text", dedupe_count="abc", last_seen_at="2026-03-01T12:00:00+00:00")],
        "calls": [listing(status=None), get("r-dedupe-text"), get("r-dedupe-text", derive_scope=False), get("r-ok")],
    },
    {
        "name": "empty_queue",
        "rows": [],
        "calls": [listing(), listing(status=None, limit=None, search="x"), get("r-a")],
    },
    {
        "name": "oversized_rows",
        "rows": [
            row("r-big", action_envelope_json=PAD, last_seen_at="2026-03-01T11:00:00+00:00"),
            row("r-huge", action_envelope_json=PAD, last_seen_at="2026-03-01T12:00:00+00:00"),
            row("r-small", last_seen_at="2026-03-01T10:00:00+00:00"),
        ],
        "pads": {"r-big": 1_200_000, "r-huge": 2_500_000},
        "calls": [get("r-big"), get("r-huge"), get("r-small"), listing(limit=None)],
    },
    {
        # Values the resident transport refuses (depth, width, string size,
        # lone surrogates, non-finite numbers) and single rows the projection
        # refuses by size.
        "name": "transport_limits",
        "rows": TRANSPORT_ROWS,
        "pads": {"r-request-big": [900_000, 5], "r-response-big": [900_000, 3], "r-near-string": 1_000_000},
        "calls": [get(str(item["request_id"])) for item in TRANSPORT_ROWS]
        + [
            get(str(item["request_id"]), derive_scope=False)
            for item in TRANSPORT_ROWS
            # The draft keeps the stored infinity and lone surrogate, which
            # no JSON reply can carry.
            if item["request_id"] not in {"r-infinity-evidence", "r-surrogate-evidence"}
        ],
    },
]
