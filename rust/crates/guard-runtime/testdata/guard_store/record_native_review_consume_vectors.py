#!/usr/bin/env python3
"""Record native-review consume vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `store_native_review_approvals.py`
(the Python twin), never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario seeds `approval_requests` rows, then replays a sequence of
`GuardStore.consume_native_review_approval` calls on a real `guard.db`. Per
call the vectors hold the Python boolean and the post-call
`guard_continuation_effects` rows. Scenarios flagged `native_may_deny` use
timestamp spellings CPython accepts but the resident deliberately refuses
(fail closed); the replay asserts the resident answers `false` for them.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)

from codex_plugin_scanner.guard import store_native_review_approvals

if not hasattr(store_native_review_approvals, "consume_native_review_approval"):
    sys.exit("refusing to record: the original Python consume implementation is gone")

from codex_plugin_scanner.guard.store import GuardStore

HASH = "native-review-v4:" + "a" * 64 + ":alpha:beta:gamma:delta"
DOMAIN_HASH = HASH + ":" + "b" * 64
T0 = "2026-03-01T12:00:00+00:00"
BASE_ARGS = {
    "harness": "claude-code",
    "artifact_id": "native-review:claude-code:cmd",
    "artifact_name": "Bash",
    "artifact_hash": HASH,
    "launch_target": "cat .env",
    "workspace": "/work/space",
    "now": "2026-03-01T12:01:00+00:00",
}
TABLES = ("approval_requests", "guard_continuation_effects")


def row(request_id: str, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "request_id": request_id,
        "harness": BASE_ARGS["harness"],
        "artifact_id": BASE_ARGS["artifact_id"],
        "artifact_name": BASE_ARGS["artifact_name"],
        "artifact_type": "native_review",
        "artifact_hash": HASH,
        "policy_action": "require-reapproval",
        "recommended_scope": "once",
        "changed_fields_json": "[]",
        "source_scope": "workspace",
        "config_path": "/cfg",
        "workspace": BASE_ARGS["workspace"],
        "launch_target": BASE_ARGS["launch_target"],
        "review_command": "hol-guard approvals",
        "approval_url": "http://127.0.0.1/approvals",
        "status": "resolved",
        "resolution_action": "allow",
        "resolution_scope": "once",
        "created_at": "2026-03-01T11:59:00+00:00",
        "resolved_at": T0,
    }
    base.update(overrides)
    return base


def call(**overrides: object) -> dict[str, object]:
    return {**BASE_ARGS, **overrides}


SCENARIOS: list[dict[str, object]] = [
    {"name": "once_allow_then_replay", "rows": [row("r1")], "calls": [call(), call()]},
    {"name": "artifact_scope_allow", "rows": [row("r1", resolution_scope="artifact")], "calls": [call(), call()]},
    {
        "name": "domain_bound_hash",
        "rows": [row("r1", artifact_hash=DOMAIN_HASH)],
        "calls": [call(artifact_hash=DOMAIN_HASH), call(artifact_hash=DOMAIN_HASH)],
    },
    {"name": "domain_hash_does_not_match_plain", "rows": [row("r1", artifact_hash=DOMAIN_HASH)], "calls": [call()]},
    {"name": "session_scope_refused", "rows": [row("r1", resolution_scope="session")], "calls": [call()]},
    {"name": "global_scope_refused", "rows": [row("r1", resolution_scope="global")], "calls": [call()]},
    {"name": "null_scope_refused", "rows": [row("r1", resolution_scope=None)], "calls": [call()]},
    {"name": "deny_refused", "rows": [row("r1", resolution_action="deny")], "calls": [call()]},
    {"name": "null_action_refused", "rows": [row("r1", resolution_action=None)], "calls": [call()]},
    {
        "name": "pending_row_ignored",
        "rows": [row("r1", status="pending", resolution_action=None, resolution_scope=None, resolved_at=None)],
        "calls": [call()],
    },
    {"name": "expired_after_five_minutes", "rows": [row("r1")], "calls": [call(now="2026-03-01T12:05:01+00:00")]},
    {"name": "exactly_five_minutes", "rows": [row("r1")], "calls": [call(now="2026-03-01T12:05:00+00:00")]},
    {
        "name": "five_minutes_plus_one_microsecond",
        "rows": [row("r1")],
        "calls": [call(now="2026-03-01T12:05:00.000001+00:00")],
    },
    {"name": "decision_in_the_future", "rows": [row("r1")], "calls": [call(now="2026-03-01T11:59:59+00:00")]},
    {"name": "same_instant_as_now", "rows": [row("r1")], "calls": [call(now=T0)]},
    {
        "name": "newer_deny_masks_older_allow",
        "rows": [row("r1"), row("r2", resolution_action="deny", resolved_at="2026-03-01T12:00:30+00:00")],
        "calls": [call()],
    },
    {
        "name": "newer_allow_beats_older_deny",
        "rows": [
            row("r1", resolution_action="deny", resolved_at="2026-03-01T11:59:00+00:00"),
            row("r2", resolved_at="2026-03-01T12:00:30+00:00"),
        ],
        "calls": [call(), call()],
    },
    {
        "name": "same_instant_conflict_fails_closed",
        "rows": [row("r1"), row("r2", resolution_action="deny")],
        "calls": [call()],
    },
    {
        "name": "same_instant_scope_conflict_fails_closed",
        "rows": [row("r1"), row("r2", resolution_scope="session")],
        "calls": [call()],
    },
    {
        "name": "same_instant_duplicates_spend_once",
        "rows": [row("r2"), row("r1"), row("r3", resolution_scope="artifact")],
        "calls": [call(), call()],
    },
    {
        "name": "equal_instant_different_offsets",
        "rows": [row("r2", resolved_at="2026-03-01T14:00:00+02:00"), row("r1")],
        "calls": [call(), call()],
    },
    {
        "name": "offset_instant_is_normalized_for_key",
        "rows": [row("r1", resolved_at="2026-03-01T14:00:00+02:00")],
        "calls": [call(), call()],
    },
    {
        "name": "fractional_seconds_key",
        "rows": [row("r1", resolved_at="2026-03-01T12:00:00.123456+00:00")],
        "calls": [call(), call()],
    },
    {
        "name": "short_fraction_key",
        "rows": [row("r1", resolved_at="2026-03-01T12:00:00.5+00:00")],
        "calls": [call(), call()],
    },
    {
        "name": "now_with_offset",
        "rows": [row("r1")],
        "calls": [call(now="2026-03-01T13:02:00+01:00"), call(now="2026-03-01T13:02:00+01:00")],
    },
    {"name": "invalid_now_refused", "rows": [row("r1")], "calls": [call(now="not-a-time")]},
    {"name": "naive_now_refused", "rows": [row("r1")], "calls": [call(now="2026-03-01T12:01:00")]},
    {
        "name": "invalid_row_timestamp_blocks_older_allow",
        "rows": [row("r1"), row("r2", resolved_at="garbage")],
        "calls": [call()],
    },
    {
        "name": "naive_row_timestamp_blocks_older_allow",
        "rows": [row("r1"), row("r2", resolved_at="2026-03-01T12:00:30")],
        "calls": [call()],
    },
    {"name": "null_row_timestamp_blocks", "rows": [row("r1", resolved_at=None)], "calls": [call()]},
    {"name": "harness_mismatch", "rows": [row("r1")], "calls": [call(harness="codex")]},
    {"name": "artifact_id_mismatch", "rows": [row("r1")], "calls": [call(artifact_id="other")]},
    {"name": "artifact_name_mismatch", "rows": [row("r1")], "calls": [call(artifact_name="Read")]},
    {"name": "launch_target_mismatch", "rows": [row("r1")], "calls": [call(launch_target="ls")]},
    {"name": "workspace_mismatch", "rows": [row("r1")], "calls": [call(workspace="/elsewhere")]},
    {
        "name": "null_workspace_matches_null",
        "rows": [row("r1", workspace=None)],
        "calls": [call(workspace=None), call(workspace=None)],
    },
    {"name": "null_workspace_does_not_match_value", "rows": [row("r1", workspace=None)], "calls": [call()]},
    {"name": "value_workspace_does_not_match_null", "rows": [row("r1")], "calls": [call(workspace=None)]},
    {"name": "no_rows", "rows": [], "calls": [call()]},
    {
        "name": "uppercase_hex_binding_refused",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "A" * 64 + ":a:b:c:d")],
        "calls": [call(artifact_hash="native-review-v4:" + "A" * 64 + ":a:b:c:d")],
    },
    {
        "name": "three_token_binding_refused",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "a" * 64 + ":a:b:c")],
        "calls": [call(artifact_hash="native-review-v4:" + "a" * 64 + ":a:b:c")],
    },
    {
        "name": "five_token_binding_refused",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "a" * 64 + ":a:b:c:d:e")],
        "calls": [call(artifact_hash="native-review-v4:" + "a" * 64 + ":a:b:c:d:e")],
    },
    {
        "name": "short_digest_binding_refused",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "a" * 63 + ":a:b:c:d")],
        "calls": [call(artifact_hash="native-review-v4:" + "a" * 63 + ":a:b:c:d")],
    },
    {
        "name": "token_charset_binding",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "a" * 64 + ":a-b:c_d:e1:f2")],
        "calls": [call(artifact_hash="native-review-v4:" + "a" * 64 + ":a-b:c_d:e1:f2")],
    },
    {
        "name": "uppercase_token_binding_refused",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "a" * 64 + ":A:b:c:d")],
        "calls": [call(artifact_hash="native-review-v4:" + "a" * 64 + ":A:b:c:d")],
    },
    {
        "name": "token_length_128_binding",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "a" * 64 + ":" + "x" * 128 + ":b:c:d")],
        "calls": [call(artifact_hash="native-review-v4:" + "a" * 64 + ":" + "x" * 128 + ":b:c:d")],
    },
    {
        "name": "token_length_129_binding_refused",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "a" * 64 + ":" + "x" * 129 + ":b:c:d")],
        "calls": [call(artifact_hash="native-review-v4:" + "a" * 64 + ":" + "x" * 129 + ":b:c:d")],
    },
    {
        "name": "empty_token_binding_refused",
        "rows": [row("r1", artifact_hash="native-review-v4:" + "a" * 64 + "::b:c:d")],
        "calls": [call(artifact_hash="native-review-v4:" + "a" * 64 + "::b:c:d")],
    },
    {
        "name": "trailing_newline_binding_refused",
        "rows": [row("r1", artifact_hash=HASH + "\n")],
        "calls": [call(artifact_hash=HASH + "\n")],
    },
    {
        "name": "plain_hash_refused",
        "rows": [row("r1", artifact_hash="a" * 64)],
        "calls": [call(artifact_hash="a" * 64)],
    },
    {
        "name": "different_bindings_spend_separately",
        "rows": [row("r1"), row("r2", artifact_hash=DOMAIN_HASH)],
        "calls": [call(), call(artifact_hash=DOMAIN_HASH), call(), call(artifact_hash=DOMAIN_HASH)],
    },
    {
        "name": "new_decision_after_spend_is_a_new_capability",
        "rows": [row("r1")],
        "calls": [call(), call()],
        "after_first_call_rows": [row("r2", resolved_at="2026-03-01T12:00:45+00:00")],
    },
    {
        "name": "z_suffix_timestamp",
        "rows": [row("r1", resolved_at="2026-03-01T12:00:00Z")],
        "calls": [call(now="2026-03-01T12:01:00Z"), call(now="2026-03-01T12:01:00Z")],
    },
    {
        "name": "space_separator_timestamp",
        "rows": [row("r1", resolved_at="2026-03-01 12:00:00+00:00")],
        "calls": [call(), call()],
    },
    {
        "name": "hour_only_offset_timestamp",
        "rows": [row("r1", resolved_at="2026-03-01T14:00:00+02")],
        "calls": [call(), call()],
    },
    {
        "name": "invalid_calendar_date_row",
        "rows": [row("r1", resolved_at="2026-02-30T12:00:00+00:00")],
        "calls": [call()],
    },
    {"name": "hour_24_row_refused", "rows": [row("r1", resolved_at="2026-03-01T24:00:00+00:00")], "calls": [call()]},
    {
        "name": "long_fraction_truncated",
        "rows": [row("r1", resolved_at="2026-03-01T12:00:00.123456789+00:00")],
        "calls": [call(), call()],
    },
    {
        "name": "basic_format_timestamp",
        "native_may_deny": True,
        "rows": [row("r1", resolved_at="20260301T120000+0000")],
        "calls": [call()],
    },
    {
        "name": "week_date_timestamp",
        "native_may_deny": True,
        "rows": [row("r1", resolved_at="2026-W09-1T12:00:00+00:00")],
        "calls": [call(now="2026-02-23T12:01:00+00:00")],
    },
    {
        "name": "offset_with_seconds_timestamp",
        "native_may_deny": True,
        "rows": [row("r1", resolved_at="2026-03-01T12:00:00+00:00:30")],
        "calls": [call(now="2026-03-01T12:01:00+00:00")],
    },
    {"name": "non_string_timestamp", "rows": [row("r1", resolved_at=12345)], "calls": [call()]},
]


def dump(path: Path, table: str, order: str) -> list[dict[str, object]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(item) for item in connection.execute(f"select * from {table} order by {order}")]
    finally:
        connection.close()


def insert(path: Path, rows: list[dict[str, object]]) -> None:
    connection = sqlite3.connect(path)
    try:
        for item in rows:
            columns = ",".join(item)
            marks = ",".join("?" * len(item))
            connection.execute(f"insert into approval_requests ({columns}) values ({marks})", tuple(item.values()))
        connection.commit()
    finally:
        connection.close()


def run(scenario: dict[str, object]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="native-review-consume-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        insert(path, scenario["rows"])  # type: ignore[arg-type]
        calls: list[dict[str, object]] = []
        for index, args in enumerate(scenario["calls"]):  # type: ignore[arg-type]
            result = store.consume_native_review_approval(**args)
            calls.append(
                {
                    "args": args,
                    "result": result,
                    "effects": [
                        {("effect_digest" if k == "effect_key" else k): v for k, v in row.items()}
                        for row in dump(path, "guard_continuation_effects", "effect_key")
                    ],
                }
            )
            if index == 0 and "after_first_call_rows" in scenario:
                insert(path, scenario["after_first_call_rows"])  # type: ignore[arg-type]
        return {
            "name": scenario["name"],
            "native_may_deny": bool(scenario.get("native_may_deny")),
            "rows": scenario["rows"],
            "after_first_call_rows": scenario.get("after_first_call_rows", []),
            "calls": calls,
        }


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="native-review-consume-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path)
        connection = sqlite3.connect(path)
        # Tables and indexes only: the resident test seeds a trigger-free copy.
        schema = [
            item[0]
            for item in connection.execute(
                "select sql from sqlite_master where sql is not null and type in ('table','index') "
                "and tbl_name in ('approval_requests','guard_continuation_effects') order by type desc, rowid"
            )
        ]
        connection.close()
    document = {
        "schema": "guard-store-native-review-consume-vectors.v1",
        "schema_sql": schema,
        "scenarios": [run(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
