#!/usr/bin/env python3
"""Record policy decision source-context vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
in `store_policy_source_context.py`, never against the branch under test and
never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario seeds `runtime_receipts`, `artifact_inventory` and
`approval_requests` with deterministic pseudo-random rows, then records the
context `build_policy_source_context_index` plus `lookup_policy_source_context`
return for a batch of policy items. Timestamps are unique per table so the
"newest row" choice never depends on Python's set iteration order.
"""

from __future__ import annotations

import json
import os
import random
import sqlite3
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from codex_plugin_scanner.guard.store_policy_source_context import (
        build_policy_source_context_index,
        lookup_policy_source_context,
    )
except ImportError:
    sys.exit("refusing to record: the original Python policy source-context implementation is gone")

from vector_support import schema_sql_for_tables

from codex_plugin_scanner.guard.store import GuardStore

TABLES = ("runtime_receipts", "artifact_inventory", "approval_requests")
SCENARIOS = 160

HARNESSES = ("codex", "claude-code", "opencode", "cursor")
FAMILIES = ("package-request", "file-read", "prompt", "tool-action", "mcp", "prompt-env-read", "other", "")
LABELS = (
    None,
    "",
    "   ",
    "pnpm install lodash",
    "Run `npm test` in repo",
    "`git status` and `ls -la '2>'`",
    "credential-looking output",
    "Bash Secret-Looking command",
    "Package review",
    "Package `npm i` review",
    "family:package-request",
    "0123456789abcdef0123456789abcdef",
    "0123456789ABCDEF0123456789ABCDEF",
    "codex:project:0123456789abcdef",
    "codex:project:0123456789ABCDEF",
    "cat /etc/hosts 2>",
    "rg TODO '2>'",
    "2>",
    "approved in review",
    "Local E2E approval proof for build",
    "Package install via npm",
    "make build",
    "Ünïcode tool call",
)
PATHS = (
    None,
    "",
    "/srv/projects/hol-guard",
    "/srv/projects/hol-guard/",
    "/srv/projects/app/package.json",
    "~/code/demo",
    "~/code/demo/Cargo.TOML",
    "C:\\Users\\dev\\repo",
    "C:/Users/dev/repo/config.yaml",
    "workspace:abc123",
    "relative/path",
    "/",
    "//net/share/file.lock",
    "/a/b/.json",
    "/a/b/notes.",
    "/a/./b/../c/readme.md",
)
PROVENANCE = (
    None,
    "",
    "hook event for package install",
    "evaluated from /srv/projects/app/package.json",
    "Evaluated From ~/code/demo/pyproject.toml",
    "evaluated from C:/repo/settings.json",
    "evaluated from relative/thing.json",
    "evaluated from /srv/projects/plain/",
    "İstanbul evaluated from /srv/projects/istanbul/package.json",
)
REASONS = (
    None,
    "",
    "approved in review",
    "Approved in local approval center",
    "local auto-resume proof",
    "Always allow the deploy script",
    "  trusted build tool  ",
)


def scanner_evidence(rng: random.Random) -> str:
    choice = rng.randrange(9)
    if choice == 0:
        return "[]"
    if choice == 1:
        return "{not json"
    if choice == 2:
        return json.dumps({"package": {"redactedCommand": "pnpm add left-pad 2>", "packageManager": " pnpm "}})
    if choice == 3:
        return json.dumps([{"other": 1}, {"package": {"ecosystem": "npm"}}])
    if choice == 4:
        return json.dumps([{"package": {"redactedCommand": "uv pip install rich"}}])
    if choice == 5:
        return json.dumps([{"package": "not-a-dict"}, {"package": {"packageManager": "  ", "ecosystem": " pypi "}}])
    if choice == 6:
        return json.dumps({"package": {"redactedCommand": "", "packageManager": ""}})
    if choice == 7:
        return json.dumps([1, "x", {"package": {"redactedCommand": "credential-looking output", "ecosystem": "go"}}])
    return ""


def artifact_id(rng: random.Random) -> str:
    harness = rng.choice(HARNESSES)
    family = rng.choice(FAMILIES)
    if rng.random() < 0.1:
        return f"family:{family}" if family else "family:"
    if rng.random() < 0.1:
        return rng.choice(("plain-id", "two:parts", "None"))
    suffix = rng.choice(("alpha", "beta", "gamma"))
    scope = rng.choice(("project", "global"))
    return f"{harness}:{scope}:{family.upper() if rng.random() < 0.1 else family}:{suffix}"


def runtime_exact_key(value: str) -> str:
    return "runtime-exact:" + sha256(value.encode("utf-8")).hexdigest()


def artifact_hash(rng: random.Random, artifact: str) -> str:
    base = rng.choice(("abc123", "def456", "fedcba"))
    choice = rng.randrange(6)
    if choice == 0:
        return f"sha256:{base}"
    if choice == 1:
        return f"SHA256:{base.upper()}"
    if choice == 2:
        return runtime_exact_key(artifact)
    if choice == 3:
        return f"  {base}  "
    return base


def seed_rows(rng: random.Random, pool: list[str]) -> dict[str, list[dict[str, object]]]:
    receipts: list[dict[str, object]] = []
    inventory: dict[tuple[str, str], dict[str, object]] = {}
    approvals: list[dict[str, object]] = []
    stamps = rng.sample(range(10_000), 40)
    for index in range(rng.randrange(0, 12)):
        artifact = rng.choice(pool)
        receipts.append(
            {
                "receipt_id": f"receipt-{index}",
                "harness": rng.choice(HARNESSES),
                "artifact_id": artifact,
                "artifact_hash": artifact_hash(rng, artifact),
                "policy_decision": "allow",
                "capabilities_summary": rng.choice([label for label in LABELS if label is not None]),
                "changed_capabilities_json": "[]",
                "provenance_summary": rng.choice([value for value in PROVENANCE if value is not None]),
                "artifact_name": rng.choice(LABELS),
                "source_scope": rng.choice(PATHS),
                "scanner_evidence_json": scanner_evidence(rng),
                "timestamp": f"2026-06-14T{stamps[index] // 600:02d}:{stamps[index] % 600 // 10:02d}:0{index % 10}Z",
            }
        )
    for _ in range(rng.randrange(0, 6)):
        artifact = rng.choice(pool)
        harness = rng.choice(HARNESSES)
        inventory[(artifact, harness)] = {
            "artifact_id": artifact,
            "harness": harness,
            "artifact_name": rng.choice([label for label in LABELS if label is not None]),
            "artifact_type": "mcp_server",
            "source_scope": rng.choice([path for path in PATHS if path is not None]),
            "config_path": "/tmp/config.json",
            "launch_command": rng.choice(LABELS),
            "first_seen_at": "2026-06-01T00:00:00Z",
            "last_seen_at": "2026-06-01T00:00:00Z",
            "last_policy_action": "allow",
            "artifact_hash": "inventory-hash",
        }
    for index in range(rng.randrange(0, 10)):
        artifact = rng.choice(pool)
        stamp = stamps[20 + index]
        approvals.append(
            {
                "request_id": f"approval-{index}",
                "harness": rng.choice(HARNESSES),
                "artifact_id": artifact,
                "artifact_name": rng.choice([label for label in LABELS if label is not None]),
                "artifact_type": "mcp_server",
                "artifact_hash": artifact_hash(rng, artifact),
                "policy_action": "require-reapproval",
                "recommended_scope": "artifact",
                "changed_fields_json": "[]",
                "source_scope": "project",
                "config_path": "/tmp/config.json",
                "review_command": "hol-guard approvals",
                "approval_url": "http://127.0.0.1/approvals",
                "workspace": rng.choice(PATHS),
                "launch_target": rng.choice(LABELS),
                "trigger_summary": rng.choice(LABELS),
                "launch_summary": rng.choice(LABELS),
                "status": rng.choice(("resolved", "resolved", "pending")),
                "created_at": "2026-06-01T00:00:00Z",
                "resolved_at": None
                if rng.random() < 0.1
                else f"2026-06-15T{stamp // 600:02d}:{stamp % 600 // 10:02d}:1{index}Z",
                "resolution_scope": "artifact",
            }
        )
    return {
        "runtime_receipts": receipts,
        "artifact_inventory": list(inventory.values()),
        "approval_requests": approvals,
    }


def items(rng: random.Random, pool: list[str], seed: dict[str, list[dict[str, object]]]) -> list[dict[str, object]]:
    batch: list[dict[str, object]] = []
    stored = [row for table in seed.values() for row in table]
    for _ in range(rng.randrange(1, 6)):
        if stored and rng.random() < 0.6:
            row = rng.choice(stored)
            artifact = str(row["artifact_id"])
            harness = rng.choice((str(row["harness"]), "*", rng.choice(HARNESSES)))
            stored_hash = str(row["artifact_hash"])
            hashed = rng.choice(
                (stored_hash, stored_hash.strip().lower(), runtime_exact_key(artifact), None, "unmatched-hash")
            )
        else:
            artifact = rng.choice(pool)
            harness = rng.choice((*HARNESSES, "*"))
            hashed = rng.choice((None, artifact_hash(rng, artifact)))
        if rng.random() < 0.1:
            artifact = None
        batch.append(
            {
                "harness": harness,
                "artifact_id": artifact,
                "artifact_hash": hashed,
                "workspace": rng.choice(PATHS),
                "reason": rng.choice(REASONS),
            }
        )
    return batch


def insert(connection: sqlite3.Connection, table: str, rows: list[dict[str, object]]) -> None:
    for row in rows:
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        connection.execute(f"insert into {table} ({columns}) values ({placeholders})", tuple(row.values()))


def record(root: Path, schema: list[str], rng: random.Random, number: int) -> dict[str, object]:
    pool = [artifact_id(rng) for _ in range(5)]
    seed = seed_rows(rng, pool)
    batch = items(rng, pool, seed)
    connection = sqlite3.connect(root / f"scenario-{number}.db")
    connection.row_factory = sqlite3.Row
    try:
        for statement in schema:
            connection.execute(statement)
        for table, rows in seed.items():
            insert(connection, table, rows)
        index = build_policy_source_context_index(
            connection,
            items=[(item["harness"], item["artifact_id"], item["artifact_hash"]) for item in batch],
        )
        contexts = [
            lookup_policy_source_context(
                index,
                harness=item["harness"],
                artifact_id=item["artifact_id"],
                artifact_hash=item["artifact_hash"],
                workspace=item["workspace"],
                reason=item["reason"],
            )
            for item in batch
        ]
    finally:
        connection.close()
    return {"name": f"scenario-{number}", "seed": seed, "items": batch, "contexts": contexts}


def main(output: Path) -> None:
    rng = random.Random(4160)
    with tempfile.TemporaryDirectory(prefix="guard-policy-source-context-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        # Triggers on these tables write rollup tables this read never touches.
        schema = [
            statement
            for statement in schema_sql_for_tables(Path(store.path), TABLES)
            if not statement.lstrip().lower().startswith("create trigger")
        ]
        scenarios = [record(Path(root), schema, rng, number) for number in range(SCENARIOS)]
    document = {
        "schema": "guard-store-policy-source-context-vectors.v1",
        "source": "guard",
        "schema_sql": schema,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    matched = sum(1 for scenario in scenarios for context in scenario["contexts"] if context)
    print(f"wrote {len(scenarios)} scenarios ({matched} non-empty contexts) to {output}", file=sys.stderr)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
