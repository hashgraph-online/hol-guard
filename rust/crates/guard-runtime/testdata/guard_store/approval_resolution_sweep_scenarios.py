"""Approval scope-sweep scenarios for `record_approval_resolution_sweep_vectors.py`.

Each scenario seeds `approval_requests` rows; every call runs against a fresh
copy of them, so one sweep never sees another's writes.
"""

from __future__ import annotations

import json

from approval_read_scenarios import DECISION, ROOT, row

HASH_A = "native-review-v4:" + "a" * 64
HASH_B = "native-review-v4:" + "b" * 64
BLOCK_DECISION = json.dumps({**json.loads(DECISION), "action": "block", "guard_action": "block"})
SANDBOX_DECISION = json.dumps(
    {**json.loads(DECISION), "action": "sandbox-required", "guard_action": "sandbox-required"}
)


def sweep(scope: str, **args: object) -> dict[str, object]:
    return {
        "harness": "codex",
        "scope": scope,
        "artifact_id": None,
        "artifact_hash": None,
        "workspace": None,
        "publisher": None,
        "resolution_action": "allow",
        "resolution_scope": scope,
        "reason": f"{scope} sweep",
        "resolved_at": "2026-03-02T10:00:00+00:00",
        **args,
    }


def seen(minute: int) -> str:
    return f"2026-03-01T11:{minute:02d}:00+00:00"


SCOPE_ROWS = [
    row("s-cmd-a", last_seen_at=seen(1)),
    row("s-cmd-b", artifact_hash=HASH_B, last_seen_at=seen(2)),
    row("s-cmd-claude", harness="claude", last_seen_at=seen(3)),
    row("s-tool-1", artifact_id="codex:native-pretool:tool-action:Bash", last_seen_at=seen(4)),
    row("s-tool-2", artifact_id="codex:native-pretool:tool-action:Bash", artifact_hash=HASH_B, last_seen_at=seen(5)),
    row("s-tool-other", artifact_id="codex:native-pretool:tool-action:Read", last_seen_at=seen(6)),
    row("s-tool-claude", harness="claude", artifact_id="claude:native-pretool:tool-action:Bash", last_seen_at=seen(7)),
    row("s-mcp-1", artifact_id="codex:project:mcp:github", last_seen_at=seen(8)),
    row("s-mcp-2", artifact_id="codex:user:MCP:slack", last_seen_at=seen(9)),
    row("s-mcp-tool", artifact_id="codex:project:mcp-tool:github", last_seen_at=seen(10)),
    row("s-family", artifact_id="family:mcp", last_seen_at=seen(11)),
    row("s-publisher", publisher="acme", last_seen_at=seen(12)),
    row("s-publisher-claude", harness="claude", publisher="acme", last_seen_at=seen(13)),
    row("s-block", policy_action="block", decision_v2_json=BLOCK_DECISION, last_seen_at=seen(14)),
    row("s-sandbox", policy_action="sandbox-required", decision_v2_json=SANDBOX_DECISION, last_seen_at=seen(15)),
    row("s-malformed", decision_v2_json="{bad", last_seen_at=seen(16)),
    row("s-unknown", policy_action="frobnicate", decision_v2_json=None, last_seen_at=seen(17)),
    row(
        "s-null-decision",
        policy_action="block",
        decision_v2_json=None,
        action_envelope_json=None,
        last_seen_at=seen(18),
    ),
    row("s-resolved", status="resolved", resolution_action="block", resolution_scope="artifact", last_seen_at=seen(19)),
    row("s-expired", status="expired", last_seen_at=seen(20)),
    row("s-tie-b", last_seen_at=seen(21)),
    row("s-tie-a", last_seen_at=seen(21)),
    row("s-no-seen", last_seen_at=None),
]
WORKSPACE_ROWS = [
    row("w-root-file", config_path=f"{ROOT}/proj", last_seen_at=seen(1)),
    row("w-nested", config_path=f"{ROOT}/proj/.codex/config.toml", last_seen_at=seen(2)),
    row("w-deep", config_path=f"{ROOT}/proj/a/b/c.json", artifact_hash=HASH_B, last_seen_at=seen(3)),
    row("w-sibling", config_path=f"{ROOT}/project/.codex/config.toml", last_seen_at=seen(4)),
    row("w-trailing", config_path=f" {ROOT}/proj/sub/// ", last_seen_at=seen(5)),
    row("w-backslash", config_path="C:\\Work\\Proj\\.codex\\config.toml", last_seen_at=seen(6)),
    row("w-drive-upper", config_path="D:/Repo/x.toml", last_seen_at=seen(7)),
    row("w-relative", config_path="proj/.codex/config.toml", last_seen_at=seen(8)),
    row("w-empty", config_path="", last_seen_at=seen(9)),
    row("w-blank", config_path="   ", last_seen_at=seen(10)),
    row("w-root", config_path="/etc/x.toml", last_seen_at=seen(11)),
    row(
        "w-tool",
        config_path=f"{ROOT}/proj/x",
        artifact_id="codex:native-pretool:tool-action:Bash",
        last_seen_at=seen(12),
    ),
    row("w-claude", harness="claude", config_path=f"{ROOT}/proj/x", last_seen_at=seen(13)),
    row(
        "w-block",
        config_path=f"{ROOT}/proj/y",
        policy_action="block",
        decision_v2_json=BLOCK_DECISION,
        last_seen_at=seen(14),
    ),
    row("w-malformed", config_path=f"{ROOT}/proj/z", decision_v2_json="{bad", last_seen_at=seen(15)),
    row("w-resolved", config_path=f"{ROOT}/proj/r", status="resolved", last_seen_at=seen(16)),
    row("w-unicode", config_path="/Ünï/proj/x", last_seen_at=seen(17)),
    row("w-colon", config_path="é:/x/y", last_seen_at=seen(18)),
]
TOOL = "codex:native-pretool:tool-action:Bash"
SCOPE_CALLS = [
    sweep("global", harness=None),
    sweep("global"),
    sweep("global", artifact_id="native-review:codex:cmd"),
    sweep("global", artifact_id="native-review:codex:cmd", artifact_hash=HASH_B),
    sweep("global", artifact_id=TOOL),
    sweep("global", artifact_id=TOOL, artifact_hash=HASH_B),
    sweep("global", artifact_id=" " + TOOL),
    sweep("global", artifact_id="family:mcp"),
    sweep("global", artifact_id="codex:project:mcp-tool:github", artifact_hash=HASH_A),
    sweep("global", artifact_id="missing"),
    sweep("harness"),
    sweep("harness", harness=None),
    sweep("harness", harness="claude"),
    sweep("harness", harness="nobody"),
    sweep("harness", artifact_id="native-review:codex:cmd"),
    sweep("harness", artifact_id="native-review:codex:cmd", artifact_hash=HASH_B),
    sweep("harness", artifact_id=TOOL),
    sweep("harness", artifact_id=TOOL, artifact_hash=HASH_A),
    sweep("harness", artifact_id="codex:project:mcp:github"),
    sweep("harness", artifact_id="codex:project:mcp:github", artifact_hash=HASH_B),
    sweep("harness", artifact_id="claude:user:mcp:other"),
    sweep("harness", artifact_id="family:mcp"),
    sweep("harness", artifact_id="family:MCP"),
    sweep("harness", artifact_id="family:unknown"),
    sweep("harness", artifact_id="codex:x:prompt-file:%"),
    sweep("harness", artifact_id="   "),
    sweep("artifact", artifact_id="native-review:codex:cmd"),
    sweep("artifact", artifact_id="native-review:codex:cmd", artifact_hash=HASH_A),
    sweep("artifact", artifact_id=TOOL),
    sweep("artifact", artifact_id=None),
    sweep("artifact", harness=None, artifact_id="native-review:codex:cmd"),
    sweep("publisher", publisher="acme"),
    sweep("publisher", publisher="acme", harness="claude"),
    sweep("publisher", publisher=None),
    sweep("publisher", harness=None, publisher="acme"),
    sweep("workspace", workspace=f"{ROOT}/proj"),
    sweep("bogus"),
    sweep("global", resolution_action="block", resolution_scope="workspace", reason=None),
]
WORKSPACE_CALLS = [
    sweep("workspace", workspace=f"{ROOT}/proj"),
    sweep("workspace", workspace=f"{ROOT}/proj/"),
    sweep("workspace", workspace=f"  {ROOT}/proj//  "),
    sweep("workspace", workspace=f"{ROOT}/pro"),
    sweep("workspace", workspace=f"{ROOT}/proj", artifact_id="native-review:codex:cmd"),
    sweep("workspace", workspace=f"{ROOT}/proj", artifact_id="native-review:codex:cmd", artifact_hash=HASH_B),
    sweep("workspace", workspace=f"{ROOT}/proj", artifact_hash=HASH_B),
    sweep("workspace", workspace=f"{ROOT}/proj", artifact_id=TOOL),
    sweep("workspace", workspace=f"{ROOT}/proj", harness="claude"),
    sweep("workspace", workspace=f"{ROOT}/proj", harness=None),
    sweep("workspace", workspace=None),
    sweep("workspace", workspace="c:\\work\\proj"),
    sweep("workspace", workspace="C:/WORK/PROJ/.codex"),
    sweep("workspace", workspace="d:/repo"),
    sweep("workspace", workspace="/"),
    sweep("workspace", workspace="//"),
    sweep("workspace", workspace=""),
    sweep("workspace", workspace="   "),
    sweep("workspace", workspace="proj"),
    sweep("workspace", workspace="/Ünï/proj"),
    sweep("workspace", workspace="/ünï/proj"),
    sweep("workspace", workspace="É:/X"),
    sweep("workspace", workspace="é:/x"),
]
BULK_ROWS = [
    row(f"b-{index:04d}", last_seen_at=f"2026-03-01T{index // 60:02d}:{index % 60:02d}:00+00:00")
    for index in range(1100)
] + [
    row("b-block", policy_action="block", decision_v2_json=BLOCK_DECISION),
    row("b-ws", config_path=f"{ROOT}/elsewhere/x"),
]
BULK_CALLS = [
    sweep("global"),
    sweep("workspace", workspace=f"{ROOT}/proj"),
]
FAILURE_ROWS = [
    row("f-ok", last_seen_at=seen(1)),
    row("f-surrogate", decision_v2_json='{"action": "ask", "s": "\\ud800"}', last_seen_at=seen(2)),
    row("f-ok-claude", harness="claude", last_seen_at=seen(3)),
]
FAILURE_CALLS = [
    sweep("global"),
    sweep("harness", harness="claude"),
    sweep("workspace", workspace=f"{ROOT}/proj"),
    sweep("workspace", workspace=f"{ROOT}/proj", harness="claude"),
]

SCENARIOS: list[dict[str, object]] = [
    {"name": "scopes", "rows": SCOPE_ROWS, "calls": SCOPE_CALLS},
    {"name": "workspaces", "rows": WORKSPACE_ROWS, "calls": WORKSPACE_CALLS},
    {"name": "bulk", "rows": BULK_ROWS, "calls": BULK_CALLS},
    {"name": "failures", "rows": FAILURE_ROWS, "calls": FAILURE_CALLS},
]
