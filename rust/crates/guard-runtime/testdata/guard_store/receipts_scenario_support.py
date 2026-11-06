"""Builders shared by the receipt vector scenarios (executed on the ORIGINAL Python)."""

from __future__ import annotations

from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope

NOW = "2026-04-02T12:30:00.123456+00:00"
QUEUE_LIMIT = 3


def receipt(index: int, **overrides: object) -> GuardReceipt:
    fields: dict[str, object] = {
        "receipt_id": f"receipt-{index:03d}",
        "timestamp": f"2026-04-{(index % 5) + 1:02d}T0{index % 9}:15:00.000000+00:00",
        "harness": "codex",
        "artifact_id": f"artifact-{index % 3}",
        "artifact_hash": f"hash-{index}",
        "policy_decision": "allow",
        "capabilities_summary": "reads files",
        "changed_capabilities": ("file_read", "network"),
        "provenance_summary": "local",
    }
    fields.update(overrides)
    return GuardReceipt(**fields)  # type: ignore[arg-type]


def envelope(**overrides: object) -> GuardActionEnvelope:
    fields: dict[str, object] = {
        "schema_version": 1,
        "action_id": "",
        "harness": "codex",
        "event_name": "PreToolUse",
        "action_type": "shell_command",
        "workspace": "/work/project",
        "workspace_hash": "wh-1",
        "tool_name": "Bash",
        "command": "ls -la /tmp",
        "prompt_excerpt": None,
        "prompt_text": None,
        "target_paths": ("/tmp/a", "/tmp/b"),
        "network_hosts": ("example.com",),
        "mcp_server": None,
        "mcp_tool": None,
        "package_manager": None,
        "package_name": None,
    }
    fields.update(overrides)
    return GuardActionEnvelope(**fields)  # type: ignore[arg-type]


def approval_sql(
    request_id: str,
    *,
    status: str = "pending",
    policy_action: str = "review",
    resolution_action: str | None = None,
    resolved_at: str | None = None,
    decision_v2_json: str | None = None,
    action_envelope_json: str | None = None,
) -> tuple[str, list[object]]:
    return (
        "insert into approval_requests (request_id, harness, artifact_id, artifact_name, artifact_type, "
        "artifact_hash, policy_action, recommended_scope, changed_fields_json, source_scope, config_path, "
        "decision_v2_json, action_envelope_json, review_command, approval_url, status, resolution_action, "
        "created_at, resolved_at) values (?, 'codex', 'artifact-0', 'Artifact', 'tool', 'hash', ?, 'once', '[]', "
        "'project', '/cfg', ?, ?, 'hol-guard approvals', 'http://127.0.0.1/a', ?, ?, '2026-04-01T00:00:00+00:00', ?)",
        [request_id, policy_action, decision_v2_json, action_envelope_json, status, resolution_action, resolved_at],
    )


def step(method: str, *args: object, label: str = "", **kwargs: object) -> dict[str, object]:
    return {"label": label, "method": method, "args": args, "kwargs": kwargs}


def sql(label: str, *statements: tuple[str, list[object]]) -> dict[str, object]:
    return {"label": label, "sql": [list(item) for item in statements]}
