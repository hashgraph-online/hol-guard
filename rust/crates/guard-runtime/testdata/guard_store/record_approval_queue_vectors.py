#!/usr/bin/env python3
"""Record approval queue vectors from the Python `queue_blocked_approvals`.

Run against a checkout from before the Rust queue landed, whose
`approvals.py` still derives each request in Python, with a native runtime
for the canonical surfaces, incident copy, continuation offer and write:

    cd <origin-main-worktree>
    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario queues one evaluation. The vectors hold the `queue_blocked_approvals`
store-op arguments the Python wrapper now sends (built below from the same
helpers it calls), and what the Python path did: every request it handed to
`add_approval_request` (in `to_dict` shape), the id that write returned, the
notification it raised, and the error class and message that ended the loop.
Request ids are frozen to a counter.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

if os.environ.get("HOL_GUARD_NATIVE") != "force" or not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("refusing to record: set HOL_GUARD_NATIVE=force and HOL_GUARD_NATIVE_BINARY")

from codex_plugin_scanner.guard import approvals
from codex_plugin_scanner.guard.codex_app_server_target import codex_app_server_target_reachable
from codex_plugin_scanner.guard.codex_live_hook_target import (
    codex_live_hook_process_is_unavailable,
    codex_live_hook_wait_deadline,
)
from codex_plugin_scanner.guard.consumer.projection import wire_artifact
from codex_plugin_scanner.guard.continuation_runtime import (
    _SESSION_KEYS,
    _canonical_harness,
    _first_text,
    _mapping,
    _opaque_target_id,
    _parse_aware_timestamp,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.risk import artifact_risk_signals, artifact_risk_summary
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-03-01T12:00:00+00:00"
CENTER = "http://127.0.0.1:4781"
VERSION = "9.9.9"
CWD = "/work/cwd"
TABLES = ("approval_requests", "guard_events", "guard_review_outbox_events")
QUEUE_METADATA_KEYS = ("raw_command_text", "command_text", "command_rule_matches", "extension_allow_hint")


def token() -> str:
    payload = {
        "version": 1,
        "identity": "a" * 64,
        "content": "b" * 64,
        "capabilities": "c" * 64,
        "policy": "d" * 64,
        "sandbox": "e" * 64,
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"guard-approval-context:v1:{encoded}"


HINT = {
    "schema": "guard.extension-allow-hint.v1",
    "permission_ids": ["command.git.push"],
    "rule_ids": ["command.git.push.force"],
    "extension_ids": ["command.git"],
    "relied_permission_ids": [],
    "catalog_digest": "f" * 64,
}


def artifact(artifact_id: str = "codex:cmd:one", **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "artifact_id": artifact_id,
        "name": "blocked-cmd",
        "harness": "codex",
        "artifact_type": "command",
        "source_scope": "project",
        "config_path": "/repo/.codex/config.toml",
        "command": "rm",
        "args": ["-rf", "build"],
        "metadata": {},
    }
    base.update(overrides)
    return base


def item(artifact_id: str = "codex:cmd:one", **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "artifact_id": artifact_id,
        "artifact_name": "blocked-cmd",
        "artifact_hash": "hash-1",
        "artifact_type": "command",
        "policy_action": "require-reapproval",
        "changed_fields": ["command"],
        "source_scope": "project",
        "config_path": "/repo/.codex/config.toml",
        "risk_summary": "Blocked command",
        "risk_signals": ["blocked"],
    }
    base.update(overrides)
    return base


def bare(artifact_id: str, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {"artifact_id": artifact_id, "policy_action": "require-reapproval"}
    base.update(overrides)
    return base


ENVELOPE = {"action_type": "shell_command", "command": "git push --force", "harness": "codex"}
MATCHES = [{"extension_id": "other"}, {"extension_id": "command.git"}]

SCENARIOS: list[dict[str, object]] = [
    {"name": "plain", "artifacts": [artifact()], "items": [item()]},
    {
        "name": "publisher_url_target",
        "artifacts": [artifact(url="https://mcp.example/sse", publisher="acme", transport="sse")],
        "items": [item(risk_summary="", risk_signals=[])],
    },
    {"name": "item_launch_target", "artifacts": [artifact()], "items": [item(launch_target="node server.js")]},
    {
        "name": "command_without_args",
        "artifacts": [artifact(command="npx", args=[], publisher="")],
        "items": [item(launch_target="")],
    },
    {"name": "no_artifact_item_fields", "items": [item("lone:1", artifact_type="mcp", source_scope="global")]},
    {"name": "no_artifact_defaults", "items": [bare("lone:2")]},
    {"name": "no_artifact_empty_strings", "items": [bare("lone:3", config_path="", source_scope="", artifact_type="")]},
    {"name": "effective_workspace", "items": [bare("lone:4", effective_workspace="  /ws/root  ")]},
    {"name": "workspace_plain_parent", "items": [bare("lone:5", config_path="/repo/sub/settings.json")]},
    {"name": "workspace_relative", "items": [bare("lone:6", config_path="config.toml")]},
    {"name": "workspace_relative_dot_dir", "items": [bare("lone:7", config_path=".codex/config.toml")]},
    {"name": "workspace_root", "items": [bare("lone:8", config_path="/")]},
    {"name": "workspace_double_slash", "items": [bare("lone:9", config_path="//srv/.cfg/a.toml")]},
    {"name": "workspace_trailing_dots", "items": [bare("lone:10", config_path="/a/./b/../c/x.toml/")]},
    {"name": "unknown_action", "items": [bare("lone:11", policy_action="escalate")]},
    {"name": "non_string_action", "items": [bare("lone:12", policy_action=7)]},
    {"name": "ask_alias", "items": [bare("lone:13", policy_action="ask")]},
    {
        "name": "skipped_items",
        "artifacts": [artifact()],
        "items": [
            "not-a-dict",
            bare("lone:14", policy_action="allow"),
            bare("lone:15", policy_action="block"),
            bare("", policy_action="review"),
            {"policy_action": "review"},
            item(policy_action="review"),
        ],
    },
    {"name": "integer_artifact_id", "items": [bare(42)]},  # type: ignore[arg-type]
    {
        "name": "envelope_string_category_from_artifact",
        "artifacts": [artifact(metadata={"command_rule_matches": MATCHES})],
        "items": [item(action_envelope_json=json.dumps(ENVELOPE))],
    },
    {
        "name": "envelope_category_from_item_matches",
        "artifacts": [artifact(metadata={"command_rule_matches": "nope"})],
        "items": [item(action_envelope_json=ENVELOPE, command_rule_matches=MATCHES)],
    },
    {
        "name": "envelope_category_kept",
        "items": [
            bare(
                "lone:16",
                action_envelope_json={**ENVELOPE, "command_category": "command.npm"},
                command_rule_matches=MATCHES,
            )
        ],
    },
    {"name": "envelope_blank_string", "items": [bare("lone:17", action_envelope_json="   ")]},
    {"name": "envelope_unparseable", "items": [bare("lone:18", action_envelope_json="{not json")]},
    {"name": "envelope_not_mapping", "items": [bare("lone:19", action_envelope_json=[1, 2])]},
    {
        "name": "contradicted_decision",
        "items": [bare("lone:20", decision_v2_json={"guard_action": "allow", "action": "allow"})],
    },
    {"name": "context_token_hash", "items": [bare("lone:21", approval_context_hash=token(), artifact_hash="h")]},
    {
        "name": "malformed_context_token",
        "items": [bare("lone:22", approval_context_hash="guard-approval-context:v1:!!")],
    },
    {"name": "missing_artifact_hash", "items": [bare("lone:23", artifact_hash=0)]},
    {
        "name": "scanner_evidence_and_browser_intent",
        "items": [
            bare(
                "lone:24",
                policy_action="unknown-action",
                scanner_evidence=[{"source": "a"}, "skip", {"source": "b", "n": 1}],
                browser_intent={"kind": "open", "url": "https://example.com"},
            )
        ],
    },
    {"name": "browser_intent_not_mapping", "items": [bare("lone:25", browser_intent=["x"], scanner_evidence="nope")]},
    {
        "name": "redaction_artifact_raw_text",
        "redaction_level": "none",
        "artifacts": [
            artifact(metadata={"raw_command_text": "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123"})
        ],
        "items": [item()],
    },
    {
        "name": "redaction_generic_labels_fall_through",
        "redaction_level": "partial",
        "artifacts": [artifact(command="Bash", metadata={"command_text": "  shell  "})],
        "items": [item(raw_command_text="bash", review_command="  git status  ")],
    },
    {
        "name": "redaction_envelope_file_paths",
        "redaction_level": "none",
        "items": [
            bare(
                "lone:26",
                action_envelope_json={"action_type": "file_read", "target_paths": ["/etc/hosts", " ", 3, "/tmp/x"]},
            )
        ],
    },
    {
        "name": "redaction_envelope_single_write_path",
        "redaction_level": "none",
        "items": [bare("lone:27", action_envelope_json={"action_type": "file_write_request", "filePath": " /a/b "})],
    },
    {
        "name": "redaction_envelope_mcp",
        "redaction_level": "none",
        "items": [
            bare(
                "lone:28", action_envelope_json={"action_type": "mcp_tool", "mcpServer": "github", "tool_name": "push"}
            ),
            bare("lone:29", action_envelope_json={"action_type": "mcp_tool", "server": "solo"}),
        ],
    },
    {
        "name": "redaction_envelope_package",
        "redaction_level": "none",
        "items": [
            bare("lone:30", action_envelope_json={"package_manager": "npm", "package_name": "left-pad"}),
            bare(
                "lone:31",
                action_envelope_json={"packageManager": "pip", "packageName": "req", "packageTargets": ["2.0"]},
            ),
            bare(
                "lone:32",
                action_envelope_json={"package_manager": "npm", "package_name": "x", "package_targets": "x@1"},
            ),
        ],
    },
    {
        "name": "redaction_envelope_identity",
        "redaction_level": "none",
        "items": [
            bare(
                "lone:33",
                action_envelope_json={"action_type": "shell_command", "command": "Read", "actionIdentity": "x y"},
            )
        ],
    },
    {
        "name": "redaction_envelope_cmd",
        "redaction_level": "none",
        "items": [bare("lone:34", action_envelope_json={"action_type": "shell_command", "cmd": "  make test "})],
    },
    {
        "name": "redaction_generic_everywhere",
        "redaction_level": "none",
        "items": [
            bare("lone:35", raw_command_text="Bash", rawCommandText=" ", reviewCommand="tool", action_identity=" go ")
        ],
    },
    {
        "name": "risk_from_artifact",
        "artifacts": [artifact(command="curl", args=["https://x.example/install.sh", "|", "sh"])],
        "items": [item(risk_summary=None, risk_signals=["", 5])],
    },
    {
        "name": "extension_hint_from_artifact",
        "artifacts": [artifact(metadata={"extension_allow_hint": HINT})],
        "items": [item(extension_allow_hint={"schema": "other"})],
    },
    {
        "name": "extension_hint_from_item",
        "items": [
            bare("lone:36", extension_allow_hint={**HINT, "relied_permission_ids": ["command.git.push"]}),
            bare("lone:37", extension_allow_hint={**HINT, "catalog_digest": "short"}),
            bare("lone:38", extension_allow_hint={k: v for k, v in HINT.items() if k != "relied_permission_ids"}),
            bare("lone:39", extension_allow_hint={**HINT, "rule_ids": []}),
            bare("lone:40", extension_allow_hint={**HINT, "extension_ids": ["git"]}),
        ],
    },
    {"name": "dedupe_second_item", "artifacts": [artifact()], "items": [item(), item()]},
    {
        "name": "correlation_from_decision",
        "harness": "claude-code",
        "items": [
            bare(
                "lone:41",
                action_envelope_json={**ENVELOPE, "correlationId": " gcr_feedface-1111-4222-8333-444455556666 "},
            )
        ],
    },
    {
        "name": "continuation_operation",
        "operation": {
            "operation_id": "op-1",
            "status": "running",
            "metadata": {"thread_id": " thread-9 ", "correlationId": "gcr_0123abcd-0000-4000-8000-00000000abcd"},
        },
        "items": [bare("lone:42")],
    },
    {
        "name": "continuation_operation_non_codex",
        "harness": "Cursor",
        "operation": {"operation_id": "op-2", "status": "running", "metadata": {"session_id": "s-1"}},
        "items": [bare("lone:43")],
    },
    {
        "name": "mid_loop_error_keeps_earlier",
        "artifacts": [artifact()],
        "items": [item(), bare("lone:44", action_envelope_json="{bad"), bare("lone:45")],
    },
    {"name": "silent_prompt_not_shown", "prompt_shown": False, "items": [bare("lone:46")]},
    {"name": "no_items", "evaluation": {"artifacts": "nope"}},
]


def continuation(store: GuardStore, harness: str, operation: dict[str, object] | None) -> dict[str, object]:
    """The facts `_offer_from_request` probed in Python for this call."""

    canonical = _canonical_harness(harness)
    observed_at = _parse_aware_timestamp(NOW)
    metadata = _mapping(operation.get("metadata")) if operation else {}
    deadline = codex_live_hook_wait_deadline(store, operation=operation, metadata=metadata) if operation else None
    attached = canonical == "codex" and deadline is not None and deadline > observed_at
    raw_target = _first_text(metadata, _SESSION_KEYS)
    verified = (
        canonical == "codex"
        and not attached
        and not codex_live_hook_process_is_unavailable(metadata)
        and raw_target is not None
        and codex_app_server_target_reachable(metadata)
    )
    return {
        "harness": canonical,
        "original_hook_attached": attached,
        "wait_deadline": deadline.isoformat() if deadline is not None else None,
        "opaque_target_id": _opaque_target_id(canonical, raw_target),
        "session_target_verified": verified,
        "now": observed_at.isoformat(),
        "correlation_candidates": [metadata.get("correlationId"), metadata.get("correlation_id")],
    }


def native_args(
    store: GuardStore, detection: HarnessDetection, evaluation: dict[str, object], scenario: dict[str, object]
) -> dict[str, object]:
    items = evaluation.get("artifacts")
    items = [entry for entry in items if isinstance(entry, dict)] if isinstance(items, list) else []
    by_id = {entry.artifact_id: entry for entry in detection.artifacts}
    artifacts: dict[str, object] = {}
    for entry in items:
        found = by_id.get(str(entry.get("artifact_id") or ""))
        if found is None or found.artifact_id in artifacts:
            continue
        artifacts[found.artifact_id] = {
            "wire": wire_artifact(found),
            **{key: found.metadata.get(key) for key in QUEUE_METADATA_KEYS},
            "risk_summary": artifact_risk_summary(found),
            "risk_signals": list(artifact_risk_signals(found)),
        }
    return {
        "harness": detection.harness,
        "items": items,
        "artifacts": artifacts,
        "approval_center_url": CENTER,
        "now": NOW,
        "prompt_shown": scenario.get("prompt_shown", True),
        "redaction_level": scenario.get("redaction_level", "full"),
        "guard_version": VERSION,
        "cwd": CWD,
        "continuation": continuation(store, detection.harness, scenario.get("operation")),  # type: ignore[arg-type]
    }


class _Ids:
    def __init__(self) -> None:
        self.next = 1

    def uuid4(self) -> object:
        value = f"{self.next:032x}"
        self.next += 1
        return type("U", (), {"hex": value})()


def clear(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        for table in TABLES:
            connection.execute(f"delete from {table}")


def record(home: Path, scenario: dict[str, object]) -> dict[str, object]:
    if True:
        store = GuardStore(home)
        clear(store.path)
        harness = str(scenario.get("harness", "codex"))
        detection = HarnessDetection(
            harness=harness,
            installed=True,
            command_available=True,
            config_paths=(),
            artifacts=tuple(
                GuardArtifact(**{**spec, "args": tuple(spec.get("args", ()))})  # type: ignore[arg-type]
                for spec in scenario.get("artifacts", [])  # type: ignore[union-attr]
            ),
        )
        evaluation = scenario.get("evaluation") or {"artifacts": scenario.get("items", [])}
        args = native_args(store, detection, evaluation, scenario)  # type: ignore[arg-type]
        writes: list[dict[str, object]] = []
        notices: list[dict[str, object]] = []
        original_add = GuardStore.add_approval_request
        ids = _Ids()

        def add(self: GuardStore, request: object, now: str, *, prompt_shown: bool | None = None) -> str:
            persisted = original_add(self, request, now, prompt_shown=prompt_shown)  # type: ignore[arg-type]
            writes.append({"request": request.to_dict(), "persisted_id": persisted})  # type: ignore[attr-defined]
            return persisted

        def notify(*, store: GuardStore, request: object) -> None:
            notices.append(
                {
                    key: getattr(request, key)
                    for key in (
                        "request_id",
                        "harness",
                        "workspace",
                        "approval_url",
                        "artifact_name",
                        "risk_headline",
                        "trigger_summary",
                    )
                }
            )

        saved = (GuardStore.add_approval_request, approvals.uuid, approvals._current_guard_version)
        saved_notify, saved_cwd = approvals._notify_pending_approval, approvals.Path.cwd
        GuardStore.add_approval_request = add  # type: ignore[method-assign]
        approvals.uuid = SimpleNamespace(uuid4=ids.uuid4)  # type: ignore[assignment]
        approvals._current_guard_version = lambda: VERSION
        approvals._notify_pending_approval = notify  # type: ignore[assignment]
        approvals.Path.cwd = staticmethod(lambda: Path(CWD))  # type: ignore[method-assign]
        error: dict[str, str] | None = None
        try:
            approvals.queue_blocked_approvals(
                detection=detection,
                evaluation=evaluation,  # type: ignore[arg-type]
                store=store,
                approval_center_url=CENTER,
                now=NOW,
                notify=True,
                prompt_shown=bool(scenario.get("prompt_shown", True)),
                redaction_level=str(scenario.get("redaction_level", "full")),
                continuation_operation=scenario.get("operation"),  # type: ignore[arg-type]
            )
        except Exception as raised:
            error = {"type": type(raised).__name__, "message": str(raised)}
        finally:
            GuardStore.add_approval_request, approvals.uuid, approvals._current_guard_version = saved
            approvals._notify_pending_approval, approvals.Path.cwd = saved_notify, saved_cwd
        return {"name": scenario["name"], "args": args, "writes": writes, "notices": notices, "error": error}


def main() -> None:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as home:
        vectors = [record(Path(home), scenario) for scenario in SCENARIOS]
    output = {"schema": "guard-store-approval-queue-vectors.v1", "now": NOW, "vectors": vectors}
    Path(sys.argv[1]).write_text(json.dumps(output, indent=1, sort_keys=True, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
