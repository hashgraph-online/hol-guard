"""Queue native PreToolUse review pauses on the local approval center.

Rust remains the semantic authority. This helper only records a resolvable
request so the user can allow or deny an already-decided review.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import harness_json_from_native_pre_tool_review


def pause_native_pre_tool_for_approval(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    guard_home: Path,
) -> dict[str, object]:
    """Pause a native review result and attach any queued approval metadata."""

    queued: Mapping[str, object] | None = None
    with suppress(Exception):
        queued = queue_native_pre_tool_review(
            store,
            harness=harness,
            payload=payload,
            native_result=native_result,
            workspace=workspace,
            guard_home=guard_home,
        )
    return harness_json_from_native_pre_tool_review(harness, native_result, approval=queued)


def queue_native_pre_tool_review(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    guard_home: Path,
) -> dict[str, object] | None:
    """Persist one native review as an approval-center request."""

    from ..approvals import queue_blocked_approvals
    from ..models import GuardArtifact, HarnessDetection
    from ..store import GuardStore

    if not isinstance(store, GuardStore):
        return None
    launch_target = _native_review_launch_target(payload, native_result)
    tool_name = _native_review_tool_name(payload)
    identity = hashlib.sha256(
        "\0".join((harness, tool_name, launch_target)).encode("utf-8")
    ).hexdigest()
    artifact_id = f"{harness}:native-pretool:{identity[:16]}"
    config_path = str(workspace if workspace is not None else guard_home)
    artifact = GuardArtifact(
        artifact_id=artifact_id,
        name=tool_name,
        harness=harness,
        artifact_type="tool_call",
        source_scope="project" if workspace is not None else "harness",
        config_path=config_path,
        command=pre_tool_command(payload),
    )
    queued = queue_blocked_approvals(
        detection=HarnessDetection(
            harness=harness,
            installed=True,
            command_available=True,
            config_paths=(config_path,),
            artifacts=(artifact,),
        ),
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact_id,
                    "artifact_name": tool_name,
                    "artifact_hash": identity,
                    "artifact_type": "tool_call",
                    "source_scope": artifact.source_scope,
                    "config_path": config_path,
                    "changed_fields": ["native_pre_tool"],
                    "policy_action": "review",
                    "launch_target": launch_target,
                    "risk_summary": str(
                        native_result.get("reason") or "HOL Guard requires review before this action can execute."
                    ),
                    "workspace": str(workspace) if workspace is not None else None,
                }
            ]
        },
        store=store,
        approval_center_url=_native_review_approval_center_url(store),
    )
    if not queued:
        return None
    first = queued[0]
    return first if isinstance(first, dict) else None


def _native_review_approval_center_url(store: Any) -> str:
    from ..models import format_local_http_origin
    from .manager import DEFAULT_GUARD_DAEMON_PORT, read_approval_center_locator

    locator = read_approval_center_locator(store.guard_home)
    if locator is not None:
        base = locator.approval_url_base.strip()
        if base:
            return base.rstrip("/")
    state = store.get_runtime_state()
    if isinstance(state, dict):
        center = state.get("approval_center_url")
        if isinstance(center, str) and center.strip():
            return center.rstrip("/")
        host = state.get("daemon_host")
        port = state.get("daemon_port")
        if isinstance(host, str) and isinstance(port, int) and port > 0:
            return format_local_http_origin(host, port)
    return format_local_http_origin("127.0.0.1", DEFAULT_GUARD_DAEMON_PORT)


def _native_review_tool_name(payload: Mapping[str, object]) -> str:
    for key in ("tool_name", "toolName", "tool"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "tool"


def _native_review_launch_target(
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
) -> str:
    command = pre_tool_command(payload)
    if command is not None:
        return command
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping):
        for key in ("url", "path", "file_path", "target"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    reason = native_result.get("reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()
    return "native PreToolUse review"


__all__ = [
    "pause_native_pre_tool_for_approval",
    "queue_native_pre_tool_review",
]
