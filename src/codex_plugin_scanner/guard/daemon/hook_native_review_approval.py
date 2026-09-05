"""Queue native PreToolUse review pauses on the local approval center.

Rust remains the semantic authority. This helper only records a resolvable
request so the user can allow or deny an already-decided review.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ..models import GuardApprovalRequest, format_local_http_origin
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import harness_json_from_native_pre_tool_review

_DEFAULT_APPROVAL_CENTER_PORT = 4781


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

    persist = getattr(store, "add_approval_request", None)
    lookup = getattr(store, "get_approval_request", None)
    if not callable(persist) or not callable(lookup):
        return None
    launch_target = _native_review_launch_target(payload, native_result)
    tool_name = _native_review_tool_name(payload)
    command = pre_tool_command(payload)
    request_id = uuid.uuid4().hex
    artifact_id = f"{harness}:native-pretool:{request_id[:16]}"
    approval_center_url = _native_review_approval_center_url(store)
    approval_url = f"{approval_center_url}/requests/{request_id}"
    reason = str(native_result.get("reason") or "HOL Guard requires review before this action can execute.")
    request = GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=artifact_id,
        artifact_name=tool_name,
        artifact_hash=request_id,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="project" if workspace is not None else "harness",
        config_path=str(workspace if workspace is not None else guard_home),
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=approval_url,
        workspace=str(workspace) if workspace is not None else None,
        artifact_type="tool_call",
        launch_target=launch_target,
        risk_summary=reason,
        action_envelope_json=_native_review_action_envelope(
            request_id=request_id,
            harness=harness,
            tool_name=tool_name,
            command=command,
            launch_target=launch_target,
            workspace=workspace,
        ),
    )
    try:
        persisted_id = persist(request, datetime.now(tz=timezone.utc).isoformat())
        stored = lookup(persisted_id)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
    return stored if isinstance(stored, dict) else None


def _native_review_action_envelope(
    *,
    request_id: str,
    harness: str,
    tool_name: str,
    command: str | None,
    launch_target: str,
    workspace: Path | None,
) -> dict[str, object]:
    host = urlparse(launch_target).hostname if "://" in launch_target else None
    action_type = "shell_command" if command is not None else "network_request" if host else "mcp_tool"
    return {
        "schema_version": 1,
        "action_id": request_id,
        "harness": harness,
        "event_name": "PreToolUse",
        "action_type": action_type,
        "workspace": str(workspace) if workspace is not None else None,
        "workspace_hash": None,
        "tool_name": tool_name,
        "command": command,
        "prompt_excerpt": None,
        "prompt_text": None,
        "target_paths": [],
        "network_hosts": [host] if isinstance(host, str) and host else [],
        "mcp_server": None,
        "mcp_tool": None,
        "package_manager": None,
        "package_name": None,
        "pre_execution_result": "review",
    }


def _native_review_approval_center_url(store: object) -> str:
    getter = getattr(store, "get_runtime_state", None)
    if callable(getter):
        try:
            state = getter()
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            state = None
        if isinstance(state, dict):
            center = state.get("approval_center_url")
            if isinstance(center, str) and center.strip():
                return center.rstrip("/")
            host = state.get("daemon_host")
            port = state.get("daemon_port")
            if isinstance(host, str) and isinstance(port, int) and port > 0:
                return format_local_http_origin(host, port)
    return format_local_http_origin("127.0.0.1", _DEFAULT_APPROVAL_CENTER_PORT)


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
