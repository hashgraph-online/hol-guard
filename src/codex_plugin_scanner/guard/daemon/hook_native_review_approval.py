"""Queue native PreToolUse review pauses on the local approval center.

Rust remains the semantic authority. This helper only records a resolvable
request so the user can allow or deny an already-decided review. Native-mode
approval reuse is bound to Rust-owned request evidence. Commands that can
execute mutable local code are not eligible for Python-side retry reuse.
"""

from __future__ import annotations

import re
import shlex
import sqlite3
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ..models import GuardApprovalRequest, format_local_http_origin
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import (
    harness_json_from_native_pre_tool,
    harness_json_from_native_pre_tool_review,
)

_DEFAULT_APPROVAL_CENTER_PORT = 4781
_MUTABLE_CODE_LAUNCHERS = {
    ".",
    "source",
    "sh",
    "bash",
    "dash",
    "ash",
    "zsh",
    "ksh",
    "fish",
    "node",
    "bun",
    "deno",
    "ruby",
    "perl",
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "yarn",
    "bunx",
    "make",
    "just",
    "task",
    "cargo",
    "uv",
    "uvx",
    "pipx",
}
_PYTHON_LAUNCHER = re.compile(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?$", re.IGNORECASE)
_DIRECT_REUSABLE_COMMANDS = {
    "cat",
    "head",
    "tail",
    "sed",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "stat",
    "wc",
    "base64",
    "xxd",
    "od",
    "hexdump",
    "strings",
}
_NATIVE_DIGEST = re.compile(r"[0-9a-f]{64}")
_NATIVE_IDENTITY_TOKEN = re.compile(r"[a-z0-9_-]{1,128}")


def pause_native_pre_tool_for_approval(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
) -> dict[str, object]:
    """Pause a native review result and attach any queued approval metadata."""

    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    identity = _native_review_binding(
        harness,
        payload,
        native_result,
        native_receipt,
        workspace,
    )
    if _native_review_matching_allow(
        store,
        harness=harness,
        tool_name=tool_name,
        launch_target=launch_target,
        workspace=workspace,
        identity=identity,
    ):
        allowed = dict(native_result)
        allowed["decision"] = "allow"
        allowed["minimum_action"] = "allow"
        allowed["policy_action"] = "allow"
        response = harness_json_from_native_pre_tool(harness, allowed)
        response["approval_reuse_status"] = "accepted"
        return response
    queued = queue_native_pre_tool_review(
        store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        guard_home=guard_home,
    )
    if queued is None:
        failed = dict(native_result)
        failed["decision"] = "deny"
        failed["minimum_action"] = "block"
        failed["policy_action"] = "block"
        failed["reason_code"] = "native_review_queue_failed"
        failed["reason"] = "HOL Guard could not record this review for approval."
        return harness_json_from_native_pre_tool(harness, failed)
    response = harness_json_from_native_pre_tool_review(harness, native_result, approval=queued)
    response["prompted"] = True
    return response


def queue_native_pre_tool_review(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
) -> dict[str, object] | None:
    """Persist one native review as an approval-center request."""

    persist = getattr(store, "add_approval_request", None)
    lookup = getattr(store, "get_approval_request", None)
    if not callable(persist) or not callable(lookup):
        return None
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    command = pre_tool_command(payload)
    request_id = uuid.uuid4().hex
    artifact_id = _native_review_artifact_id(harness, tool_name)
    approval_center_url = _native_review_approval_center_url(store)
    approval_url = f"{approval_center_url}/requests/{request_id}"
    reason = str(native_result.get("reason") or "HOL Guard requires review before this action can execute.")
    binding = _native_review_binding(harness, payload, native_result, native_receipt, workspace)
    request = GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=artifact_id,
        artifact_name=tool_name,
        artifact_hash=binding or request_id,
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


def _native_review_artifact_id(harness: str, tool_name: str) -> str:
    return f"{harness}:native-pretool:{tool_name}"


def _command_reuse_is_payload_bound(command: str) -> bool:
    """Allow retry reuse only when mutable local code cannot hide behind argv.

    This is intentionally narrower than command classification. It does not
    decide whether a command is safe; Rust already made that decision. It only
    decides whether the Rust request digest plus exact command shape is enough
    identity for a one-use retry. Script/interpreter/package invocations require
    native source-bound identity and are not reusable through this compatibility
    store.
    """

    if any(marker in command for marker in ("`", "$(", "${", "\n", "\r")):
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens:
        return False
    # Only one direct command is eligible. Pipelines, redirections and command
    # lists can hide additional mutable executables or script inputs.
    if any(token in {";", "&", "&&", "|", "||", "<", ">", "<<", ">>"} for token in tokens):
        return False
    # Leading environment assignments can change executable lookup or loader
    # behavior without changing the apparent command. They are never reusable.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
        return False
    executable = tokens[0]
    if "/" in executable or "\\" in executable or executable.startswith("."):
        return False
    basename = Path(executable).name.lower()
    if basename in _MUTABLE_CODE_LAUNCHERS or _PYTHON_LAUNCHER.fullmatch(basename):
        return False
    return basename in _DIRECT_REUSABLE_COMMANDS


def _native_review_binding(
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
) -> str | None:
    """Bind a short-lived retry to Rust-owned request and decision evidence."""

    command = pre_tool_command(payload)
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    if action_type == "package":
        return None
    if command is not None and not _command_reuse_is_payload_bound(command):
        return None
    if not isinstance(native_receipt, Mapping):
        return None
    if (
        native_receipt.get("schema") != "guard-native-hook-decision-receipt.v1"
        or native_receipt.get("version") != 1
        or native_receipt.get("authority") != "rust"
        or native_receipt.get("harness") != harness
        or native_receipt.get("event_name") != "PreToolUse"
        or native_receipt.get("workspace_bound") is not (workspace is not None)
    ):
        return None
    request_digest = native_receipt.get("request_digest")
    if not isinstance(request_digest, str) or _NATIVE_DIGEST.fullmatch(request_digest) is None:
        return None
    decision = str(native_result.get("decision") or "")
    minimum_action = str(native_result.get("minimum_action") or "")
    policy_action = str(native_result.get("policy_action") or "")
    reason_code = str(native_result.get("reason_code") or "")
    if (
        native_receipt.get("decision") != decision
        or native_receipt.get("policy_action") != policy_action
        or native_receipt.get("reason_code") != reason_code
    ):
        return None
    identity_tokens = (decision, minimum_action, policy_action, reason_code)
    if any(_NATIVE_IDENTITY_TOKEN.fullmatch(value) is None for value in identity_tokens):
        return None
    return ":".join(("native-review-v4", request_digest, *identity_tokens))


def _native_review_matching_allow(
    store: object,
    *,
    harness: str,
    tool_name: str,
    launch_target: str,
    workspace: Path | None,
    identity: str | None,
) -> bool:
    consume = getattr(store, "consume_native_review_approval", None)
    if not callable(consume) or identity is None or not launch_target:
        return False
    try:
        return (
            consume(
                harness=harness,
                artifact_id=_native_review_artifact_id(harness, tool_name),
                artifact_name=tool_name,
                artifact_hash=identity,
                launch_target=launch_target,
                workspace=str(workspace) if workspace is not None else None,
                now=datetime.now(tz=timezone.utc).isoformat(),
            )
            is True
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False


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
    if command is not None:
        action_type = "shell_command"
    elif host:
        action_type = "network_request"
    else:
        action_type = "mcp_tool"
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


def _native_review_launch_target(payload: Mapping[str, object]) -> str:
    command = pre_tool_command(payload)
    if command is not None:
        return command
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping):
        for key in ("url", "path", "file_path", "target"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return f"tool:{_native_review_tool_name(payload)}"


__all__ = [
    "pause_native_pre_tool_for_approval",
    "queue_native_pre_tool_review",
]
