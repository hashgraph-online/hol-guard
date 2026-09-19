"""Queue native PreToolUse review pauses on the local approval center.

Rust remains the semantic authority. This helper only records a resolvable
request so the user can allow or deny an already-decided review. Native-mode
approval reuse is bound to Rust-owned request evidence. Commands that can
execute mutable local code are not eligible for Python-side retry reuse.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ..live_process_identity import CODEX_BROWSER_WAIT_PROCESS_KEY, CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY
from ..models import GuardApprovalRequest, format_local_http_origin
from ..runtime.actions import normalize_harness_payload
from ..store import GuardStore
from .hook_native_review_binding import (
    NATIVE_REVIEW_BINDING_FIELD,
    NATIVE_REVIEW_REQUEST_DIGEST_FIELD,
    native_codex_request_digest,
    native_review_action_identity,
    native_review_policy_binding,
)
from .hook_native_review_continuation import attach_native_codex_wait, native_codex_wait_operation
from .hook_native_review_retry import (
    _command_reuse_is_payload_bound as _command_reuse_is_payload_bound,
)
from .hook_native_review_retry import _native_review_binding
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import (
    harness_json_from_native_pre_tool,
    harness_json_from_native_pre_tool_review,
)

_DEFAULT_APPROVAL_CENTER_PORT = 4781


def pause_native_pre_tool_for_approval(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
    verified_receipt: object = None,
    home_dir: Path | None = None,
    config_reader: Callable[[Path], dict[str, object]] | None = None,
) -> dict[str, object]:
    """Pause a native review result and attach any queued approval metadata."""

    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    try:
        binding = native_review_policy_binding(
            harness=harness, native_result=native_result, verified_receipt=verified_receipt
        )
    except ValueError:
        failed = dict(native_result)
        failed.update(
            decision="deny",
            minimum_action="block",
            policy_action="block",
            reason_code="native_review_policy_binding_invalid",
            reason="HOL Guard could not bind this review to its native policy.",
        )
        return harness_json_from_native_pre_tool(harness, failed)
    identity = _native_review_binding(harness, payload, native_result, native_receipt, workspace)
    live_codex_payload = harness == "codex" and (
        CODEX_BROWSER_WAIT_PROCESS_KEY in payload or CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY in payload
    )
    if not live_codex_payload and _native_review_matching_allow(
        store,
        harness=harness,
        tool_name=tool_name,
        launch_target=launch_target,
        workspace=workspace,
        policy_binding=binding,
        identity=identity,
    ):
        allowed = dict(native_result)
        allowed["decision"] = "allow"
        allowed["minimum_action"] = "allow"
        allowed["policy_action"] = "allow"
        response = harness_json_from_native_pre_tool(harness, allowed)
        response["approval_reuse_status"] = "accepted"
        return response
    queued = _queue_native_pre_tool_review(
        store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        guard_home=guard_home,
        policy_binding=binding,
        home_dir=home_dir,
        verified_receipt=verified_receipt,
        config_reader=config_reader,
    )
    if queued is None:
        failed = dict(native_result)
        failed["decision"] = "deny"
        failed["minimum_action"] = "block"
        failed["policy_action"] = "block"
        failed["reason_code"] = "native_review_queue_failed"
        failed["reason"] = "HOL Guard could not record this review for approval."
        return harness_json_from_native_pre_tool(harness, failed)
    response = harness_json_from_native_pre_tool_review(
        harness,
        native_result,
        approval=queued,
        guard_home=guard_home,
    )
    response["prompted"] = True
    response["approval_center_url"] = _native_review_approval_center_url(store)
    return response


def queue_native_pre_tool_review(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None = None,
    workspace: Path | None,
    guard_home: Path,
    verified_receipt: object = None,
    home_dir: Path | None = None,
    config_reader: Callable[[Path], dict[str, object]] | None = None,
) -> dict[str, object] | None:
    """Persist one native review as an approval-center request."""

    try:
        binding = native_review_policy_binding(
            harness=harness, native_result=native_result, verified_receipt=verified_receipt
        )
    except ValueError:
        return None
    return _queue_native_pre_tool_review(
        store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        guard_home=guard_home,
        policy_binding=binding,
        home_dir=home_dir,
        verified_receipt=verified_receipt,
        config_reader=config_reader,
    )


def _queue_native_pre_tool_review(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
    policy_binding: Mapping[str, object] | None,
    home_dir: Path | None,
    verified_receipt: object,
    config_reader: Callable[[Path], dict[str, object]] | None = None,
) -> dict[str, object] | None:
    persist = getattr(store, "add_approval_request", None)
    lookup = getattr(store, "get_approval_request", None)
    if not callable(persist) or not callable(lookup):
        return None
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    command = pre_tool_command(payload)
    now = datetime.now(tz=timezone.utc).isoformat()
    try:
        operation = native_codex_wait_operation(
            store,
            harness=harness,
            payload=payload,
            workspace=workspace,
            home_dir=home_dir,
            now=now,
            config_reader=config_reader,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
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
        action_identity=native_review_action_identity(
            tool_name=tool_name, launch_target=launch_target, binding=policy_binding
        ),
        action_envelope_json=_native_review_action_envelope(
            request_id=request_id,
            harness=harness,
            tool_name=tool_name,
            command=command,
            launch_target=launch_target,
            workspace=workspace,
            policy_binding=policy_binding,
        ),
    )
    try:
        if harness == "codex":
            envelope = normalize_harness_payload(
                harness, "PreToolUse", payload, workspace=workspace, home_dir=home_dir or guard_home.parent
            ).to_dict()
            envelope["pre_execution_result"] = "review"
            if policy_binding is not None:
                envelope[NATIVE_REVIEW_BINDING_FIELD] = dict(policy_binding)
            request_digest = native_codex_request_digest(native_result, verified_receipt)
            if request_digest is not None:
                envelope[NATIVE_REVIEW_REQUEST_DIGEST_FIELD] = request_digest
                # The local-once MAC binds this exact native request digest.
                if operation is not None:
                    request = replace(request, artifact_hash=request_digest)
            elif operation is not None:
                return None
            request = replace(request, action_envelope_json=envelope)
        if operation is not None and isinstance(store, GuardStore):
            from ..continuation_runtime import continuation_offer_payload

            request = replace(
                request,
                continuation_snapshot=continuation_offer_payload(
                    store,
                    request_row=request.to_dict(),
                    now=now,
                    headless=True,
                    operation=operation,
                    config_reader=config_reader,
                ),
                # Every live hook owns one exact request/authority. Pending queue
                # deduplication must never retarget or extend another waiter.
                action_identity=request_id,
            )
        persisted_id = persist(request, now)
        if operation is not None and isinstance(store, GuardStore):
            if not isinstance(persisted_id, str) or persisted_id != request_id:
                raise ValueError("native_codex_wait_request_deduplicated")
            attach_native_codex_wait(store, request_id=persisted_id, operation=operation, workspace=workspace, now=now)
        stored = lookup(persisted_id)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
    return stored if isinstance(stored, dict) else None


def _native_review_artifact_id(harness: str, tool_name: str) -> str:
    return f"{harness}:native-pretool:{tool_name}"


def _native_review_matching_allow(
    store: object,
    *,
    harness: str,
    tool_name: str,
    launch_target: str,
    workspace: Path | None,
    identity: str | None,
    policy_binding: Mapping[str, object] | None = None,
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
                policy_binding=policy_binding,
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
    policy_binding: Mapping[str, object] | None = None,
) -> dict[str, object]:
    host = urlparse(launch_target).hostname if "://" in launch_target else None
    if command is not None:
        action_type = "shell_command"
    elif host:
        action_type = "network_request"
    else:
        action_type = "mcp_tool"
    envelope: dict[str, object] = {
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
    if policy_binding is not None:
        envelope[NATIVE_REVIEW_BINDING_FIELD] = dict(policy_binding)
    return envelope


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
