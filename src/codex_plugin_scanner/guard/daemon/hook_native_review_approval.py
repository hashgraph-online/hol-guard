"""Queue native PreToolUse pauses while Rust remains the semantic authority."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import uuid
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..models import GuardAction, GuardApprovalRequest, format_local_http_origin
from ..runtime.native_cloud_review_origin import (
    NATIVE_CLOUD_REVIEW_ORIGIN_FIELD,
    NATIVE_CLOUD_REVIEW_ORIGIN_QUEUE_PREFIX,
    NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD,
    frozen_native_approval_origin,
    native_approval_origins_match,
)
from .hook_native_review_binding import (
    native_review_claimed_allow,
    native_review_matching_allow,
    native_review_policy_binding,
)
from .hook_native_review_command import (
    _native_review_artifact_id,
    _native_review_binding,
)
from .hook_native_review_origin import (
    _native_cloud_review_origin,
    _native_origin_unavailable,
    _native_review_action_envelope,
)
from .hook_native_review_wait import _bind_live_codex_hook_wait, _live_codex_wait
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import (
    harness_json_from_native_pre_tool,
    harness_json_from_native_pre_tool_review,
)

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

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
    home_dir: Path | None = None,
    deadline: float | None = None,
    claim_saved_approval: bool = True,
    claimed_saved_allow_hash: str | None = None,
    claimed_approval_request_id: str | None = None,
) -> dict[str, object]:
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
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
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    identity = _native_review_binding(
        harness,
        payload,
        native_result,
        native_receipt,
        workspace,
    )
    if claimed_saved_allow_hash is not None and native_review_claimed_allow(
        store,
        harness=harness,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        workspace=workspace,
        identity=identity,
        claimed_saved_allow_hash=claimed_saved_allow_hash,
        claimed_approval_request_id=claimed_approval_request_id,
        claim_saved_approval=claim_saved_approval,
        fresh_receipt=native_receipt,
    ):
        allowed = dict(native_result)
        allowed["decision"] = "allow"
        allowed["minimum_action"] = "allow"
        allowed["policy_action"] = "allow"
        response = harness_json_from_native_pre_tool(harness, allowed)
        response["approval_reuse_status"] = "accepted"
        return response
    if claim_saved_approval and native_review_matching_allow(
        store,
        harness=harness,
        tool_name=tool_name,
        artifact_id=_native_review_artifact_id(harness, tool_name),
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
    from ..blocked_request_mode import asks_for_approval, safe_alternative_reason
    from ..config import load_guard_config

    try:
        ask = asks_for_approval(load_guard_config(guard_home, workspace=workspace))
    except (OSError, RuntimeError, TypeError, ValueError):
        ask = False
    if not ask:
        # The agent stays on the silent block. The inbox row is a separate record.
        queued = queue_native_pre_tool_review(
            store,
            harness=harness,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            guard_home=guard_home,
            home_dir=home_dir,
            deadline=deadline,
        )
        if queued is None:
            _LOGGER.warning("Silent review blocked without an inbox row for %s", harness)
        else:
            _record_silent_native_review_event(store, queued)
        blocked = dict(native_result)
        blocked.update(
            decision="deny",
            minimum_action="block",
            policy_action="block",
            reason=safe_alternative_reason(str(native_result.get("reason") or "HOL Guard blocked this action.")),
        )
        response = harness_json_from_native_pre_tool(harness, blocked)
        response["prompted"] = False
        response["blocked_request_mode"] = "safe-alternative"
        return response

    queued = queue_native_pre_tool_review(
        store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        guard_home=guard_home,
        home_dir=home_dir,
        deadline=deadline,
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


def _record_silent_native_review_event(store: object, queued: Mapping[str, object]) -> None:
    """Write the local creation event for a silent inbox row. Do not mark a prompt as shown."""

    add_event = getattr(store, "add_event", None)
    if not callable(add_event):
        return
    created_at = queued.get("created_at")
    timestamp = created_at if isinstance(created_at, str) and created_at else datetime.now(tz=timezone.utc).isoformat()
    try:
        add_event(
            "approval.created",
            {
                "request_id": queued.get("request_id"),
                "harness": queued.get("harness"),
                "artifact_id": queued.get("artifact_id"),
                "artifact_name": queued.get("artifact_name"),
                "artifact_type": queued.get("artifact_type"),
                "policy_action": queued.get("policy_action"),
                "recommended_scope": queued.get("recommended_scope"),
                "source_scope": queued.get("source_scope"),
                "workspace": queued.get("workspace"),
                "publisher": queued.get("publisher"),
            },
            timestamp,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Silent review inbox row saved without approval.created (%s)", type(error).__name__)


def queue_native_pre_tool_review(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
    except ValueError:
        return None
    persist = getattr(store, "add_approval_request", None)
    lookup = getattr(store, "get_approval_request", None)
    if not callable(persist) or not callable(lookup):
        return None
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    native_origin, native_origin_unavailable = _native_cloud_review_origin(
        guard_home=guard_home,
        harness=harness,
        native_result=native_result,
        native_receipt=native_receipt,
    )
    request_id = str(native_origin["request_id"]) if native_origin is not None else uuid.uuid4().hex
    if native_origin is not None:
        try:
            existing = lookup(request_id)
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            return None
        if isinstance(existing, dict):
            if existing.get("status") == "pending" and native_approval_origins_match(
                frozen_native_approval_origin(existing), native_origin
            ):
                return existing
            # A pre-cutover or terminal row cannot acquire an eligible origin.
            native_origin = None
            native_origin_unavailable = _native_origin_unavailable(
                native_receipt, reason_code="native_cloud_review_original_snapshot_conflict"
            )
            request_id = uuid.uuid4().hex
    artifact_id = _native_review_artifact_id(harness, tool_name)
    approval_center_url = _native_review_approval_center_url(store)
    approval_url = f"{approval_center_url}/requests/{request_id}"
    reason = str(native_result.get("reason") or "HOL Guard requires review before this action can execute.")
    queued_at = datetime.now(tz=timezone.utc)
    live_wait = _live_codex_wait(harness=harness, payload=payload, request_id=request_id, now=queued_at)
    binding = _native_review_binding(harness, payload, native_result, native_receipt, workspace)
    try:
        action_envelope = _native_review_action_envelope(
            harness=harness,
            payload=payload,
            native_receipt=native_receipt,
            workspace=workspace,
            guard_home=guard_home,
            home_dir=home_dir,
            deadline=deadline,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
        # Never make an action approvable when its details could not be safely presented.
        # Exception messages can contain private tool input; log only the error class.
        _LOGGER.warning("Native review presentation failed for %s (%s)", request_id, type(error).__name__)
        return None
    if action_envelope is None:
        _LOGGER.warning("Native review presentation failed for %s (ValueError)", request_id)
        return None
    raw_command: str | None = None
    if native_origin is not None and isinstance(native_origin.get("command_sha256"), str):
        from ..memory_decision_outbox import NATIVE_MEMORY_SOURCE_BINDING_FIELD, native_memory_source_binding

        candidate = pre_tool_command(payload)
        source_binding = native_memory_source_binding(store)
        if (
            candidate is not None
            and source_binding is not None
            and hashlib.sha256(candidate.encode("utf-8")).hexdigest() == native_origin["command_sha256"]
            and native_origin.get("consent_revision") == source_binding["consent_revision"]
            and native_origin.get("revocation_epoch") == source_binding["revocation_epoch"]
        ):
            raw_command = candidate
            action_envelope[NATIVE_MEMORY_SOURCE_BINDING_FIELD] = source_binding
    policy_action: GuardAction = "review"
    if native_origin is not None:
        assert native_receipt is not None
        policy_action = cast(GuardAction, native_receipt["policy_action"])
        action_envelope["pre_execution_result"] = policy_action
        action_envelope[NATIVE_CLOUD_REVIEW_ORIGIN_FIELD] = deepcopy(native_origin)
        action_envelope["nativeApprovalChallenge"] = deepcopy(native_origin["challenge"])
    elif native_origin_unavailable is not None:
        action_envelope[NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD] = native_origin_unavailable
    request = GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=artifact_id,
        artifact_name=tool_name,
        artifact_hash=binding or request_id,
        policy_action=policy_action,
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="project" if workspace is not None else "harness",
        config_path=str(workspace if workspace is not None else guard_home),
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=approval_url,
        raw_command_text=raw_command,
        workspace=str(workspace) if workspace is not None else None,
        artifact_type="tool_call",
        launch_target=launch_target,
        risk_summary=reason,
        queue_group_id=NATIVE_CLOUD_REVIEW_ORIGIN_QUEUE_PREFIX + request_id if native_origin is not None else None,
        action_envelope_json=action_envelope,
        continuation_snapshot=None if live_wait is None else live_wait[0],
    )
    try:
        persisted_id = persist(request, datetime.now(tz=timezone.utc).isoformat())
        stored = lookup(persisted_id)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
    if not isinstance(stored, dict):
        return None
    _bind_live_codex_hook_wait(
        store,
        request_id=str(stored.get("request_id") or persisted_id),
        workspace=workspace,
        now=queued_at,
        live_wait=live_wait,
    )
    return stored


def record_claude_permission_notice_for_native_review(
    store: GuardStore,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
) -> None:
    """Persist the Claude permission-prompt notice for a queued native review."""
    from ..cli.commands_support_hook_state import _record_claude_permission_notice
    from ..models import GuardArtifact

    tool_name = _native_review_tool_name(payload)
    command = pre_tool_command(payload)
    artifact_id = _native_review_artifact_id(harness, tool_name)
    binding = _native_review_binding(harness, payload, native_result, native_receipt, workspace)
    metadata: dict[str, object] = {"raw_command_text": command} if command else {}
    artifact = GuardArtifact(
        artifact_id=artifact_id,
        name=tool_name,
        harness=harness,
        artifact_type="tool_call",
        source_scope="project" if workspace is not None else "harness",
        config_path=str(workspace if workspace is not None else guard_home),
        command=command,
        metadata=metadata,
    )
    _record_claude_permission_notice(
        store=store,
        payload=dict(payload),
        reason=str(native_result.get("reason") or "HOL Guard requires review before this action can execute."),
        artifact=artifact,
        artifact_hash=binding or artifact_id,
    )


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
    "record_claude_permission_notice_for_native_review",
]
