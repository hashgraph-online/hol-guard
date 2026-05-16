"""Privacy-safe usage events for harness skills and MCP tools."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Mapping
from contextlib import suppress
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Literal

from .edge_events import build_harness_usage_event
from .runtime.actions import GuardActionEnvelope

if TYPE_CHECKING:
    from .store import GuardStore

UsageStatus = Literal["observed", "allowed", "blocked", "failed", "unknown"]
HarnessUsageEventKind = Literal["harness.mcp.used", "harness.skill.activated"]
HarnessUsageEventTuple = tuple[HarnessUsageEventKind, str, dict[str, object]]

_SKILL_ACTIVATION_KEYS = frozenset(
    {
        "activeskill",
        "activeskillid",
        "activeskillname",
        "activeskillpath",
        "activatedskill",
        "activatedskillid",
        "activatedskillname",
        "skillpath",
    }
)
_REQUEST_ID_KEYS = ("request_id", "requestId", "tool_call_id", "toolCallId", "call_id", "callId")
_SESSION_ID_KEYS = ("session_id", "sessionId", "conversation_id", "conversationId", "thread_id", "threadId")
_MAX_SKILL_SEARCH_DEPTH = 6


def record_harness_usage_events(
    *,
    store: GuardStore,
    action: GuardActionEnvelope | None,
    raw_payload: Mapping[str, object],
    occurred_at: str,
) -> int:
    """Queue cloud usage events without leaking prompt, args, output, or local paths."""

    if action is None:
        return 0
    events = _usage_events(action=action, raw_payload=raw_payload, occurred_at=occurred_at)
    if not events:
        return 0
    try:
        device_id = store.get_or_create_installation_id()
        workspace_id = store.get_cloud_workspace_id()
        for event_type, subject_id, payload in events:
            store.add_guard_event_v1(
                build_harness_usage_event(
                    event_type=event_type,
                    subject_id=subject_id,
                    occurred_at=occurred_at,
                    payload=payload,
                    device_id=device_id,
                    workspace_id=workspace_id,
                )
            )
        return len(events)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        with suppress(OSError, RuntimeError, ValueError, sqlite3.Error):
            store.add_event(
                "harness_usage_event_failed",
                {"error_type": type(error).__name__},
                occurred_at,
            )
    return 0


def _usage_events(
    *,
    action: GuardActionEnvelope,
    raw_payload: Mapping[str, object],
    occurred_at: str,
) -> list[HarnessUsageEventTuple]:
    events: list[HarnessUsageEventTuple] = []
    request_id = _string_from_keys(raw_payload, _REQUEST_ID_KEYS)
    session_id = _string_from_keys(raw_payload, _SESSION_ID_KEYS)
    base_payload = {
        "harness": action.harness,
        "eventName": action.event_name,
        "actionType": action.action_type,
        "workspaceHash": action.workspace_hash,
        "requestId": request_id,
        "sessionId": session_id,
        "status": _usage_status(action, raw_payload),
    }
    if action.action_type == "mcp_tool" and action.mcp_server is not None:
        subject_id = _subject_id(
            "mcp",
            action.harness,
            action.event_name,
            action.mcp_server,
            action.mcp_tool or "unknown",
            request_id or action.action_id,
            occurred_at,
        )
        payload = {
            **base_payload,
            "mcpServer": action.mcp_server,
            "mcpTool": action.mcp_tool,
            "toolName": action.tool_name,
        }
        events.append(("harness.mcp.used", subject_id, _compact_payload(payload)))
    skill = _skill_details(raw_payload)
    if skill is not None:
        subject_id = _subject_id(
            "skill",
            action.harness,
            action.event_name,
            skill.get("skillId") or skill.get("skillName") or "unknown",
            request_id or action.action_id,
            occurred_at,
        )
        payload = {**base_payload, **skill}
        events.append(("harness.skill.activated", subject_id, _compact_payload(payload)))
    return events


def _usage_status(action: GuardActionEnvelope, raw_payload: Mapping[str, object]) -> UsageStatus:
    explicit = _string_from_keys(
        raw_payload,
        ("policy_action", "policyAction", "permission_decision", "permissionDecision"),
    )
    if explicit in {"block", "deny", "sandbox-required", "require-reapproval"}:
        return "blocked"
    if explicit in {"allow", "approve", "approved", "warn"}:
        return "allowed"
    if action.event_name == "PostToolUseFailure":
        return "failed"
    if action.event_name == "PostToolUse":
        return "allowed"
    if action.event_name == "PreToolUse":
        return "observed"
    return "unknown"


def _skill_details(payload: Mapping[str, object]) -> dict[str, object] | None:
    found = _find_skill_value(payload)
    if found is None:
        return None
    key, value = found
    if isinstance(value, Mapping):
        name = _safe_label(_string_from_keys(value, ("name", "title", "slug", "id")))
        identifier = _safe_label(_string_from_keys(value, ("id", "skill_id", "skillId", "slug")))
        source = _safe_label(_string_from_keys(value, ("source", "provider", "runtime")))
        path_hash = _path_hash(_string_from_keys(value, ("path", "skill_path", "skillPath", "uri", "url")))
    else:
        label = _safe_label(str(value))
        name = label
        identifier = None if _normalized_key(key) in {"skillpath", "skilluri", "skillurl"} else label
        source = None
        path_hash = _path_hash(str(value)) if _normalized_key(key) in {"skillpath", "skilluri", "skillurl"} else None
    details: dict[str, object] = {}
    if name is not None:
        details["skillName"] = name
    if identifier is not None:
        details["skillId"] = identifier
    if source is not None:
        details["skillSource"] = source
    if path_hash is not None:
        details["skillPathHash"] = path_hash
    return details or None


def _find_skill_value(payload: object, *, depth: int = 0) -> tuple[str, object] | None:
    if depth > _MAX_SKILL_SEARCH_DEPTH:
        return None
    if isinstance(payload, list):
        for item in payload:
            nested = _find_skill_value(item, depth=depth + 1)
            if nested is not None:
                return nested
        return None
    if not isinstance(payload, Mapping):
        return None
    for key, value in payload.items():
        if not isinstance(key, str):
            continue
        if _normalized_key(key) in _SKILL_ACTIVATION_KEYS and isinstance(value, (str, Mapping)):
            if isinstance(value, str) and not value.strip():
                continue
            return key, value
        if isinstance(value, (Mapping, list)):
            nested = _find_skill_value(value, depth=depth + 1)
            if nested is not None:
                return nested
    return None


def _string_from_keys(payload: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _compact_payload(payload: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if value is not None}


def _safe_label(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if _looks_like_path(stripped):
        label = PureWindowsPath(stripped).name if "\\" in stripped else PurePosixPath(stripped).name
        stripped = label or "skill"
    return stripped[:120]


def _path_hash(value: str | None) -> str | None:
    if value is None or not _looks_like_path(value):
        return None
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _looks_like_path(value: str) -> bool:
    return value.startswith(("~", "/", "file:")) or "/" in value or "\\" in value


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _subject_id(*parts: str) -> str:
    clean_parts = [part for part in parts if part]
    return hashlib.sha256(":".join(clean_parts).encode("utf-8")).hexdigest()
