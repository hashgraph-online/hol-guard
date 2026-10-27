"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from ..native_hook_authority_state import (
    hook_authority_state,
    keys_field,
    object_field,
)

if TYPE_CHECKING:
    from ._commands_shared import (
        _CLAUDE_GUARD_APPROVAL_HEADER,
        _CLAUDE_GUARD_APPROVAL_OPTIONS,
        _now,
    )


from ._commands_shared import *
from .commands_parser_helpers import *


def _runtime_artifacts_module():
    return importlib.import_module(".commands_support_runtime_artifacts", __package__)


def _runtime_policy_module():
    return importlib.import_module(".commands_support_runtime_policy", __package__)


def _runtime_resolution_module():
    return importlib.import_module(".commands_support_runtime_resolution", __package__)


def _optional_string(value: object) -> str | None:
    return _runtime_artifacts_module()._optional_string(value)


def _hook_event_name(payload: Mapping[str, object]) -> str:
    return _runtime_artifacts_module()._hook_event_name(payload)


def _claude_notification_tool_name(payload: dict[str, object]) -> str | None:
    return _runtime_policy_module()._claude_notification_tool_name(payload)


def _canonical_harness_name(value: str) -> str:
    return _runtime_resolution_module()._canonical_harness_name(value)


def _state_now(now: str | None) -> str:
    return now or _now()


def _load_claude_pending_permission_index(
    store: GuardStore,
    *,
    session_id: str,
    now: str | None = None,
) -> list[str]:
    reply = hook_authority_state(store, "claude_load_index", now=_state_now(now), session_id=session_id)
    return keys_field(reply, "pending_keys")


def _claude_guard_approval_question_text(approval_code: str) -> str:
    return f"HOL Guard intercepted this sensitive action (approval code: {approval_code}). What should Claude do?"


def _claude_artifact_command_binding(artifact: GuardArtifact) -> str:
    raw_command_text = artifact.metadata.get("raw_command_text")
    if isinstance(raw_command_text, str) and raw_command_text:
        return raw_command_text
    if isinstance(artifact.command, str) and artifact.command:
        return artifact.command
    return f"artifact:{artifact.artifact_id}"


def _load_verified_claude_pending_permission(
    store: GuardStore,
    *,
    session_id: str,
    artifact_id: str,
    expected_artifact_hash: str | None = None,
    expected_command: str | None = None,
    now: str | None = None,
) -> dict[str, object] | None:
    """The pending permission the resident holds for this session's artifact.

    The artifact id names the row: the resident derives its state key, so the
    key the row is stored under and the key it is looked up under come from one
    implementation.
    """

    reply = hook_authority_state(
        store,
        "claude_load_pending",
        now=_state_now(now),
        session_id=session_id,
        artifact_id=artifact_id,
        expected_artifact_hash=expected_artifact_hash,
        expected_command=expected_command,
    )
    return object_field(reply, "pending")


def _record_claude_permission_notice(
    *,
    store: GuardStore,
    payload: dict[str, object],
    reason: str,
    artifact: GuardArtifact,
    artifact_hash: str,
) -> None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return
    saved_at = _now()
    tool_name = _optional_string(payload.get("tool_name"))
    approval_code = secrets.token_hex(6)
    approval_question = _claude_guard_approval_question_text(approval_code)
    notice_payload: dict[str, object] = {
        "session_id": session_id,
        "saved_at": saved_at,
        "reason": reason,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "artifact_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "config_path": artifact.config_path,
        "source_scope": artifact.source_scope,
        "approval_header": _CLAUDE_GUARD_APPROVAL_HEADER,
        "approval_question": approval_question,
        "approval_options": list(_CLAUDE_GUARD_APPROVAL_OPTIONS),
        "approval_code": approval_code,
        "command": _claude_artifact_command_binding(artifact),
    }
    raw_command_text = artifact.metadata.get("raw_command_text")
    if isinstance(raw_command_text, str) and raw_command_text:
        notice_payload["raw_command_text"] = raw_command_text
    wrapper_chain = artifact.metadata.get("wrapper_chain")
    if isinstance(wrapper_chain, list):
        notice_payload["wrapper_chain"] = [item for item in wrapper_chain if isinstance(item, str) and item]
    if tool_name is not None:
        notice_payload["tool_name"] = tool_name
    hook_authority_state(
        store,
        "claude_record_notice",
        now=saved_at,
        create_key=True,
        session_id=session_id,
        tool_name=tool_name,
        payload=notice_payload,
    )


def _load_verified_claude_permission_notice(
    store: GuardStore,
    payload: dict[str, object],
) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    reply = hook_authority_state(
        store,
        "claude_load_notice",
        now=_now(),
        session_id=session_id,
        tool_name=_claude_notification_tool_name(payload),
    )
    return object_field(reply, "notice")


def _load_claude_permission_notice(store: GuardStore, payload: dict[str, object]) -> dict[str, object] | None:
    return _load_verified_claude_permission_notice(store, payload)


def _peek_claude_permission_notice(store: GuardStore, payload: dict[str, object]) -> dict[str, object] | None:
    return _load_verified_claude_permission_notice(store, payload)


def _mark_claude_pending_permission_prompt_seen(
    *,
    store: GuardStore,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> None:
    session_id = _optional_string(payload.get("session_id"))
    artifact_id = _optional_string((notice or {}).get("artifact_id"))
    if session_id is None or artifact_id is None:
        return
    artifact_hash = _optional_string((notice or {}).get("artifact_hash"))
    command = _optional_string((notice or {}).get("command"))
    if artifact_hash is None or command is None:
        return
    hook_authority_state(
        store,
        "claude_mark_prompt_seen",
        now=_now(),
        session_id=session_id,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        command=command,
    )


def _load_single_claude_pending_permission(
    store: GuardStore,
    payload: dict[str, object],
) -> tuple[str, dict[str, object]] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    reply = hook_authority_state(store, "claude_load_single_pending", now=_now(), session_id=session_id)
    pending = object_field(reply, "pending")
    pending_key = reply.get("pending_key") if reply is not None else None
    if pending is None or not isinstance(pending_key, str):
        return None
    return pending_key, pending


def _remove_claude_pending_permission(
    store: GuardStore,
    *,
    session_id: str,
    artifact_id: str,
) -> None:
    hook_authority_state(
        store,
        "claude_remove_pending",
        now=_now(),
        session_id=session_id,
        artifact_id=artifact_id,
    )


__all__ = [
    "_claude_guard_approval_question_text",
    "_load_claude_pending_permission_index",
    "_load_claude_permission_notice",
    "_load_single_claude_pending_permission",
    "_load_verified_claude_pending_permission",
    "_mark_claude_pending_permission_prompt_seen",
    "_peek_claude_permission_notice",
    "_record_claude_permission_notice",
    "_remove_claude_pending_permission",
]
