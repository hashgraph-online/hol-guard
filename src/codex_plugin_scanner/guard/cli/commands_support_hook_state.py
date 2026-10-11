"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..native_hook_authority_state import flag_field, hook_authority_state, keys_field, object_field

if TYPE_CHECKING:
    from ._commands_shared import (
        _CLAUDE_GUARD_APPROVAL_HEADER,
        _CLAUDE_GUARD_APPROVAL_OPTIONS,
        _hook_command_text,
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


def _update_codex_browser_operation_status(
    response_payload: dict[str, object],
    daemon_client: object | None,
    status: str,
) -> None:
    operation_id = response_payload.get("operation_id")
    if daemon_client is None or not isinstance(operation_id, str) or not operation_id:
        return
    update_operation_status = getattr(daemon_client, "update_operation_status", None)
    if not callable(update_operation_status):
        return
    with suppress(Exception):
        update_operation_status(operation_id=operation_id, status=status)


def _should_emit_prequeue_native_hook_response(
    args: argparse.Namespace,
    *,
    output_stream: TextIO | None,
    event_name: str | None = None,
) -> bool:
    if _canonical_harness_name(args.harness) != "claude-code":
        return False
    if not getattr(args, "json", False):
        return True
    if event_name == "UserPromptSubmit":
        # Prompt submits keep the composed envelope surface under --json so
        # approval state, risk detail, and the decision copy stay together.
        return False
    return output_stream is not None


def _emit_claude_permission_request_passthrough(*, output_stream: TextIO | None = None) -> None:
    if output_stream is not None:
        output_stream.write("")


def _claude_permission_notice_state_key(session_id: str, tool_name: str | None = None) -> str:
    if tool_name is not None:
        return f"claude_permission_notice:{session_id}:{tool_name}"
    return f"claude_permission_notice:{session_id}"


def _claude_pending_permission_index_key(session_id: str) -> str:
    return f"claude_pending_permissions:{session_id}"


def _claude_pending_permission_state_key(session_id: str, artifact_id: str) -> str:
    fingerprint = hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:24]
    return f"claude_pending_permission:{session_id}:{fingerprint}"


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
    pending_key: str,
    expected_artifact_id: str | None = None,
    expected_artifact_hash: str | None = None,
    expected_command: str | None = None,
    now: str | None = None,
) -> dict[str, object] | None:
    reply = hook_authority_state(
        store,
        "claude_load_pending",
        now=_state_now(now),
        session_id=session_id,
        pending_key=pending_key,
        expected_artifact_id=expected_artifact_id,
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


def _load_claude_pending_permission(
    store: GuardStore,
    payload: dict[str, object],
    artifact: GuardArtifact,
    artifact_hash: str,
) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    pending_key = _claude_pending_permission_state_key(session_id, artifact.artifact_id)
    return _load_verified_claude_pending_permission(
        store,
        session_id=session_id,
        pending_key=pending_key,
        expected_artifact_id=artifact.artifact_id,
        expected_artifact_hash=artifact_hash,
        expected_command=_claude_artifact_command_binding(artifact),
    )


def _remove_claude_pending_permission(
    store: GuardStore,
    *,
    session_id: str,
    pending_key: str,
) -> None:
    hook_authority_state(
        store,
        "claude_remove_pending",
        now=_now(),
        session_id=session_id,
        pending_key=pending_key,
    )


def _cursor_conversation_id(payload: dict[str, object]) -> str | None:
    for key in ("conversation_id", "conversationId", "session_id", "sessionId"):
        value = _optional_string(payload.get(key))
        if value is not None:
            return value
    for env_key in ("CURSOR_SESSION_ID", "CURSOR_TRACE_ID"):
        value = _optional_string(os.environ.get(env_key))
        if value is not None:
            return value
    return None


def _cursor_shell_command_from_payload(payload: Mapping[str, object]) -> str | None:
    from ..adapters.cursor_native_approval import (
        cursor_hook_payload_is_mcp_execution,
        is_shell_wrapper_command,
        normalize_cursor_shell_command,
    )

    tool_input_command = _hook_command_text(payload)
    top_level = _optional_string(payload.get("command"))
    if cursor_hook_payload_is_mcp_execution(payload):
        if tool_input_command is not None:
            return normalize_cursor_shell_command(tool_input_command)
        if top_level is not None:
            return normalize_cursor_shell_command(top_level)
        return None
    if tool_input_command is not None and (top_level is None or is_shell_wrapper_command(top_level)):
        return normalize_cursor_shell_command(tool_input_command)
    if top_level is not None:
        return normalize_cursor_shell_command(top_level)
    return None


def _cursor_shell_command_fingerprint(command: str) -> str:
    from ..adapters.cursor_native_approval import normalize_cursor_shell_command

    return hashlib.sha256(normalize_cursor_shell_command(command).encode("utf-8")).hexdigest()[:24]


def _cursor_pending_shell_index_key(conversation_id: str) -> str:
    return f"cursor_pending_shells:{conversation_id}"


def _cursor_pending_shell_state_key(conversation_id: str, command: str) -> str:
    return f"cursor_pending_shell:{conversation_id}:{_cursor_shell_command_fingerprint(command)}"


def _append_cursor_pending_shell_key(
    store: GuardStore,
    *,
    conversation_id: str,
    pending_key: str,
    now: str,
) -> bool:
    reply = hook_authority_state(
        store,
        "cursor_append_key",
        now=now,
        create_key=True,
        conversation_id=conversation_id,
        pending_key=pending_key,
    )
    return flag_field(reply, "stored")


def _load_cursor_pending_shell_index(
    store: GuardStore,
    *,
    conversation_id: str,
    now: str | None = None,
) -> list[str]:
    reply = hook_authority_state(
        store,
        "cursor_load_index",
        now=_state_now(now),
        conversation_id=conversation_id,
    )
    return keys_field(reply, "pending_keys")


def _store_cursor_pending_shell_index(
    store: GuardStore,
    *,
    conversation_id: str,
    pending_keys: Sequence[str],
    now: str,
) -> bool:
    reply = hook_authority_state(
        store,
        "cursor_store_index",
        now=now,
        create_key=bool(pending_keys),
        conversation_id=conversation_id,
        pending_keys=list(pending_keys),
    )
    return flag_field(reply, "stored")


def _store_cursor_pending_shell_state(
    store: GuardStore,
    *,
    conversation_id: str,
    command: str,
    payload: Mapping[str, object],
    now: str,
) -> bool:
    reply = hook_authority_state(
        store,
        "cursor_store_pending_state",
        now=now,
        create_key=True,
        conversation_id=conversation_id,
        state_key=_cursor_pending_shell_state_key(conversation_id, command),
        payload=dict(payload),
    )
    return flag_field(reply, "stored")


def _load_verified_cursor_pending_shell_state(
    store: GuardStore,
    *,
    conversation_id: str,
    command: str,
    state_key: str | None = None,
    now: str | None = None,
) -> dict[str, object] | None:
    from ..adapters.cursor_native_approval import normalize_cursor_shell_command

    normalized_command = normalize_cursor_shell_command(command)
    expected_key = _cursor_pending_shell_state_key(conversation_id, normalized_command)
    reply = hook_authority_state(
        store,
        "cursor_load_pending_state",
        now=_state_now(now),
        conversation_id=conversation_id,
        command=normalized_command,
        state_key=state_key or expected_key,
        expected_key=expected_key,
    )
    return object_field(reply, "pending")


def _cursor_native_shell_allow_state_key(conversation_id: str, command: str) -> str:
    return f"cursor_native_shell_allow:{conversation_id}:{_cursor_shell_command_fingerprint(command)}"


def _cursor_after_shell_observed(payload: Mapping[str, object]) -> bool:
    event_name = (_hook_event_name(payload) or "").strip().lower()
    duration = payload.get("duration")
    if isinstance(duration, (int, float)) and not isinstance(duration, bool):
        return duration >= 0
    if event_name == "aftermcpexecution":
        result_json = payload.get("result_json")
        return isinstance(result_json, str) and bool(result_json.strip())
    output = payload.get("output")
    return isinstance(output, str)


def _record_cursor_native_shell_allow_state(
    *,
    store: GuardStore,
    conversation_id: str,
    command: str,
    artifact: GuardArtifact,
    artifact_hash: str,
    now: str,
) -> bool:
    from ..adapters.cursor_native_approval import normalize_cursor_shell_command

    normalized_command = normalize_cursor_shell_command(command)
    reply = hook_authority_state(
        store,
        "cursor_record_allow",
        now=now,
        create_key=True,
        conversation_id=conversation_id,
        state_key=_cursor_native_shell_allow_state_key(conversation_id, normalized_command),
        command=normalized_command,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        artifact_name=artifact.name,
    )
    return flag_field(reply, "stored")


def _load_cursor_native_shell_allowance(
    store: GuardStore,
    payload: Mapping[str, object],
) -> dict[str, object] | None:
    conversation_id = _cursor_conversation_id(dict(payload))
    command = _cursor_shell_command_from_payload(payload)
    if conversation_id is None or command is None:
        return None
    reply = hook_authority_state(
        store,
        "cursor_load_allowance",
        now=_now(),
        conversation_id=conversation_id,
        command=command,
        state_key=_cursor_native_shell_allow_state_key(conversation_id, command),
    )
    return object_field(reply, "allowance")


def _cursor_native_shell_is_approved(
    store: GuardStore,
    payload: Mapping[str, object],
) -> bool:
    return _load_cursor_native_shell_allowance(store, payload) is not None


__all__ = [
    "_append_cursor_pending_shell_key",
    "_claude_guard_approval_question_text",
    "_claude_pending_permission_index_key",
    "_claude_pending_permission_state_key",
    "_claude_permission_notice_state_key",
    "_cursor_after_shell_observed",
    "_cursor_conversation_id",
    "_cursor_native_shell_allow_state_key",
    "_cursor_native_shell_is_approved",
    "_cursor_pending_shell_index_key",
    "_cursor_pending_shell_state_key",
    "_cursor_shell_command_fingerprint",
    "_cursor_shell_command_from_payload",
    "_emit_claude_permission_request_passthrough",
    "_load_claude_pending_permission",
    "_load_claude_pending_permission_index",
    "_load_claude_permission_notice",
    "_load_cursor_native_shell_allowance",
    "_load_cursor_pending_shell_index",
    "_load_single_claude_pending_permission",
    "_load_verified_claude_pending_permission",
    "_load_verified_cursor_pending_shell_state",
    "_mark_claude_pending_permission_prompt_seen",
    "_peek_claude_permission_notice",
    "_record_claude_permission_notice",
    "_record_cursor_native_shell_allow_state",
    "_remove_claude_pending_permission",
    "_should_emit_prequeue_native_hook_response",
    "_store_cursor_pending_shell_index",
    "_store_cursor_pending_shell_state",
    "_update_codex_browser_operation_status",
]
