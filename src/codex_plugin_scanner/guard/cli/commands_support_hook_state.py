"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

from ..local_authority_integrity import sign_local_authority_payload, verify_local_authority_payload

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
) -> bool:
    if _canonical_harness_name(args.harness) != "claude-code":
        return False
    if not getattr(args, "json", False):
        return True
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


_CLAUDE_PENDING_PERMISSION_MAX_AGE_SECONDS = 30 * 60
_CLAUDE_NOTICE_INTEGRITY_PURPOSE = "claude-permission-notice"
_CLAUDE_PENDING_INTEGRITY_PURPOSE = "claude-pending-permission"
_CLAUDE_PENDING_INDEX_INTEGRITY_PURPOSE = "claude-pending-permission-index"
_CURSOR_PENDING_INTEGRITY_PURPOSE = "cursor-pending-shell"
_CURSOR_PENDING_INDEX_INTEGRITY_PURPOSE = "cursor-pending-shell-index"


def _hook_authority_state_is_fresh(
    payload: Mapping[str, object],
    *,
    now: str,
    max_age_seconds: int,
) -> bool:
    saved_at = _optional_string(payload.get("saved_at"))
    if saved_at is None:
        return False
    try:
        saved_time = datetime.fromisoformat(saved_at.replace("Z", "+00:00"))
        current_time = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except ValueError:
        return False
    if saved_time.tzinfo is None:
        saved_time = saved_time.replace(tzinfo=timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    age_seconds = (current_time - saved_time).total_seconds()
    return 0 <= age_seconds <= max_age_seconds


def _record_hook_authority_integrity_failure(
    store: GuardStore,
    *,
    harness: str,
    source: str,
    state_key: str,
    artifact_id: object,
    integrity_status: str,
    message: str | None,
    now: str,
) -> None:
    with suppress(OSError, sqlite3.Error):
        store.add_event(
            "rule.ignored.local_integrity",
            {
                "decision_id": None,
                "harness": harness,
                "artifact_id": artifact_id,
                "scope": "session",
                "source": source,
                "integrity_status": integrity_status,
                "message": message,
                "state_key_fingerprint": hashlib.sha256(state_key.encode("utf-8")).hexdigest()[:16],
            },
            now,
        )


def _delete_hook_authority_state(store: GuardStore, state_key: str) -> None:
    with suppress(OSError, sqlite3.Error):
        store.delete_sync_payload(state_key)


def _signed_hook_authority_payload(
    store: GuardStore,
    *,
    state_key: str,
    payload: Mapping[str, object],
    purpose: str,
    now: str,
) -> dict[str, object] | None:
    key, key_id = store._policy_integrity_secret_material(create=True)
    if key is None or key_id is None:
        return None
    signed_payload = {name: value for name, value in payload.items() if name != "integrity"}
    signed_payload["state_key"] = state_key
    signed_payload["integrity"] = sign_local_authority_payload(
        signed_payload,
        key=key,
        key_id=key_id,
        purpose=purpose,
        signed_at=now,
    )
    return signed_payload


def _store_signed_hook_authority_payload(
    store: GuardStore,
    *,
    state_key: str,
    payload: Mapping[str, object],
    purpose: str,
    now: str,
) -> bool:
    signed_payload = _signed_hook_authority_payload(
        store,
        state_key=state_key,
        payload=payload,
        purpose=purpose,
        now=now,
    )
    if signed_payload is None:
        return False
    try:
        store.set_sync_payload(state_key, signed_payload, now)
    except (OSError, sqlite3.Error):
        return False
    return True


def _load_verified_hook_authority_payload(
    store: GuardStore,
    *,
    state_key: str,
    purpose: str,
    harness: str,
    source: str,
    now: str,
    max_age_seconds: int,
) -> dict[str, object] | None:
    try:
        persisted = store.get_sync_payload(state_key)
    except (json.JSONDecodeError, TypeError, ValueError):
        _record_hook_authority_integrity_failure(
            store,
            harness=harness,
            source=source,
            state_key=state_key,
            artifact_id=None,
            integrity_status="tampered",
            message="local_authority_integrity_payload_invalid_json",
            now=now,
        )
        _delete_hook_authority_state(store, state_key)
        return None
    except (OSError, sqlite3.Error):
        return None
    if persisted is None:
        return None
    if not isinstance(persisted, dict):
        _record_hook_authority_integrity_failure(
            store,
            harness=harness,
            source=source,
            state_key=state_key,
            artifact_id=None,
            integrity_status="missing_integrity",
            message="local_authority_integrity_metadata_missing",
            now=now,
        )
        _delete_hook_authority_state(store, state_key)
        return None
    raw_integrity = persisted.get("integrity")
    integrity: Mapping[str, object] = (
        cast(Mapping[str, object], raw_integrity) if isinstance(raw_integrity, Mapping) else {}
    )
    signed_payload = {name: value for name, value in persisted.items() if name != "integrity"}
    key, key_id = store._policy_integrity_secret_material(create=False)
    integrity_result = verify_local_authority_payload(
        signed_payload,
        integrity,
        key=key,
        key_id=key_id,
        purpose=purpose,
    )
    context_matches = persisted.get("state_key") == state_key
    if integrity_result.status != "valid" or not context_matches:
        integrity_status = integrity_result.status if integrity_result.status != "valid" else "tampered"
        message = (
            integrity_result.message
            if integrity_result.status != "valid"
            else "local_authority_integrity_state_key_mismatch"
        )
        _record_hook_authority_integrity_failure(
            store,
            harness=harness,
            source=source,
            state_key=state_key,
            artifact_id=persisted.get("artifact_id"),
            integrity_status=integrity_status,
            message=message,
            now=now,
        )
        _delete_hook_authority_state(store, state_key)
        return None
    if not _hook_authority_state_is_fresh(persisted, now=now, max_age_seconds=max_age_seconds):
        with suppress(OSError, sqlite3.Error):
            store.add_event(
                "approval.pending_state_expired",
                {
                    "harness": harness,
                    "source": source,
                    "artifact_id": persisted.get("artifact_id"),
                    "state_key_fingerprint": hashlib.sha256(state_key.encode("utf-8")).hexdigest()[:16],
                },
                now,
            )
        _delete_hook_authority_state(store, state_key)
        return None
    return persisted


def _invalidate_hook_authority_context(
    store: GuardStore,
    *,
    state_key: str,
    payload: Mapping[str, object],
    harness: str,
    source: str,
    message: str,
    now: str,
) -> None:
    _record_hook_authority_integrity_failure(
        store,
        harness=harness,
        source=source,
        state_key=state_key,
        artifact_id=payload.get("artifact_id"),
        integrity_status="tampered",
        message=message,
        now=now,
    )
    _delete_hook_authority_state(store, state_key)


def _append_claude_pending_permission_key(
    store: GuardStore,
    *,
    session_id: str,
    pending_key: str,
    now: str,
) -> bool:
    pending_keys = _load_claude_pending_permission_index(store, session_id=session_id, now=now)
    if pending_key in pending_keys:
        return True
    pending_keys.append(pending_key)
    return _store_claude_pending_permission_index(
        store,
        session_id=session_id,
        pending_keys=pending_keys,
        now=now,
    )


def _load_claude_pending_permission_index(
    store: GuardStore,
    *,
    session_id: str,
    now: str | None = None,
) -> list[str]:
    current_time = now or _now()
    index_key = _claude_pending_permission_index_key(session_id)
    persisted = _load_verified_hook_authority_payload(
        store,
        state_key=index_key,
        purpose=_CLAUDE_PENDING_INDEX_INTEGRITY_PURPOSE,
        harness="claude-code",
        source="claude-pending-permission-index",
        now=current_time,
        max_age_seconds=_CLAUDE_PENDING_PERMISSION_MAX_AGE_SECONDS,
    )
    if persisted is None:
        return []
    pending_keys_value = persisted.get("pending_keys")
    expected_prefix = f"claude_pending_permission:{session_id}:"
    context_matches = (
        persisted.get("session_id") == session_id
        and isinstance(pending_keys_value, list)
        and all(isinstance(item, str) and item.startswith(expected_prefix) for item in pending_keys_value)
    )
    if not context_matches:
        _invalidate_hook_authority_context(
            store,
            state_key=index_key,
            payload=persisted,
            harness="claude-code",
            source="claude-pending-permission-index",
            message="local_authority_integrity_pending_index_context_mismatch",
            now=current_time,
        )
        return []
    return list(dict.fromkeys(cast(list[str], pending_keys_value)))


def _store_claude_pending_permission_index(
    store: GuardStore,
    *,
    session_id: str,
    pending_keys: Sequence[str],
    now: str,
) -> bool:
    index_key = _claude_pending_permission_index_key(session_id)
    if not pending_keys:
        _delete_hook_authority_state(store, index_key)
        return True
    return _store_signed_hook_authority_payload(
        store,
        state_key=index_key,
        payload={
            "session_id": session_id,
            "pending_keys": list(dict.fromkeys(pending_keys)),
            "saved_at": now,
        },
        purpose=_CLAUDE_PENDING_INDEX_INTEGRITY_PURPOSE,
        now=now,
    )


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
    current_time = now or _now()
    persisted = _load_verified_hook_authority_payload(
        store,
        state_key=pending_key,
        purpose=_CLAUDE_PENDING_INTEGRITY_PURPOSE,
        harness="claude-code",
        source="claude-pending-permission",
        now=current_time,
        max_age_seconds=_CLAUDE_PENDING_PERMISSION_MAX_AGE_SECONDS,
    )
    if persisted is None:
        return None
    artifact_id = _optional_string(persisted.get("artifact_id"))
    artifact_hash = _optional_string(persisted.get("artifact_hash"))
    command = _optional_string(persisted.get("command"))
    expected_key = _claude_pending_permission_state_key(session_id, artifact_id) if artifact_id is not None else None
    context_matches = (
        persisted.get("session_id") == session_id
        and artifact_id is not None
        and artifact_hash is not None
        and command is not None
        and pending_key == expected_key
        and (expected_artifact_id is None or artifact_id == expected_artifact_id)
        and (expected_artifact_hash is None or artifact_hash == expected_artifact_hash)
        and (expected_command is None or command == expected_command)
    )
    if context_matches:
        return persisted
    _invalidate_hook_authority_context(
        store,
        state_key=pending_key,
        payload=persisted,
        harness="claude-code",
        source="claude-pending-permission",
        message="local_authority_integrity_pending_context_mismatch",
        now=current_time,
    )
    return None


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
    notice_key = _claude_permission_notice_state_key(session_id, tool_name)
    pending_key = _claude_pending_permission_state_key(session_id, artifact.artifact_id)
    if not _store_signed_hook_authority_payload(
        store,
        state_key=pending_key,
        payload=notice_payload,
        purpose=_CLAUDE_PENDING_INTEGRITY_PURPOSE,
        now=saved_at,
    ):
        return
    if not _append_claude_pending_permission_key(
        store,
        session_id=session_id,
        pending_key=pending_key,
        now=saved_at,
    ):
        _delete_hook_authority_state(store, pending_key)
        return
    if not _store_signed_hook_authority_payload(
        store,
        state_key=notice_key,
        payload=notice_payload,
        purpose=_CLAUDE_NOTICE_INTEGRITY_PURPOSE,
        now=saved_at,
    ):
        _remove_claude_pending_permission(store, session_id=session_id, pending_key=pending_key)


def _load_verified_claude_permission_notice(
    store: GuardStore,
    payload: dict[str, object],
) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    tool_name = _claude_notification_tool_name(payload)
    now = _now()
    selected_tool_name = tool_name
    selected_key = _claude_permission_notice_state_key(session_id, selected_tool_name)
    persisted = _load_verified_hook_authority_payload(
        store,
        state_key=selected_key,
        purpose=_CLAUDE_NOTICE_INTEGRITY_PURPOSE,
        harness="claude-code",
        source="claude-permission-notice",
        now=now,
        max_age_seconds=_CLAUDE_PENDING_PERMISSION_MAX_AGE_SECONDS,
    )
    if persisted is None and tool_name is not None:
        selected_tool_name = None
        selected_key = _claude_permission_notice_state_key(session_id)
        persisted = _load_verified_hook_authority_payload(
            store,
            state_key=selected_key,
            purpose=_CLAUDE_NOTICE_INTEGRITY_PURPOSE,
            harness="claude-code",
            source="claude-permission-notice",
            now=now,
            max_age_seconds=_CLAUDE_PENDING_PERMISSION_MAX_AGE_SECONDS,
        )
    if persisted is None:
        return None
    artifact_id = _optional_string(persisted.get("artifact_id"))
    artifact_hash = _optional_string(persisted.get("artifact_hash"))
    command = _optional_string(persisted.get("command"))
    stored_tool_name = _optional_string(persisted.get("tool_name"))
    context_matches = (
        persisted.get("session_id") == session_id
        and artifact_id is not None
        and artifact_hash is not None
        and command is not None
        and stored_tool_name == selected_tool_name
    )
    if not context_matches:
        _invalidate_hook_authority_context(
            store,
            state_key=selected_key,
            payload=persisted,
            harness="claude-code",
            source="claude-permission-notice",
            message="local_authority_integrity_notice_context_mismatch",
            now=now,
        )
        return None
    assert artifact_id is not None
    assert artifact_hash is not None
    assert command is not None
    pending_key = _claude_pending_permission_state_key(session_id, artifact_id)
    pending = _load_verified_claude_pending_permission(
        store,
        session_id=session_id,
        pending_key=pending_key,
        expected_artifact_id=artifact_id,
        expected_artifact_hash=artifact_hash,
        expected_command=command,
        now=now,
    )
    if pending is None:
        _delete_hook_authority_state(store, selected_key)
        return None
    return persisted


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
    pending_key = _claude_pending_permission_state_key(session_id, artifact_id)
    artifact_hash = _optional_string((notice or {}).get("artifact_hash"))
    command = _optional_string((notice or {}).get("command"))
    if artifact_hash is None or command is None:
        return
    now = _now()
    pending = _load_verified_claude_pending_permission(
        store,
        session_id=session_id,
        pending_key=pending_key,
        expected_artifact_id=artifact_id,
        expected_artifact_hash=artifact_hash,
        expected_command=command,
        now=now,
    )
    if pending is None:
        return
    updated = dict(pending)
    updated["permission_prompt_seen"] = True
    updated["permission_prompt_seen_at"] = now
    _store_signed_hook_authority_payload(
        store,
        state_key=pending_key,
        payload=updated,
        purpose=_CLAUDE_PENDING_INTEGRITY_PURPOSE,
        now=now,
    )


def _load_single_claude_pending_permission(
    store: GuardStore,
    payload: dict[str, object],
) -> tuple[str, dict[str, object]] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    now = _now()
    pending_keys = _load_claude_pending_permission_index(store, session_id=session_id, now=now)
    pending_items: list[tuple[str, dict[str, object]]] = []
    for pending_key in pending_keys:
        pending = _load_verified_claude_pending_permission(
            store,
            session_id=session_id,
            pending_key=pending_key,
            now=now,
        )
        if pending is not None:
            pending_items.append((pending_key, pending))
    prompt_seen_items = [item for item in pending_items if item[1].get("permission_prompt_seen") is True]
    if len(prompt_seen_items) == 1:
        return prompt_seen_items[0]
    if len(pending_items) != 1:
        return None
    return pending_items[0]


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
    now = _now()
    _delete_hook_authority_state(store, pending_key)
    remaining = [
        key
        for key in _load_claude_pending_permission_index(store, session_id=session_id, now=now)
        if key != pending_key
    ]
    _store_claude_pending_permission_index(
        store,
        session_id=session_id,
        pending_keys=remaining,
        now=now,
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
    pending_keys = _load_cursor_pending_shell_index(store, conversation_id=conversation_id, now=now)
    if pending_key in pending_keys:
        return True
    pending_keys.append(pending_key)
    return _store_cursor_pending_shell_index(
        store,
        conversation_id=conversation_id,
        pending_keys=pending_keys,
        now=now,
    )


def _load_cursor_pending_shell_index(
    store: GuardStore,
    *,
    conversation_id: str,
    now: str | None = None,
) -> list[str]:
    current_time = now or _now()
    index_key = _cursor_pending_shell_index_key(conversation_id)
    persisted = _load_verified_hook_authority_payload(
        store,
        state_key=index_key,
        purpose=_CURSOR_PENDING_INDEX_INTEGRITY_PURPOSE,
        harness="cursor",
        source="cursor-pending-shell-index",
        now=current_time,
        max_age_seconds=_CURSOR_PENDING_SHELL_MAX_AGE_SECONDS,
    )
    if persisted is None:
        return []
    pending_keys_value = persisted.get("pending_keys")
    expected_prefix = f"cursor_pending_shell:{conversation_id}:"
    context_matches = (
        persisted.get("conversation_id") == conversation_id
        and isinstance(pending_keys_value, list)
        and all(isinstance(item, str) and item.startswith(expected_prefix) for item in pending_keys_value)
    )
    if not context_matches:
        _invalidate_hook_authority_context(
            store,
            state_key=index_key,
            payload=persisted,
            harness="cursor",
            source="cursor-pending-shell-index",
            message="local_authority_integrity_pending_index_context_mismatch",
            now=current_time,
        )
        return []
    return list(dict.fromkeys(cast(list[str], pending_keys_value)))


def _store_cursor_pending_shell_index(
    store: GuardStore,
    *,
    conversation_id: str,
    pending_keys: Sequence[str],
    now: str,
) -> bool:
    index_key = _cursor_pending_shell_index_key(conversation_id)
    if not pending_keys:
        _delete_hook_authority_state(store, index_key)
        return True
    return _store_signed_hook_authority_payload(
        store,
        state_key=index_key,
        payload={
            "conversation_id": conversation_id,
            "pending_keys": list(dict.fromkeys(pending_keys)),
            "saved_at": now,
        },
        purpose=_CURSOR_PENDING_INDEX_INTEGRITY_PURPOSE,
        now=now,
    )


def _store_cursor_pending_shell_state(
    store: GuardStore,
    *,
    conversation_id: str,
    command: str,
    payload: Mapping[str, object],
    now: str,
) -> bool:
    state_key = _cursor_pending_shell_state_key(conversation_id, command)
    return _store_signed_hook_authority_payload(
        store,
        state_key=state_key,
        payload=payload,
        purpose=_CURSOR_PENDING_INTEGRITY_PURPOSE,
        now=now,
    )


def _load_verified_cursor_pending_shell_state(
    store: GuardStore,
    *,
    conversation_id: str,
    command: str,
    state_key: str | None = None,
    now: str | None = None,
) -> dict[str, object] | None:
    from ..adapters.cursor_native_approval import normalize_cursor_shell_command

    current_time = now or _now()
    normalized_command = normalize_cursor_shell_command(command)
    expected_key = _cursor_pending_shell_state_key(conversation_id, normalized_command)
    selected_key = state_key or expected_key
    persisted = _load_verified_hook_authority_payload(
        store,
        state_key=selected_key,
        purpose=_CURSOR_PENDING_INTEGRITY_PURPOSE,
        harness="cursor",
        source="cursor-pending-shell",
        now=current_time,
        max_age_seconds=_CURSOR_PENDING_SHELL_MAX_AGE_SECONDS,
    )
    if persisted is None:
        return None
    artifact_id = _optional_string(persisted.get("artifact_id"))
    artifact_hash = _optional_string(persisted.get("artifact_hash"))
    stored_command = _optional_string(persisted.get("command"))
    context_matches = (
        selected_key == expected_key
        and persisted.get("conversation_id") == conversation_id
        and artifact_id is not None
        and artifact_hash is not None
        and stored_command == normalized_command
    )
    if context_matches:
        return persisted
    _invalidate_hook_authority_context(
        store,
        state_key=selected_key,
        payload=persisted,
        harness="cursor",
        source="cursor-pending-shell",
        message="local_authority_integrity_pending_context_mismatch",
        now=current_time,
    )
    return None


def _cursor_native_shell_allow_state_key(conversation_id: str, command: str) -> str:
    return f"cursor_native_shell_allow:{conversation_id}:{_cursor_shell_command_fingerprint(command)}"


_CURSOR_PENDING_SHELL_MAX_AGE_SECONDS = 30 * 60
_CURSOR_NATIVE_ALLOW_INTEGRITY_PURPOSE = "cursor-native-shell-allow"


def _cursor_pending_shell_is_fresh(pending: Mapping[str, object], *, now: str) -> bool:
    return _hook_authority_state_is_fresh(
        pending,
        now=now,
        max_age_seconds=_CURSOR_PENDING_SHELL_MAX_AGE_SECONDS,
    )


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
    state_key = _cursor_native_shell_allow_state_key(conversation_id, normalized_command)
    allow_payload: dict[str, object] = {
        "state_key": state_key,
        "conversation_id": conversation_id,
        "saved_at": now,
        "action": "allow",
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "artifact_name": artifact.name,
        "command": normalized_command,
        "native_source": "cursor-native",
    }
    key, key_id = store._policy_integrity_secret_material(create=True)
    if key is None or key_id is None:
        return False
    allow_payload["integrity"] = sign_local_authority_payload(
        allow_payload,
        key=key,
        key_id=key_id,
        purpose=_CURSOR_NATIVE_ALLOW_INTEGRITY_PURPOSE,
        signed_at=now,
    )
    try:
        store.set_sync_payload(
            state_key,
            allow_payload,
            now,
        )
    except (OSError, sqlite3.Error):
        return False
    return True


def _cursor_native_shell_allowance_is_fresh(approved: Mapping[str, object], *, now: str) -> bool:
    if not isinstance(approved, dict) or approved.get("action") != "allow":
        return False
    return _cursor_pending_shell_is_fresh(approved, now=now)


def _record_cursor_native_allow_integrity_failure(
    store: GuardStore,
    *,
    state_key: str,
    artifact_id: object,
    integrity_status: str,
    message: str | None,
    now: str,
) -> None:
    with suppress(OSError, sqlite3.Error):
        store.add_event(
            "rule.ignored.local_integrity",
            {
                "decision_id": None,
                "harness": "cursor",
                "artifact_id": artifact_id,
                "scope": "session",
                "source": "cursor-native-session",
                "integrity_status": integrity_status,
                "message": message,
                "state_key_fingerprint": hashlib.sha256(state_key.encode("utf-8")).hexdigest()[:16],
            },
            now,
        )


def _load_cursor_native_shell_allowance(
    store: GuardStore,
    payload: Mapping[str, object],
) -> dict[str, object] | None:
    conversation_id = _cursor_conversation_id(dict(payload))
    command = _cursor_shell_command_from_payload(payload)
    if conversation_id is None or command is None:
        return None
    state_key = _cursor_native_shell_allow_state_key(conversation_id, command)
    now = _now()
    try:
        approved = store.get_sync_payload(state_key)
    except json.JSONDecodeError:
        _record_cursor_native_allow_integrity_failure(
            store,
            state_key=state_key,
            artifact_id=None,
            integrity_status="tampered",
            message="local_authority_integrity_payload_invalid_json",
            now=now,
        )
        with suppress(OSError, sqlite3.Error):
            store.delete_sync_payload(state_key)
        return None
    except (OSError, sqlite3.Error):
        approved = None
    if not isinstance(approved, dict):
        return None
    raw_integrity = approved.get("integrity")
    integrity: Mapping[str, object] = (
        cast(Mapping[str, object], raw_integrity) if isinstance(raw_integrity, Mapping) else {}
    )
    signed_payload = {key: value for key, value in approved.items() if key != "integrity"}
    integrity_key: bytes | None = None
    integrity_key_id: str | None = None
    if integrity:
        integrity_key, integrity_key_id = store._policy_integrity_secret_material(create=False)
    integrity_result = verify_local_authority_payload(
        signed_payload,
        integrity,
        key=integrity_key,
        key_id=integrity_key_id,
        purpose=_CURSOR_NATIVE_ALLOW_INTEGRITY_PURPOSE,
    )
    context_matches = (
        approved.get("state_key") == state_key
        and approved.get("conversation_id") == conversation_id
        and approved.get("command") == command
    )
    allowance_is_fresh = _cursor_native_shell_allowance_is_fresh(approved, now=now)
    if integrity_result.status == "valid" and context_matches and allowance_is_fresh:
        return approved
    if integrity_result.status == "valid" and context_matches:
        with suppress(OSError, sqlite3.Error):
            store.delete_sync_payload(state_key)
        return None
    integrity_status = integrity_result.status if integrity_result.status != "valid" else "tampered"
    integrity_message = (
        integrity_result.message if integrity_result.status != "valid" else "local_authority_integrity_context_mismatch"
    )
    _record_cursor_native_allow_integrity_failure(
        store,
        state_key=state_key,
        artifact_id=approved.get("artifact_id"),
        integrity_status=integrity_status,
        message=integrity_message,
        now=now,
    )
    with suppress(OSError, sqlite3.Error):
        store.delete_sync_payload(state_key)
    return None


def _cursor_native_shell_is_approved(
    store: GuardStore,
    payload: Mapping[str, object],
) -> bool:
    return _load_cursor_native_shell_allowance(store, payload) is not None


__all__ = [
    "_CLAUDE_PENDING_PERMISSION_MAX_AGE_SECONDS",
    "_CURSOR_PENDING_SHELL_MAX_AGE_SECONDS",
    "_append_claude_pending_permission_key",
    "_append_cursor_pending_shell_key",
    "_claude_guard_approval_question_text",
    "_claude_pending_permission_index_key",
    "_claude_pending_permission_state_key",
    "_claude_permission_notice_state_key",
    "_cursor_after_shell_observed",
    "_cursor_conversation_id",
    "_cursor_native_shell_allow_state_key",
    "_cursor_native_shell_allowance_is_fresh",
    "_cursor_native_shell_is_approved",
    "_cursor_pending_shell_index_key",
    "_cursor_pending_shell_is_fresh",
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
