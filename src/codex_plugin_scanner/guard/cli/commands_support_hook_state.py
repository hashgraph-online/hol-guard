"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *
from .commands_parser_helpers import *

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

def _sync_payload_list_from_row(row: sqlite3.Row | None) -> list[str]:
    if row is None:
        return []
    try:
        payload = json.loads(str(row["payload_json"]))
    except json.JSONDecodeError:
        return []
    return [str(item) for item in payload] if isinstance(payload, list) else []

def _append_claude_pending_permission_key(
    store: GuardStore,
    *,
    session_id: str,
    pending_key: str,
    now: str,
) -> None:
    index_key = _claude_pending_permission_index_key(session_id)
    with store._connect() as connection:
        connection.execute("begin immediate")
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (index_key,),
        ).fetchone()
        pending_keys = _sync_payload_list_from_row(row)
        if pending_key in pending_keys:
            return
        pending_keys.append(pending_key)
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values (?, ?, ?)
            on conflict(state_key) do update set
              payload_json = excluded.payload_json,
              updated_at = excluded.updated_at
            """,
            (index_key, json.dumps(pending_keys), now),
        )

def _claude_guard_approval_question_text(approval_code: str) -> str:
    return f"HOL Guard intercepted this sensitive action (approval code: {approval_code}). What should Claude do?"

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
    }
    if tool_name is not None:
        notice_payload["tool_name"] = tool_name
    try:
        store.set_sync_payload(_claude_permission_notice_state_key(session_id, tool_name), notice_payload, saved_at)
        pending_key = _claude_pending_permission_state_key(session_id, artifact.artifact_id)
        store.set_sync_payload(pending_key, notice_payload, saved_at)
        _append_claude_pending_permission_key(store, session_id=session_id, pending_key=pending_key, now=saved_at)
    except (OSError, sqlite3.Error):
        return

def _load_claude_permission_notice(store: GuardStore, payload: dict[str, object]) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    tool_name = _claude_notification_tool_name(payload)
    try:
        selected_key = _claude_permission_notice_state_key(session_id, tool_name)
        persisted = store.get_sync_payload(selected_key)
        if persisted is None and tool_name is not None:
            selected_key = _claude_permission_notice_state_key(session_id)
            persisted = store.get_sync_payload(selected_key)
        if isinstance(persisted, dict):
            artifact_id = _optional_string(persisted.get("artifact_id"))
            if artifact_id is not None:
                pending_key = _claude_pending_permission_state_key(session_id, artifact_id)
                pending = store.get_sync_payload(pending_key)
                if not isinstance(pending, dict):
                    store.delete_sync_payload(selected_key)
                    persisted = None
            else:
                store.delete_sync_payload(selected_key)
                persisted = None
    except (OSError, sqlite3.Error):
        return None
    if isinstance(persisted, dict):
        return persisted
    return None

def _peek_claude_permission_notice(store: GuardStore, payload: dict[str, object]) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    tool_name = _claude_notification_tool_name(payload)
    try:
        persisted = store.get_sync_payload(_claude_permission_notice_state_key(session_id, tool_name))
        if persisted is None and tool_name is not None:
            persisted = store.get_sync_payload(_claude_permission_notice_state_key(session_id))
    except (OSError, sqlite3.Error):
        return None
    return persisted if isinstance(persisted, dict) else None

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
    try:
        pending = store.get_sync_payload(pending_key)
    except (OSError, sqlite3.Error):
        return
    if not isinstance(pending, dict):
        return
    updated = dict(pending)
    updated["permission_prompt_seen"] = True
    updated["permission_prompt_seen_at"] = _now()
    try:
        store.set_sync_payload(pending_key, updated, _now())
    except (OSError, sqlite3.Error):
        return

def _load_single_claude_pending_permission(
    store: GuardStore,
    payload: dict[str, object],
) -> tuple[str, dict[str, object]] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    try:
        index_payload = store.get_sync_payload(_claude_pending_permission_index_key(session_id))
    except (OSError, sqlite3.Error):
        return None
    if not isinstance(index_payload, list):
        return None
    pending_keys = [str(item) for item in index_payload]
    pending_items: list[tuple[str, dict[str, object]]] = []
    for pending_key in pending_keys:
        try:
            pending = store.get_sync_payload(pending_key)
        except (OSError, sqlite3.Error):
            continue
        if isinstance(pending, dict):
            pending_items.append((pending_key, pending))
    prompt_seen_items = [item for item in pending_items if item[1].get("permission_prompt_seen") is True]
    if len(prompt_seen_items) == 1:
        return prompt_seen_items[0]
    if len(pending_items) != 1:
        return None
    try:
        pending = store.get_sync_payload(pending_items[0][0])
    except (OSError, sqlite3.Error):
        return None
    if not isinstance(pending, dict):
        return None
    return pending_items[0][0], pending

def _load_claude_pending_permission(
    store: GuardStore,
    payload: dict[str, object],
    artifact: GuardArtifact,
) -> dict[str, object] | None:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    pending_key = _claude_pending_permission_state_key(session_id, artifact.artifact_id)
    try:
        persisted = store.get_sync_payload(pending_key)
    except (OSError, sqlite3.Error):
        return None
    return persisted if isinstance(persisted, dict) else None

def _remove_claude_pending_permission(
    store: GuardStore,
    *,
    session_id: str,
    pending_key: str,
) -> None:
    try:
        index_key = _claude_pending_permission_index_key(session_id)
        with store._connect() as connection:
            connection.execute("begin immediate")
            connection.execute("delete from sync_state where state_key = ?", (pending_key,))
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (index_key,),
            ).fetchone()
            remaining = [key for key in _sync_payload_list_from_row(row) if key != pending_key]
            if remaining:
                connection.execute(
                    """
                    insert into sync_state (state_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(state_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (index_key, json.dumps(remaining), _now()),
                )
            else:
                connection.execute("delete from sync_state where state_key = ?", (index_key,))
    except (OSError, sqlite3.Error):
        return

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
        is_lean_ctx_wrapper_command,
        normalize_cursor_shell_command,
    )

    tool_input_command = _hook_command_text(payload)
    top_level = _optional_string(payload.get("command"))
    if tool_input_command is not None and (
        top_level is None or is_lean_ctx_wrapper_command(top_level)
    ):
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
) -> None:
    index_key = _cursor_pending_shell_index_key(conversation_id)
    try:
        with store._connect() as connection:
            connection.execute("begin immediate")
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (index_key,),
            ).fetchone()
            pending_keys = _sync_payload_list_from_row(row)
            if pending_key in pending_keys:
                return
            pending_keys.append(pending_key)
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (index_key, json.dumps(pending_keys), now),
            )
    except (OSError, sqlite3.Error):
        return

def _cursor_native_shell_allow_state_key(conversation_id: str, command: str) -> str:
    return f"cursor_native_shell_allow:{conversation_id}:{_cursor_shell_command_fingerprint(command)}"

_CURSOR_PENDING_SHELL_MAX_AGE_SECONDS = 30 * 60

def _cursor_pending_shell_is_fresh(pending: Mapping[str, object], *, now: str) -> bool:
    saved_at = _optional_string(pending.get("saved_at"))
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
    return 0 <= age_seconds <= _CURSOR_PENDING_SHELL_MAX_AGE_SECONDS

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
    allow_payload: dict[str, object] = {
        "saved_at": now,
        "action": "allow",
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "artifact_name": artifact.name,
        "command": command,
        "native_source": "cursor-native",
    }
    try:
        store.set_sync_payload(
            _cursor_native_shell_allow_state_key(conversation_id, command),
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

def _cursor_native_shell_is_approved(
    store: GuardStore,
    payload: Mapping[str, object],
) -> bool:
    conversation_id = _cursor_conversation_id(dict(payload))
    command = _cursor_shell_command_from_payload(payload)
    if conversation_id is None or command is None:
        return False
    now = _now()
    try:
        approved = store.get_sync_payload(_cursor_native_shell_allow_state_key(conversation_id, command))
    except (OSError, sqlite3.Error):
        approved = None
    if isinstance(approved, dict) and _cursor_native_shell_allowance_is_fresh(approved, now=now):
        return True
    if isinstance(approved, dict):
        with suppress(OSError, sqlite3.Error):
            store.delete_sync_payload(_cursor_native_shell_allow_state_key(conversation_id, command))
    return False

__all__ = [
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
    "_load_claude_permission_notice",
    "_load_single_claude_pending_permission",
    "_mark_claude_pending_permission_prompt_seen",
    "_peek_claude_permission_notice",
    "_record_claude_permission_notice",
    "_record_cursor_native_shell_allow_state",
    "_remove_claude_pending_permission",
    "_should_emit_prequeue_native_hook_response",
    "_sync_payload_list_from_row",
    "_update_codex_browser_operation_status",
]
