"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *
from .commands_parser_helpers import *

def _record_cursor_pending_shell_permission(
    *,
    store: GuardStore,
    guard_home: Path,
    payload: dict[str, object],
    reason: str,
    artifact: GuardArtifact,
    artifact_hash: str,
) -> None:
    from ..adapters.cursor_native_approval import (
        compute_cursor_after_shell_proof,
        ensure_cursor_approval_binding,
        ensure_cursor_hook_attestation_secret,
        remove_cursor_shell_binding_file,
        write_cursor_shell_binding_file,
    )

    conversation_id = _cursor_conversation_id(payload)
    command = _cursor_shell_command_from_payload(payload)
    if conversation_id is None or command is None:
        return
    approval_binding = ensure_cursor_approval_binding(payload)
    saved_at = _now()
    try:
        secret = ensure_cursor_hook_attestation_secret(guard_home)
        after_shell_proof = compute_cursor_after_shell_proof(
            secret=secret,
            conversation_id=conversation_id,
            command=command,
            approval_binding=approval_binding,
        )
    except OSError:
        return
    notice_payload: dict[str, object] = {
        "saved_at": saved_at,
        "reason": reason,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "artifact_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "config_path": artifact.config_path,
        "source_scope": artifact.source_scope,
        "command": command,
        "conversation_id": conversation_id,
        "approval_binding": approval_binding,
        "generation_id": approval_binding,
        "after_shell_proof": after_shell_proof,
        "native_source": "cursor-native",
    }
    pending_key = _cursor_pending_shell_state_key(conversation_id, command)
    try:
        store.set_sync_payload(pending_key, notice_payload, saved_at)
        _append_cursor_pending_shell_key(
            store,
            conversation_id=conversation_id,
            pending_key=pending_key,
            now=saved_at,
        )
        write_cursor_shell_binding_file(
            guard_home,
            conversation_id=conversation_id,
            command=command,
            approval_binding=approval_binding,
        )
    except (OSError, sqlite3.Error):
        remove_cursor_shell_binding_file(
            guard_home,
            conversation_id=conversation_id,
            command=command,
        )
        return

def _attach_cursor_pending_approval_request_ids(
    *,
    store: GuardStore,
    payload: dict[str, object],
    response_payload: dict[str, object],
) -> None:
    conversation_id = _cursor_conversation_id(payload)
    command = _cursor_shell_command_from_payload(payload)
    if conversation_id is None or command is None:
        return
    pending_key = _cursor_pending_shell_state_key(conversation_id, command)
    try:
        pending = store.get_sync_payload(pending_key)
    except (OSError, sqlite3.Error):
        return
    if not isinstance(pending, dict):
        return
    request_ids: list[str] = []
    approval_requests = response_payload.get("approval_requests")
    if isinstance(approval_requests, list):
        for item in approval_requests:
            if isinstance(item, dict):
                request_id = _optional_string(item.get("request_id"))
                if request_id is not None:
                    request_ids.append(request_id)
    for request_id in _string_list(response_payload.get("approval_request_ids")):
        if request_id not in request_ids:
            request_ids.append(request_id)
    if not request_ids:
        return
    updated = dict(pending)
    updated["approval_request_ids"] = request_ids
    try:
        store.set_sync_payload(pending_key, updated, _now())
    except (OSError, sqlite3.Error):
        return

def _load_cursor_pending_shell_permission(
    store: GuardStore,
    *,
    conversation_id: str,
    command: str,
) -> dict[str, object] | None:
    pending_key = _cursor_pending_shell_state_key(conversation_id, command)
    try:
        pending = store.get_sync_payload(pending_key)
    except (OSError, sqlite3.Error):
        pending = None
    if isinstance(pending, dict):
        return pending
    target_fingerprint = _cursor_shell_command_fingerprint(command)
    try:
        index_payload = store.get_sync_payload(_cursor_pending_shell_index_key(conversation_id))
    except (OSError, sqlite3.Error):
        return None
    if not isinstance(index_payload, list):
        return None
    for indexed_key in index_payload:
        if not isinstance(indexed_key, str):
            continue
        try:
            candidate = store.get_sync_payload(indexed_key)
        except (OSError, sqlite3.Error):
            continue
        if not isinstance(candidate, dict):
            continue
        stored_command = _optional_string(candidate.get("command"))
        if stored_command is None:
            continue
        if _cursor_shell_command_fingerprint(stored_command) == target_fingerprint:
            return candidate
    return None

def _remove_cursor_pending_shell_permission(
    store: GuardStore,
    *,
    conversation_id: str,
    pending_key: str,
) -> None:
    try:
        index_key = _cursor_pending_shell_index_key(conversation_id)
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

def _persist_cursor_native_permission_policy(
    *,
    store: GuardStore,
    artifact_id: str,
    artifact_hash: str,
    action: str,
    reason: str,
    now: str,
    source: str = "cursor-native-approval",
) -> bool:
    try:
        store.upsert_policy(
            PolicyDecision(
                harness="cursor",
                scope="artifact",
                action="allow" if action == "allow" else "block",
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                reason=reason,
                source=source,
            ),
            now,
        )
        store.add_event(
            "cursor/native_permission_saved",
            {
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "action": action,
                "reason": reason,
            },
            now,
        )
    except (ApprovalGateError, OSError, sqlite3.Error):
        return False
    return True

def _resolve_cursor_pending_approval_requests(
    *,
    store: GuardStore,
    pending: Mapping[str, object],
    reason: str,
    now: str,
) -> None:
    request_ids = pending.get("approval_request_ids")
    if not isinstance(request_ids, list):
        return
    for request_id in request_ids:
        if not isinstance(request_id, str) or not request_id.strip():
            continue
        with suppress(ApprovalGateError, OSError, sqlite3.Error):
            store.resolve_approval_request(
                request_id.strip(),
                resolution_action="allow",
                resolution_scope="artifact",
                reason=reason,
                resolved_at=now,
            )

def _persist_cursor_native_permission_after_shell(
    *,
    store: GuardStore,
    payload: dict[str, object],
    harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    hook_env: Mapping[str, str] | None = None,
) -> bool:
    from ..adapters.cursor_native_approval import cursor_after_shell_trusted

    prepared = payload
    conversation_id = _cursor_conversation_id(prepared)
    command = _cursor_shell_command_from_payload(prepared)
    if conversation_id is None or command is None:
        return False
    pending = _load_cursor_pending_shell_permission(
        store,
        conversation_id=conversation_id,
        command=command,
    )
    if pending is None:
        return False
    now = _now()
    if not _cursor_after_shell_observed(prepared):
        return False
    if not _cursor_pending_shell_is_fresh(pending, now=now):
        return False
    if not cursor_after_shell_trusted(
        guard_home=guard_home,
        pending=pending,
        payload=prepared,
        conversation_id=conversation_id,
        command=command,
        env=hook_env,
    ):
        return False
    action_envelope = _hook_action_envelope(
        harness=harness,
        payload=prepared,
        home_dir=home_dir,
        workspace=workspace,
    )
    runtime_artifact = _hook_runtime_artifact(
        harness=harness,
        payload=prepared,
        action_envelope=action_envelope,
        home_dir=home_dir,
        guard_home=guard_home,
        workspace=workspace,
    )
    if runtime_artifact is None:
        return False
    runtime_artifact_hash = artifact_hash(runtime_artifact)
    session_saved = _record_cursor_native_shell_allow_state(
        store=store,
        conversation_id=conversation_id,
        command=command,
        artifact=runtime_artifact,
        artifact_hash=runtime_artifact_hash,
        now=now,
    )
    if not session_saved:
        return False
    _resolve_cursor_pending_approval_requests(
        store=store,
        pending=pending,
        reason="Approved in Cursor native shell approval prompt.",
        now=now,
    )
    receipt = build_receipt(
        harness="cursor",
        artifact_id=runtime_artifact.artifact_id,
        artifact_hash=runtime_artifact_hash,
        policy_decision="allow",
        capabilities_summary=_runtime_capabilities_summary(runtime_artifact),
        changed_capabilities=[runtime_artifact.artifact_type, "cursor-native-session-approved"],
        provenance_summary=f"runtime shell command session-approved from {runtime_artifact.config_path}",
        artifact_name=runtime_artifact.name,
        source_scope=runtime_artifact.source_scope,
        user_override="cursor-native-approve",
        approval_source="harness-native-session",
    )
    try:
        store.add_receipt(receipt)
    except (OSError, sqlite3.Error):
        return False
    pending_key = _cursor_pending_shell_state_key(conversation_id, command)
    _remove_cursor_pending_shell_permission(
        store,
        conversation_id=conversation_id,
        pending_key=pending_key,
    )
    from ..adapters.cursor_native_approval import remove_cursor_shell_binding_file

    remove_cursor_shell_binding_file(
        guard_home,
        conversation_id=conversation_id,
        command=command,
    )
    return True

def _persist_claude_native_permission_policy(
    *,
    store: GuardStore,
    artifact_id: str,
    artifact_hash: str,
    action: str,
    reason: str,
    now: str,
    source: str = "claude-native-approval",
) -> bool:
    try:
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="allow" if action == "allow" else "block",
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                reason=reason,
                source=source,
            ),
            now,
        )
        store.add_event(
            "claude/native_permission_saved",
            {
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "action": action,
                "reason": reason,
            },
            now,
        )
    except (ApprovalGateError, OSError, sqlite3.Error):
        return False
    return True

def _persist_claude_native_permission_for_runtime_artifact(
    *,
    store: GuardStore,
    payload: dict[str, object],
    artifact: GuardArtifact,
    artifact_hash: str,
    action: str,
    reason: str,
) -> bool:
    pending = _load_claude_pending_permission(store, payload, artifact)
    if pending is None:
        return False
    now = _now()
    saved_policy = _persist_claude_native_permission_policy(
        store=store,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        action=action,
        reason=reason,
        now=now,
    )
    if not saved_policy:
        return False
    try:
        store.record_inventory_artifact(
            artifact=artifact,
            artifact_hash=artifact_hash,
            policy_action="allow" if action == "allow" else "block",
            changed=False,
            now=now,
            approved=action == "allow",
        )
    except (OSError, sqlite3.Error):
        return False
    session_id = _optional_string(payload.get("session_id"))
    if session_id is not None:
        _remove_claude_pending_permission(
            store,
            session_id=session_id,
            pending_key=_claude_pending_permission_state_key(session_id, artifact.artifact_id),
        )
    return True

def _discard_claude_pending_permissions(store: GuardStore, payload: dict[str, object]) -> int:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return 0
    index_key = _claude_pending_permission_index_key(session_id)
    try:
        index_payload = store.get_sync_payload(index_key)
    except (OSError, sqlite3.Error):
        return 0
    if not isinstance(index_payload, list):
        return 0
    pending_keys = [str(item) for item in index_payload]
    if not pending_keys:
        return 0
    try:
        store.delete_sync_payloads([*pending_keys, index_key])
    except (OSError, sqlite3.Error):
        return 0
    return len(pending_keys)

__all__ = [
    "_attach_cursor_pending_approval_request_ids",
    "_discard_claude_pending_permissions",
    "_load_cursor_pending_shell_permission",
    "_persist_claude_native_permission_for_runtime_artifact",
    "_persist_claude_native_permission_policy",
    "_persist_cursor_native_permission_after_shell",
    "_persist_cursor_native_permission_policy",
    "_record_cursor_pending_shell_permission",
    "_remove_cursor_pending_shell_permission",
    "_resolve_cursor_pending_approval_requests",
]
