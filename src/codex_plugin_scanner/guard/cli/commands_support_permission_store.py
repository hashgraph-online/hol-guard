"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_hook_payload import _hook_action_envelope
    from .commands_support_hook_state import (
        _append_cursor_pending_shell_key,
        _claude_pending_permission_state_key,
        _cursor_conversation_id,
        _cursor_pending_shell_state_key,
        _cursor_shell_command_from_payload,
        _load_claude_pending_permission,
        _load_verified_cursor_pending_shell_state,
        _record_cursor_native_shell_allow_state,
        _remove_claude_pending_permission,
        _store_cursor_pending_shell_state,
    )
    from .commands_support_runtime_artifacts import _hook_runtime_artifact, _optional_string, _string_list
    from .commands_support_runtime_resolution import _runtime_capabilities_summary


from ..models import GuardAction
from ..native_hook_authority_state import (
    HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE,
    flag_field,
    hook_authority_state,
    object_field,
)
from ..native_hook_render import (
    native_cursor_after_shell_observed,
    native_cursor_observer_event,
)
from ..runtime.approval_context import parse_approval_context_token
from ..store import _runtime_scoped_exact_match_key, runtime_tool_action_exact_match_context
from ._commands_shared import *
from .commands_parser_helpers import *


def _cursor_runtime_artifact_from_pending(pending: Mapping[str, object]) -> GuardArtifact | None:
    artifact_id = _optional_string(pending.get("artifact_id"))
    artifact_name = _optional_string(pending.get("artifact_name"))
    artifact_type = _optional_string(pending.get("artifact_type"))
    config_path = _optional_string(pending.get("config_path"))
    source_scope = _optional_string(pending.get("source_scope"))
    if artifact_id is None or artifact_name is None or artifact_type is None or config_path is None:
        return None
    command = _optional_string(pending.get("command"))
    return GuardArtifact(
        artifact_id=artifact_id,
        name=artifact_name,
        harness="cursor",
        artifact_type=artifact_type,
        source_scope=source_scope or "project",
        config_path=config_path,
        command=command,
    )


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
        compute_cursor_after_observer_proof,
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
    # The issuing and checking sides have to attest under the same event, so
    # both take it from the resident. Without an answer no proof is issued,
    # which leaves the approval unable to become an allowance later.
    observer_event = native_cursor_observer_event(payload, guard_home=guard_home)
    if observer_event is None:
        return
    saved_at = _now()
    try:
        secret = ensure_cursor_hook_attestation_secret(guard_home)
        after_shell_proof = compute_cursor_after_observer_proof(
            secret=secret,
            conversation_id=conversation_id,
            command=command,
            approval_binding=approval_binding,
            observer_event=observer_event,
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
        "observer_event": observer_event,
        "after_shell_proof": after_shell_proof,
        "native_source": "cursor-native",
    }
    pending_key = _cursor_pending_shell_state_key(conversation_id, command)
    try:
        pending_saved = _store_cursor_pending_shell_state(
            store,
            conversation_id=conversation_id,
            command=command,
            payload=notice_payload,
            now=saved_at,
        )
        indexed = pending_saved and _append_cursor_pending_shell_key(
            store,
            conversation_id=conversation_id,
            pending_key=pending_key,
            now=saved_at,
        )
        if not indexed:
            store.delete_sync_payload(pending_key)
            return
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
    pending = _load_verified_cursor_pending_shell_state(
        store,
        conversation_id=conversation_id,
        command=command,
        state_key=pending_key,
    )
    if pending is None:
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
    _store_cursor_pending_shell_state(
        store,
        conversation_id=conversation_id,
        command=command,
        payload=updated,
        now=_now(),
    )


def _load_cursor_pending_shell_permission(
    store: GuardStore,
    *,
    conversation_id: str,
    command: str,
) -> dict[str, object] | None:
    from ..adapters.cursor_native_approval import normalize_cursor_shell_command

    normalized_command = normalize_cursor_shell_command(command)
    reply = hook_authority_state(
        store,
        "cursor_find_pending",
        now=_now(),
        required_feature=HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE,
        conversation_id=conversation_id,
        command=normalized_command,
        expected_key=_cursor_pending_shell_state_key(conversation_id, normalized_command),
    )
    return object_field(reply, "pending")


def _remove_cursor_pending_shell_permission(
    store: GuardStore,
    *,
    conversation_id: str,
    pending_key: str,
) -> None:
    hook_authority_state(
        store,
        "cursor_remove_pending",
        now=_now(),
        required_feature=HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE,
        conversation_id=conversation_id,
        pending_key=pending_key,
    )


def _resolve_cursor_pending_approval_requests(
    *,
    store: GuardStore,
    pending: Mapping[str, object],
    reason: str,
    now: str,
    artifact_id: str,
    artifact_hash: str,
) -> None:
    request_ids: list[str] = []
    raw_ids = pending.get("approval_request_ids")
    if isinstance(raw_ids, list):
        for request_id in raw_ids:
            if isinstance(request_id, str) and request_id.strip():
                request_ids.append(request_id.strip())
    with suppress(OSError, sqlite3.Error):
        for item in store.list_approval_requests(status="pending", harness="cursor", limit=50):
            if not isinstance(item, Mapping):
                continue
            item_id = _optional_string(item.get("request_id"))
            if item_id is None or item_id in request_ids:
                continue
            if _optional_string(item.get("artifact_id")) != artifact_id:
                continue
            if _optional_string(item.get("artifact_hash")) != artifact_hash:
                continue
            request_ids.append(item_id)
    for request_id in request_ids:
        with suppress(OSError, sqlite3.Error, ValueError):
            store.resolve_harness_native_approval_request(
                request_id,
                reason=reason,
                resolved_at=now,
                expected_harness="cursor",
                expected_artifact_id=artifact_id,
                expected_artifact_hash=artifact_hash,
            )


_CURSOR_PENDING_MAX_AGE_SECONDS = 30 * 60


def _cursor_pending_saved_at_is_fresh(
    store: GuardStore,
    pending: Mapping[str, object],
    now: str,
) -> bool:
    """Whether the resident still treats ``pending`` as fresh at ``now``."""

    saved_at = pending.get("saved_at")
    if not isinstance(saved_at, str) or not saved_at.strip():
        return False
    reply = hook_authority_state(
        store,
        "state_is_fresh",
        now=now,
        saved_at=saved_at.strip(),
        max_age_seconds=_CURSOR_PENDING_MAX_AGE_SECONDS,
    )
    return flag_field(reply, "fresh")


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
    from ..adapters.cursor_native_approval import cursor_after_observer_trusted

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
    # The load checked freshness against its own earlier clock. Recheck against
    # this clock so a pending row that expires while that load is in flight
    # cannot become an allowance.
    if not _cursor_pending_saved_at_is_fresh(store, pending, now):
        return False
    # Whether the harness is reporting a finished command is what separates a
    # pending approval from a durable allowance, and the resident reads that
    # payload itself. A resident that cannot answer leaves the approval pending
    # rather than minting an allowance on a guess.
    if not native_cursor_after_shell_observed(harness, prepared, guard_home=guard_home):
        return False
    if not cursor_after_observer_trusted(
        guard_home=guard_home,
        pending=pending,
        payload=prepared,
        conversation_id=conversation_id,
        command=command,
        env=hook_env,
    ):
        return False
    runtime_artifact = _cursor_runtime_artifact_from_pending(pending)
    runtime_artifact_hash = _optional_string(pending.get("artifact_hash"))
    if runtime_artifact is not None and runtime_artifact_hash is None:
        runtime_artifact_hash = artifact_hash(runtime_artifact)
    if runtime_artifact is None:
        action_envelope = _hook_action_envelope(
            harness=harness,
            payload=prepared,
            home_dir=home_dir,
            workspace=workspace,
            guard_home=guard_home,
        )
        runtime_artifact = _hook_runtime_artifact(
            harness=harness,
            payload=prepared,
            action_envelope=action_envelope,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )
        if runtime_artifact is not None:
            runtime_artifact_hash = artifact_hash(runtime_artifact)
    if runtime_artifact is None or runtime_artifact_hash is None:
        return False
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
        reason="Approved in Cursor native approval prompt.",
        now=now,
        artifact_id=runtime_artifact.artifact_id,
        artifact_hash=runtime_artifact_hash,
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
    artifact_type: str | None = None,
    config_path: str | None = None,
    source_scope: str | None = None,
    raw_command_text: str | None = None,
    wrapper_chain: Sequence[object] | None = None,
    action: str,
    reason: str,
    now: str,
    source: str = "claude-native-approval",
) -> bool:
    exact_match_context = (
        runtime_tool_action_exact_match_context(
            config_path=config_path,
            source_scope=source_scope,
            raw_command_text=raw_command_text,
            wrapper_chain=wrapper_chain,
        )
        if artifact_type == "tool_action_request"
        else None
    )
    exact_artifact_hash = (
        _runtime_scoped_exact_match_key(artifact_id, exact_match_context)
        if artifact_type == "tool_action_request"
        else None
    )
    # V1 approval-context tokens already bind the full tool identity and are
    # the only values that may authorize P44 approval reuse.  Keep the legacy
    # exact-command key only for legacy callers/blocks.
    stored_artifact_hash = (
        artifact_hash
        if parse_approval_context_token(artifact_hash) is not None
        else exact_artifact_hash or artifact_hash
    )
    try:
        if artifact_type == "tool_action_request" and exact_artifact_hash is None:
            store.add_event(
                "claude/native_permission_exact_key_missing",
                {
                    "artifact_id": artifact_id,
                    "artifact_type": artifact_type,
                    "source": source,
                },
                now,
            )
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="allow" if action == "allow" else "block",
                artifact_id=artifact_id,
                artifact_hash=stored_artifact_hash,
                reason=reason,
                source=source,
            ),
            now,
        )
        store.add_event(
            "claude/native_permission_saved",
            {
                "artifact_id": artifact_id,
                "artifact_hash": stored_artifact_hash,
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
    authoritative_action: GuardAction,
    reason: str,
) -> tuple[bool, bool]:
    """Record a Claude-native answer without overriding current authority.

    The first result reports whether a matching pending native prompt was
    observed; the second reports whether a reusable allow policy was saved.
    Stronger recomputed actions remain authoritative and are recorded only as
    evidence/inventory, never as a contradictory effective allow.
    """

    pending = _load_claude_pending_permission(store, payload, artifact, artifact_hash)
    if pending is None:
        return False, False
    now = _now()
    if pending.get("permission_prompt_seen") is not True:
        with suppress(OSError, sqlite3.Error):
            store.add_event(
                "approval.pending_prompt_unseen",
                {
                    "harness": "claude-code",
                    "source": "claude-pending-permission",
                    "session_id": payload.get("session_id"),
                    "artifact_id": artifact.artifact_id,
                    "artifact_hash": artifact_hash,
                },
                now,
            )
        return False, False
    raw_command_text_value = artifact.metadata.get("raw_command_text")
    raw_command_text = raw_command_text_value if isinstance(raw_command_text_value, str) else None
    wrapper_chain_value = artifact.metadata.get("wrapper_chain")
    wrapper_chain = (
        wrapper_chain_value
        if isinstance(wrapper_chain_value, Sequence) and not isinstance(wrapper_chain_value, str)
        else None
    )
    saved_policy = False
    if authoritative_action == "allow":
        saved_policy = _persist_claude_native_permission_policy(
            store=store,
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
            artifact_type=artifact.artifact_type,
            config_path=artifact.config_path,
            source_scope=artifact.source_scope,
            raw_command_text=raw_command_text,
            wrapper_chain=wrapper_chain,
            action=action,
            reason=reason,
            now=now,
        )
        if not saved_policy:
            return True, False
    else:
        with suppress(OSError, sqlite3.Error):
            store.add_event(
                "claude/native_permission_current_policy_retained",
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_hash": artifact_hash,
                    "native_action": action,
                    "authoritative_action": authoritative_action,
                },
                now,
            )
    try:
        store.record_inventory_artifact(
            artifact=artifact,
            artifact_hash=artifact_hash,
            policy_action=authoritative_action,
            changed=False,
            now=now,
            approved=authoritative_action in {"allow", "warn"},
        )
    except (OSError, sqlite3.Error):
        return True, saved_policy
    session_id = _optional_string(payload.get("session_id"))
    if session_id is not None:
        _remove_claude_pending_permission(
            store,
            session_id=session_id,
            pending_key=_claude_pending_permission_state_key(session_id, artifact.artifact_id),
        )
    return True, saved_policy


def _discard_claude_pending_permissions(store: GuardStore, payload: dict[str, object]) -> int:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return 0
    reply = hook_authority_state(
        store,
        "claude_discard_session",
        now=_now(),
        required_feature=HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE,
        session_id=session_id,
    )
    discarded = reply.get("discarded") if reply is not None else None
    return discarded if isinstance(discarded, int) and not isinstance(discarded, bool) else 0


__all__ = [
    "_attach_cursor_pending_approval_request_ids",
    "_discard_claude_pending_permissions",
    "_load_cursor_pending_shell_permission",
    "_persist_claude_native_permission_for_runtime_artifact",
    "_persist_claude_native_permission_policy",
    "_persist_cursor_native_permission_after_shell",
    "_record_cursor_pending_shell_permission",
    "_remove_cursor_pending_shell_permission",
    "_resolve_cursor_pending_approval_requests",
]
