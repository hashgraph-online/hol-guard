"""Records a Claude permission notice for an arbitrary artifact.

The daemon's Claude review queue builds and signs its notice in the resident
(``add_claude_approval_request``). These tests seed notices for artifacts that
queue never produces, such as file reads, through the same resident
``claude_record_notice`` op the retired CLI helper called.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_hook_authority_state import hook_authority_state

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.store import GuardStore

CLAUDE_GUARD_APPROVAL_HEADER = "HOL Guard"
CLAUDE_GUARD_APPROVAL_OPTIONS = ("Allow once", "Allow during this session", "Keep blocked")


def claude_guard_approval_question_text(approval_code: str) -> str:
    return f"HOL Guard intercepted this sensitive action (approval code: {approval_code}). What should Claude do?"


def _command_binding(artifact: GuardArtifact) -> str:
    raw_command_text = artifact.metadata.get("raw_command_text")
    if isinstance(raw_command_text, str) and raw_command_text:
        return raw_command_text
    if isinstance(artifact.command, str) and artifact.command:
        return artifact.command
    return f"artifact:{artifact.artifact_id}"


def record_claude_permission_notice(
    *,
    store: GuardStore,
    payload: dict[str, object],
    reason: str,
    artifact: GuardArtifact,
    artifact_hash: str,
) -> None:
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        return
    saved_at = datetime.now(timezone.utc).isoformat()
    raw_tool_name = payload.get("tool_name")
    tool_name = raw_tool_name.strip() if isinstance(raw_tool_name, str) and raw_tool_name.strip() else None
    approval_code = secrets.token_hex(6)
    notice_payload: dict[str, object] = {
        "session_id": session_id.strip(),
        "saved_at": saved_at,
        "reason": reason,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "artifact_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "config_path": artifact.config_path,
        "source_scope": artifact.source_scope,
        "approval_header": CLAUDE_GUARD_APPROVAL_HEADER,
        "approval_question": claude_guard_approval_question_text(approval_code),
        "approval_options": list(CLAUDE_GUARD_APPROVAL_OPTIONS),
        "approval_code": approval_code,
        "command": _command_binding(artifact),
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
        session_id=session_id.strip(),
        tool_name=tool_name,
        payload=notice_payload,
    )
