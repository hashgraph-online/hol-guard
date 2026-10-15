"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _CLAUDE_GUARD_APPROVAL_HEADER, _CLAUDE_GUARD_APPROVAL_OPTIONS, _now
    from .commands_support_hook_state import (
        _load_single_claude_pending_permission,
        _remove_claude_pending_permission,
    )
    from .commands_support_permission_store import _persist_claude_native_permission_policy
    from .commands_support_runtime_artifacts import _hook_event_name, _optional_string
    from .commands_support_runtime_policy import (
        _claude_notification_tool_display_name,
        _claude_notification_tool_name,
        _ensure_terminal_punctuation,
        _runtime_artifact_policy_action,
    )
    from .commands_support_runtime_resolution import _canonical_harness_name


from ..action_lattice import most_restrictive_guard_action, normalize_guard_action
from ..native_claude_guard_question import ClaudeGuardQuestionVerdict, claude_guard_question_verdict
from ._commands_shared import *
from .commands_parser_helpers import *


def _claude_guard_approval_question_message(notice: dict[str, object] | None) -> str:
    tool_name = _optional_string((notice or {}).get("tool_name")) or "this tool"
    reason = _optional_string((notice or {}).get("reason"))
    header = _optional_string((notice or {}).get("approval_header")) or _CLAUDE_GUARD_APPROVAL_HEADER
    question = _optional_string((notice or {}).get("approval_question")) or (
        "HOL Guard intercepted this sensitive action. What should Claude do?"
    )
    options = _claude_guard_approval_options_from_value((notice or {}).get("approval_options"))
    if not options:
        options = _CLAUDE_GUARD_APPROVAL_OPTIONS
    options_text = "', '".join(options)
    reason_text = f" HOL Guard reason: {_ensure_terminal_punctuation(reason)}" if reason is not None else ""
    return (
        f"HOL Guard needs the user's explicit decision before {tool_name} can run.{reason_text} "
        "The native Claude permission prompt is not the final decision surface for this request. Call "
        "AskUserQuestion now with one HOL Guard approval question before retrying the tool. Use header "
        f"'{header}', question '{question}', and exactly these options: '{options_text}'. If the user chooses an "
        "allow option, retry the same tool once. If the user chooses Keep blocked, do not retry the sensitive action."
    )


def _claude_guard_approval_options_from_value(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    labels: list[str] = []
    for item in value:
        label: str | None
        if isinstance(item, dict):
            label = _optional_string(item.get("label"))
        elif isinstance(item, str):
            label = item.strip()
        else:
            label = None
        if label is None:
            return ()
        labels.append(label)
    return tuple(labels)


def _claude_guard_question_verdict(
    payload: dict[str, object], pending: dict[str, object]
) -> ClaudeGuardQuestionVerdict:
    return claude_guard_question_verdict(payload, pending, event=_hook_event_name(payload))


def _persist_claude_guard_question_decision(
    store: GuardStore,
    payload: dict[str, object],
    *,
    pending_pair: tuple[str, dict[str, object]] | None = None,
    verdict: ClaudeGuardQuestionVerdict | None = None,
) -> bool:
    if pending_pair is None:
        pending_pair = _load_single_claude_pending_permission(store, payload)
    if pending_pair is None:
        return False
    pending_key, pending = pending_pair
    if pending.get("permission_prompt_seen") is not True:
        with suppress(OSError, sqlite3.Error):
            store.add_event(
                "approval.pending_prompt_unseen",
                {
                    "harness": "claude-code",
                    "source": "claude-pending-permission",
                    "session_id": payload.get("session_id"),
                    "artifact_id": pending.get("artifact_id"),
                    "artifact_hash": pending.get("artifact_hash"),
                },
                _now(),
            )
        return False
    if verdict is None:
        verdict = _claude_guard_question_verdict(payload, pending)
    action = verdict.action
    if not verdict.is_question or action is None:
        return False
    artifact_id = _optional_string(pending.get("artifact_id"))
    artifact_hash_value = _optional_string(pending.get("artifact_hash"))
    if artifact_id is None or artifact_hash_value is None:
        return False
    artifact_type = _optional_string(pending.get("artifact_type"))
    config_path = _optional_string(pending.get("config_path"))
    source_scope = _optional_string(pending.get("source_scope"))
    raw_command_text = _optional_string(pending.get("raw_command_text"))
    pending_wrapper_chain = pending.get("wrapper_chain")
    wrapper_chain = pending_wrapper_chain if isinstance(pending_wrapper_chain, list) else None
    saved = _persist_claude_native_permission_policy(
        store=store,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash_value,
        artifact_type=artifact_type,
        config_path=config_path,
        source_scope=source_scope,
        raw_command_text=raw_command_text,
        wrapper_chain=wrapper_chain,
        action=action,
        reason=(
            "Allowed through HOL Guard AskUserQuestion approval."
            if action == "allow"
            else "Blocked through HOL Guard AskUserQuestion approval."
        ),
        now=_now(),
        source="claude-ask-user-question",
    )
    if not saved:
        return False
    session_id = _optional_string(payload.get("session_id"))
    if session_id is not None:
        _remove_claude_pending_permission(store, session_id=session_id, pending_key=pending_key)
    return True


def _is_claude_permission_prompt_notification(args: argparse.Namespace, payload: dict[str, object]) -> bool:
    return (
        _canonical_harness_name(args.harness) == "claude-code"
        and _hook_event_name(payload) == "Notification"
        and _optional_string(payload.get("notification_type")) == "permission_prompt"
    )


def _is_claude_permission_request(args: argparse.Namespace, payload: dict[str, object]) -> bool:
    return _canonical_harness_name(args.harness) == "claude-code" and _hook_event_name(payload) == "PermissionRequest"


def _claude_permission_notice_prefers_ask_user_question(notice: dict[str, object]) -> bool:
    artifact_type = _optional_string(notice.get("artifact_type"))
    return artifact_type != "package_request"


def _resolve_claude_permission_request_policy_action(
    *,
    config: GuardConfig,
    store: GuardStore,
    args: argparse.Namespace,
    runtime_artifact: GuardArtifact,
    runtime_workspace: Path | None,
) -> tuple[str, dict[str, object]]:
    policy_action = _runtime_artifact_policy_action(config, runtime_artifact, args.harness, guard_home=store.guard_home)
    package_evaluation = None
    if runtime_artifact.artifact_type == "package_request":
        package_evaluation = evaluate_package_request_artifact(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
        )
        policy_action = most_restrictive_guard_action(
            policy_action,
            normalize_guard_action(package_evaluation.policy_action),
        )
    stub: dict[str, object] = {
        "harness": _canonical_harness_name(args.harness),
        "policy_action": policy_action,
        "risk_summary": (
            package_evaluation.risk_summary
            if package_evaluation is not None
            else artifact_risk_summary(runtime_artifact)
        ),
    }
    if package_evaluation is not None:
        stub["decision_v2_json"] = {
            "harness_message": package_evaluation.user_copy.harness_message,
        }
    return policy_action, stub


def _claude_permission_request_terminal_notice(
    *,
    payload: dict[str, object],
    native_reason: str,
) -> str:
    tool_name = _claude_notification_tool_display_name(payload)
    if tool_name is not None:
        return f"HOL Guard: reviewing Claude approval for {tool_name}. {_ensure_terminal_punctuation(native_reason)}"
    return f"HOL Guard: reviewing this Claude approval prompt. {_ensure_terminal_punctuation(native_reason)}"


def _claude_permission_request_system_message(
    *,
    payload: dict[str, object],
    native_reason: str,
) -> str:
    tool_name = _claude_notification_tool_display_name(payload)
    if tool_name is not None:
        return (
            f"HOL Guard is reviewing Claude's approval prompt for {tool_name}. "
            "Claude's risk warnings above are separate from HOL Guard. "
            f"{_ensure_terminal_punctuation(native_reason)}"
        )
    return (
        "HOL Guard is reviewing this Claude approval prompt. "
        "Claude's risk warnings above are separate from HOL Guard. "
        f"{_ensure_terminal_punctuation(native_reason)}"
    )


def _claude_permission_request_additional_context(native_reason: str) -> str:
    return (
        "This review came from HOL Guard, not from Claude alone. "
        f"{_ensure_terminal_punctuation(native_reason)} "
        "Use Claude's normal Allow / deny controls unless HOL Guard opened a separate approval question."
    )


def _claude_permission_prompt_system_message(
    *,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> str:
    tool_name = _claude_notification_tool_name(payload)
    if tool_name is None and notice is not None:
        tool_name = _optional_string(notice.get("tool_name"))
    reason = _optional_string(notice.get("reason")) if notice is not None else None
    intro = "HOL Guard intercepted a sensitive request and is routing it to a HOL Guard approval question."
    if tool_name is not None:
        intro = (
            f"HOL Guard intercepted Claude's attempt to use {tool_name} and is routing it to a HOL Guard approval "
            "question."
        )
    if reason is not None:
        return (
            f"{intro} This approval flow came from HOL Guard, not from Claude alone. "
            f"{_ensure_terminal_punctuation(reason)} "
            "HOL Guard will ask the user to choose Allow once, Allow during this session, or Keep blocked before "
            "Claude retries the action."
        )
    return (
        f"{intro} This approval flow came from HOL Guard, not from Claude alone. "
        "HOL Guard will ask the user to choose Allow once, Allow during this session, or Keep blocked before Claude "
        "retries the action."
    )


def _claude_permission_prompt_additional_context(notice: dict[str, object] | None) -> str:
    if notice is not None:
        return _claude_guard_approval_question_message(notice)
    reason = _optional_string(notice.get("reason")) if notice is not None else None
    if reason is not None:
        return (
            "HOL Guard intercepted the sensitive request and is routing it into a HOL Guard approval question. "
            "This approval flow came from HOL Guard, not from Claude alone. "
            f"{_ensure_terminal_punctuation(reason)} Ask the user with AskUserQuestion and the options Allow once, "
            "Allow during this session, and Keep blocked. If the user chooses Keep blocked, do not retry the same "
            "sensitive access."
        )
    return (
        "HOL Guard intercepted the sensitive request and is routing it into a HOL Guard approval question. "
        "This approval flow came from HOL Guard, not from Claude alone. Ask the user with AskUserQuestion and the "
        "options Allow once, Allow during this session, and Keep blocked. If the user chooses Keep blocked, do not "
        "retry the same action."
    )


def _claude_permission_prompt_terminal_notice(
    *,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> str:
    tool_name = _claude_notification_tool_name(payload)
    reason = _optional_string(notice.get("reason")) if notice is not None else None
    if tool_name is not None and reason is not None:
        return (
            f"HOL Guard is routing this Claude approval request for {tool_name} into a HOL Guard decision prompt. "
            f"{_ensure_terminal_punctuation(reason)} "
            "Choose Allow once, Allow during this session, or Keep blocked in the HOL Guard prompt."
        )
    if tool_name is not None:
        return (
            f"HOL Guard is routing this Claude approval request for {tool_name} into a HOL Guard decision prompt. "
            "Choose Allow once, Allow during this session, or Keep blocked in the HOL Guard prompt."
        )
    return (
        "HOL Guard is routing this Claude approval request into a HOL Guard decision prompt to protect a sensitive "
        "action. Choose Allow once, Allow during this session, or Keep blocked in the HOL Guard prompt."
    )


def _claude_native_pretooluse_terminal_notice(*, payload: dict[str, object], reason: str) -> str:
    tool_name = _claude_notification_tool_name(payload)
    if tool_name is not None:
        return (
            f"HOL Guard intercepted Claude's attempt to use {tool_name}. {_ensure_terminal_punctuation(reason)} "
            "Guard will route the next approval through a HOL Guard prompt if Claude asks to continue."
        )
    return (
        "HOL Guard intercepted a sensitive Claude action. "
        f"{_ensure_terminal_punctuation(reason)} Guard will route the next approval through a HOL Guard prompt if "
        "Claude asks to continue."
    )


__all__ = [
    "_claude_guard_approval_options_from_value",
    "_claude_guard_approval_question_message",
    "_claude_guard_question_verdict",
    "_claude_native_pretooluse_terminal_notice",
    "_claude_permission_notice_prefers_ask_user_question",
    "_claude_permission_prompt_additional_context",
    "_claude_permission_prompt_system_message",
    "_claude_permission_prompt_terminal_notice",
    "_claude_permission_request_additional_context",
    "_claude_permission_request_system_message",
    "_claude_permission_request_terminal_notice",
    "_is_claude_permission_prompt_notification",
    "_is_claude_permission_request",
    "_persist_claude_guard_question_decision",
    "_resolve_claude_permission_request_policy_action",
]
