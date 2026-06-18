"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _CLAUDE_GUARD_APPROVAL_HEADER, _CLAUDE_GUARD_APPROVAL_OPTIONS, _now
    from .commands_support_hook_state import (
        _claude_guard_approval_question_text,
        _claude_pending_permission_index_key,
        _load_single_claude_pending_permission,
        _remove_claude_pending_permission,
        _sync_payload_list_from_row,
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


from ._commands_shared import *
from .commands_parser_helpers import *


def _persist_claude_pending_permission_denials(store: GuardStore, payload: dict[str, object]) -> int:
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
    processed_keys: list[str] = []
    denied = 0
    for pending_key in pending_keys:
        try:
            pending = store.get_sync_payload(pending_key)
        except (OSError, sqlite3.Error):
            continue
        if not isinstance(pending, dict):
            continue
        if pending.get("permission_prompt_seen") is not True:
            continue
        artifact_id = _optional_string(pending.get("artifact_id"))
        artifact_hash_value = _optional_string(pending.get("artifact_hash"))
        if artifact_id is None or artifact_hash_value is None:
            continue
        reason = _optional_string(pending.get("reason")) or "Denied in Claude's native approval prompt."
        saved_policy = _persist_claude_native_permission_policy(
            store=store,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash_value,
            action="block",
            reason=f"Denied in Claude native approval prompt. {reason}",
            now=_now(),
        )
        if not saved_policy:
            continue
        processed_keys.append(pending_key)
        denied += 1
    if processed_keys:
        processed_set = set(processed_keys)
        try:
            with store._connect() as connection:
                connection.execute("begin immediate")
                for pending_key in processed_keys:
                    connection.execute("delete from sync_state where state_key = ?", (pending_key,))
                row = connection.execute(
                    "select payload_json from sync_state where state_key = ?",
                    (index_key,),
                ).fetchone()
                current_keys = _sync_payload_list_from_row(row)
                remaining_keys = [pending_key for pending_key in current_keys if pending_key not in processed_set]
                if remaining_keys:
                    connection.execute(
                        """
                        insert into sync_state (state_key, payload_json, updated_at)
                        values (?, ?, ?)
                        on conflict(state_key) do update set
                          payload_json = excluded.payload_json,
                          updated_at = excluded.updated_at
                        """,
                        (index_key, json.dumps(remaining_keys), _now()),
                    )
                else:
                    connection.execute("delete from sync_state where state_key = ?", (index_key,))
        except (OSError, sqlite3.Error):
            return denied
    return denied


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


def _normalize_claude_guard_approval_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


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


def _claude_guard_prompt_contract_from_pending(
    pending: dict[str, object],
) -> tuple[str, str, tuple[str, ...]] | None:
    header = _optional_string(pending.get("approval_header"))
    question = _optional_string(pending.get("approval_question"))
    approval_code = _optional_string(pending.get("approval_code"))
    options = _claude_guard_approval_options_from_value(pending.get("approval_options"))
    if approval_code is None:
        if header is None and question is None and not options:
            return (
                _CLAUDE_GUARD_APPROVAL_HEADER,
                "HOL Guard intercepted this sensitive action. What should Claude do?",
                _CLAUDE_GUARD_APPROVAL_OPTIONS,
            )
        if header is None or question is None or not options:
            return None
        expected_question = "HOL Guard intercepted this sensitive action. What should Claude do?"
    else:
        if header is None or question is None or not options:
            return None
        expected_question = _claude_guard_approval_question_text(approval_code)
    normalized_expected_options = tuple(
        _normalize_claude_guard_approval_text(option) for option in _CLAUDE_GUARD_APPROVAL_OPTIONS
    )
    normalized_pending_options = tuple(_normalize_claude_guard_approval_text(option) for option in options)
    if _normalize_claude_guard_approval_text(question) != _normalize_claude_guard_approval_text(expected_question):
        return None
    if normalized_pending_options != normalized_expected_options:
        return None
    return header, question, options


def _claude_guard_prompt_contract_from_question_list(
    payload_section: object,
) -> tuple[str, str, tuple[str, ...]] | None:
    if not isinstance(payload_section, dict):
        return None
    questions = payload_section.get("questions")
    if not isinstance(questions, list) or len(questions) != 1:
        return None
    first_question = questions[0]
    if not isinstance(first_question, dict):
        return None
    header = _optional_string(first_question.get("header"))
    question = _optional_string(first_question.get("question"))
    options = _claude_guard_approval_options_from_value(first_question.get("options"))
    if header is None or question is None or not options:
        return None
    return header, question, options


def _claude_guard_prompt_contract_matches(
    expected_contract: tuple[str, str, tuple[str, ...]],
    actual_contract: tuple[str, str, tuple[str, ...]],
) -> bool:
    expected_header, expected_question, expected_options = expected_contract
    actual_header, actual_question, actual_options = actual_contract
    if _normalize_claude_guard_approval_text(actual_header) != _normalize_claude_guard_approval_text(expected_header):
        return False
    if _normalize_claude_guard_approval_text(actual_question) != _normalize_claude_guard_approval_text(
        expected_question
    ):
        return False
    expected_labels = tuple(_normalize_claude_guard_approval_text(option) for option in expected_options)
    actual_labels = tuple(_normalize_claude_guard_approval_text(option) for option in actual_options)
    return actual_labels == expected_labels


def _is_claude_guard_approval_question(
    payload: dict[str, object],
    pending: dict[str, object],
) -> bool:
    if _hook_event_name(payload) != "PostToolUse":
        return False
    tool_name = _optional_string(payload.get("tool_name"))
    if tool_name is None or tool_name.lower() != "askuserquestion":
        return False
    expected_contract = _claude_guard_prompt_contract_from_pending(pending)
    if expected_contract is None:
        return False
    tool_input_contract = _claude_guard_prompt_contract_from_question_list(payload.get("tool_input"))
    if tool_input_contract is None:
        return False
    if not _claude_guard_prompt_contract_matches(expected_contract, tool_input_contract):
        return False
    response_contract = _claude_guard_prompt_contract_from_question_list(payload.get("tool_response"))
    return response_contract is None or _claude_guard_prompt_contract_matches(expected_contract, response_contract)


def _claude_guard_approval_action_for_answer(answer_text: str) -> str | None:
    normalized_answer = _normalize_claude_guard_approval_text(answer_text)
    if normalized_answer == _normalize_claude_guard_approval_text("Keep blocked"):
        return "block"
    if normalized_answer in {
        _normalize_claude_guard_approval_text("Allow once"),
        _normalize_claude_guard_approval_text("Allow during this session"),
    }:
        return "allow"
    return None


def _claude_guard_answer_text_from_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, dict):
        label = _optional_string(value.get("label"))
        if label is not None:
            return label
    return None


def _claude_guard_approval_answer(payload: dict[str, object], *, expected_question: str | None = None) -> str | None:
    response = payload.get("tool_response")
    answer_text: str | None = None
    if isinstance(response, dict):
        answers = response.get("answers")
        if isinstance(answers, dict):
            normalized_expected_question = (
                _normalize_claude_guard_approval_text(expected_question) if isinstance(expected_question, str) else None
            )
            if normalized_expected_question is not None:
                for question, answer in answers.items():
                    if not isinstance(question, str):
                        continue
                    if _normalize_claude_guard_approval_text(question) != normalized_expected_question:
                        continue
                    parsed_answer_text = _claude_guard_answer_text_from_value(answer)
                    if parsed_answer_text is not None:
                        answer_text = parsed_answer_text
                        break
            if answer_text is None and len(answers) == 1:
                only_answer = next(iter(answers.values()))
                answer_text = _claude_guard_answer_text_from_value(only_answer)
        if answer_text is None:
            for key in ("answer", "selected_answer", "selected", "choice", "value", "label"):
                value = response.get(key)
                parsed_answer_text = _claude_guard_answer_text_from_value(value)
                if parsed_answer_text is not None:
                    answer_text = parsed_answer_text
                    break
        if answer_text is None and "questions" not in response and "options" not in response:
            content = response.get("content")
            if isinstance(content, str) and content.strip():
                answer_text = content
    elif isinstance(response, str) and response.strip():
        answer_text = response
    if answer_text is None:
        return None
    return _claude_guard_approval_action_for_answer(answer_text)


def _persist_claude_guard_question_decision(store: GuardStore, payload: dict[str, object]) -> bool:
    pending_pair = _load_single_claude_pending_permission(store, payload)
    if pending_pair is None:
        return False
    pending_key, pending = pending_pair
    approval_code = _optional_string(pending.get("approval_code"))
    if approval_code is None and pending.get("permission_prompt_seen") is not True:
        return False
    if not _is_claude_guard_approval_question(payload, pending):
        return False
    action = _claude_guard_approval_answer(
        payload,
        expected_question=_optional_string(pending.get("approval_question")),
    )
    if action is None:
        return False
    artifact_id = _optional_string(pending.get("artifact_id"))
    artifact_hash_value = _optional_string(pending.get("artifact_hash"))
    if artifact_id is None or artifact_hash_value is None:
        return False
    artifact_type = _optional_string(pending.get("artifact_type"))
    saved = _persist_claude_native_permission_policy(
        store=store,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash_value,
        artifact_type=artifact_type,
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
    policy_action = _runtime_artifact_policy_action(config, runtime_artifact, args.harness)
    package_evaluation = None
    if runtime_artifact.artifact_type == "package_request":
        package_evaluation = evaluate_package_request_artifact(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
        )
        if guard_action_severity(package_evaluation.policy_action) > guard_action_severity(policy_action):
            policy_action = package_evaluation.policy_action
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
    "_claude_guard_answer_text_from_value",
    "_claude_guard_approval_action_for_answer",
    "_claude_guard_approval_answer",
    "_claude_guard_approval_options_from_value",
    "_claude_guard_approval_question_message",
    "_claude_guard_prompt_contract_from_pending",
    "_claude_guard_prompt_contract_from_question_list",
    "_claude_guard_prompt_contract_matches",
    "_claude_native_pretooluse_terminal_notice",
    "_claude_permission_notice_prefers_ask_user_question",
    "_claude_permission_prompt_additional_context",
    "_claude_permission_prompt_system_message",
    "_claude_permission_prompt_terminal_notice",
    "_claude_permission_request_additional_context",
    "_claude_permission_request_system_message",
    "_claude_permission_request_terminal_notice",
    "_is_claude_guard_approval_question",
    "_is_claude_permission_prompt_notification",
    "_is_claude_permission_request",
    "_normalize_claude_guard_approval_text",
    "_persist_claude_guard_question_decision",
    "_persist_claude_pending_permission_denials",
    "_resolve_claude_permission_request_policy_action",
]
