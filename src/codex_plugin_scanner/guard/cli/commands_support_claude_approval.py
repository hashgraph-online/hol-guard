"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..runtime.package_request_evaluation import PackageRequestEvaluation
    from ._commands_shared import _now
    from .commands_support_hook_state import (
        _load_single_claude_pending_permission,
        _remove_claude_pending_permission,
    )
    from .commands_support_permission_store import _persist_claude_native_permission_policy
    from .commands_support_runtime_artifacts import _hook_event_name, _optional_string
    from .commands_support_runtime_policy import _runtime_artifact_policy_action
    from .commands_support_runtime_resolution import _canonical_harness_name


from ..native_claude_guard_question import ClaudeGuardQuestionVerdict, claude_guard_question_verdict
from ._commands_shared import *
from .commands_parser_helpers import *

# The copy for a render the resident could not answer. Every piece of Claude
# approval text below says Guard is holding the request, so an unreachable
# resident never leaves a prompt reading as though Guard allowed the action.
_CLAUDE_COPY_UNAVAILABLE = (
    "HOL Guard is holding this Claude request for review. The HOL Guard runtime could not render "
    "the full notice, so nothing in this prompt should be read as HOL Guard allowing the action."
)


def _claude_approval_copy(
    which: str,
    *,
    payload: dict[str, object] | None = None,
    notice: dict[str, object] | None = None,
    reason: str = "",
) -> object | None:
    from ..native_hook_render import native_claude_approval_copy

    return native_claude_approval_copy(which, payload=payload, notice=notice, reason=reason)


def _claude_approval_text(
    which: str,
    *,
    payload: dict[str, object] | None = None,
    notice: dict[str, object] | None = None,
    reason: str = "",
) -> str:
    rendered = _claude_approval_copy(which, payload=payload, notice=notice, reason=reason)
    return rendered if isinstance(rendered, str) else _CLAUDE_COPY_UNAVAILABLE


def _claude_guard_approval_question_message(notice: dict[str, object] | None) -> str:
    return _claude_approval_text("approval_question_message", notice=notice)


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
    pending = pending_pair[1]
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
        _remove_claude_pending_permission(store, session_id=session_id, artifact_id=artifact_id)
    return True


def _claude_permission_notice_prefers_ask_user_question(notice: dict[str, object]) -> bool:
    # A render the resident cannot answer falls back to the Guard approval
    # question, which denies Claude's own dialog; the deferring branch is the
    # one that would hand the decision back to Claude.
    rendered = _claude_approval_copy("notice_prefers_ask_user_question", notice=notice)
    return rendered if isinstance(rendered, bool) else True


def _claude_permission_request_artifact_policy(
    *,
    config: GuardConfig,
    store: GuardStore,
    args: argparse.Namespace,
    runtime_artifact: GuardArtifact,
    runtime_workspace: Path | None,
) -> tuple[dict[str, object], PackageRequestEvaluation | None]:
    """The artifact policy facts the resident asked for, and the package evaluation.

    The resident composes the verdict from these; the evaluation is kept only
    for the reason the response shows.
    """

    config_action = _runtime_artifact_policy_action(config, runtime_artifact, args.harness, guard_home=store.guard_home)
    package_evaluation = None
    if runtime_artifact.artifact_type == "package_request":
        package_evaluation = evaluate_package_request_artifact(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
        )
    facts: dict[str, object] = {
        "config_action": config_action,
        "package_action": None if package_evaluation is None else package_evaluation.policy_action,
    }
    return facts, package_evaluation


def _claude_permission_request_reason_stub(
    *,
    args: argparse.Namespace,
    runtime_artifact: GuardArtifact,
    artifact_action: str,
    package_evaluation: PackageRequestEvaluation | None,
) -> dict[str, object]:
    """The fields the artifact's review reason is rendered from."""

    stub: dict[str, object] = {
        "harness": _canonical_harness_name(args.harness),
        "policy_action": artifact_action,
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
    return stub


def _claude_permission_request_terminal_notice(
    *,
    payload: dict[str, object],
    native_reason: str,
) -> str:
    return _claude_approval_text("permission_request_terminal_notice", payload=payload, reason=native_reason)


def _claude_permission_request_system_message(
    *,
    payload: dict[str, object],
    native_reason: str,
) -> str:
    return _claude_approval_text("permission_request_system_message", payload=payload, reason=native_reason)


def _claude_permission_request_additional_context(native_reason: str) -> str:
    return _claude_approval_text("permission_request_additional_context", reason=native_reason)


def _claude_permission_prompt_system_message(
    *,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> str:
    return _claude_approval_text("permission_prompt_system_message", payload=payload, notice=notice)


def _claude_permission_prompt_additional_context(notice: dict[str, object] | None) -> str:
    return _claude_approval_text("permission_prompt_additional_context", notice=notice)


def _claude_permission_prompt_terminal_notice(
    *,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> str:
    return _claude_approval_text("permission_prompt_terminal_notice", payload=payload, notice=notice)


def _claude_native_pretooluse_terminal_notice(*, payload: dict[str, object], reason: str) -> str:
    return _claude_approval_text("native_pretooluse_terminal_notice", payload=payload, reason=reason)


__all__ = [
    "_claude_guard_approval_question_message",
    "_claude_guard_question_verdict",
    "_claude_native_pretooluse_terminal_notice",
    "_claude_permission_notice_prefers_ask_user_question",
    "_claude_permission_prompt_additional_context",
    "_claude_permission_prompt_system_message",
    "_claude_permission_prompt_terminal_notice",
    "_claude_permission_request_additional_context",
    "_claude_permission_request_artifact_policy",
    "_claude_permission_request_reason_stub",
    "_claude_permission_request_system_message",
    "_claude_permission_request_terminal_notice",
    "_persist_claude_guard_question_decision",
]
