"""Best-effort command activity recording at hook orchestration boundaries."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from ..action_lattice import guard_action_severity
from ..models import GuardAction
from ..runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    CommandExecutionStatus,
)
from ..runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
)
from ..runtime.command_activity_lifecycle import (
    CommandActivityDecisionFacts,
    build_correlated_post_activity,
    build_pre_hook_evidence,
    build_unpaired_post_evidence,
)
from ..runtime.command_evaluation import CompositeCommandEvaluation, evaluate_command
from ..runtime.command_shadow_evaluation import (
    CommandShadowObservation,
    baseline_command_shadow_proposal,
    build_command_shadow_observation,
    load_command_shadow_control,
)
from ..runtime.secret_file_requests import extract_sensitive_tool_action_request
from ..store import GuardStore

_PRE_HOOK_EVENTS = frozenset({"PreToolUse", "preToolUse", "copilotPermissionRequest"})
_POST_HOOK_EVENTS = frozenset(
    {
        "PostToolUse",
        "PostToolUseFailure",
        "postToolUse",
        "afterShellExecution",
        "afterMCPExecution",
    }
)


def record_pre_hook_command_activity_best_effort(
    *,
    store: GuardStore,
    guard_home: Path,
    harness: str,
    event: str,
    payload: Mapping[str, object],
    policy_action: GuardAction,
    receipt_id: str | None,
    prompted: bool,
    approval_reuse_status: ActivityApprovalReuseStatus = ActivityApprovalReuseStatus.NOT_APPLICABLE,
    workflow_authorization_claimed: bool = False,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    """Record matched pre-hook evidence without allowing analytics to affect enforcement."""

    try:
        if event not in _PRE_HOOK_EVENTS:
            return False
        evaluation = _evaluate_payload_command(
            payload,
            cwd=cwd,
            home_dir=home_dir,
        )
        if evaluation is None:
            return False
        key = load_or_create_installation_correlation_key(guard_home)
        correlation = derive_proven_request_correlation(
            harness=harness,
            event=event,
            payload=payload,
            key=key,
        )
        activity_id = _activity_id()
        occurred_at = _utc_now()
        evidence = build_pre_hook_evidence(
            evaluation,
            CommandActivityDecisionFacts(
                policy_action=policy_action,
                decision_reason_code=_activity_decision_reason(
                    evaluation,
                    policy_action=policy_action,
                    workflow_authorization_claimed=workflow_authorization_claimed,
                ),
                prompted=prompted,
                approval_reuse_status=approval_reuse_status,
                receipt_id=receipt_id,
                workflow_authorization_claimed=workflow_authorization_claimed,
            ),
            activity_id=activity_id,
            occurred_at=occurred_at,
            harness=harness,
            request_correlation=correlation,
        )
        if correlation is not None and store.is_exact_command_activity_pre_replay(evidence):
            return False
        shadow, shadow_failed = _build_shadow_best_effort(
            evaluation=evaluation,
            policy_action=policy_action,
            activity_id=activity_id,
            occurred_at=occurred_at,
        )
        try:
            recorded = store.record_command_activity(
                evidence,
                shadow=shadow,
                shadow_evaluation_succeeded=not shadow_failed,
            )
        except Exception:
            if correlation is not None and store.is_exact_command_activity_pre_replay(evidence):
                return False
            raise
        if shadow_failed:
            _record_persistence_failure(store, "shadow_evaluation_failed")
        return recorded
    except Exception:
        _record_persistence_failure(store, "pre_record_failed")
        return False


def record_post_hook_command_activity_best_effort(
    *,
    store: GuardStore,
    guard_home: Path,
    harness: str,
    event: str,
    payload: Mapping[str, object],
    succeeded: bool,
) -> bool:
    """Transition strong pairs or record a fact-minimal unpaired command post."""

    try:
        if event not in _POST_HOOK_EVENTS:
            return False
        key = load_or_create_installation_correlation_key(guard_home)
        correlation = derive_proven_request_correlation(
            harness=harness,
            event=event,
            payload=payload,
            key=key,
        )
        if correlation is not None:
            previous = store.get_command_activity_by_request_correlation(correlation)
            if previous is not None:
                if previous.execution_status is CommandExecutionStatus.PREVENTED:
                    return False
                expected_status = (
                    CommandExecutionStatus.CONFIRMED_SUCCESS if succeeded else CommandExecutionStatus.CONFIRMED_FAILURE
                )
                if previous.execution_status is expected_status:
                    return False
                if previous.execution_status is not CommandExecutionStatus.ALLOWED_UNCONFIRMED:
                    raise ValueError("post-hook proof conflicts with persisted command lifecycle")
                current = build_correlated_post_activity(
                    previous,
                    request_correlation=correlation,
                    succeeded=succeeded,
                )
                return store.transition_command_activity(current)
        if _payload_command_text(payload) is None:
            return False
        evidence = build_unpaired_post_evidence(
            activity_id=_activity_id(),
            occurred_at=_utc_now(),
            harness=harness,
            succeeded=succeeded,
        )
        return store.record_command_activity(evidence)
    except Exception:
        _record_persistence_failure(store, "post_record_failed")
        return False


def hook_post_succeeded(event: str, payload: Mapping[str, object]) -> bool:
    """Interpret only bounded native failure signals; absence means success."""

    if "failure" in event.strip().lower():
        return False
    for key in ("is_error", "isError", "failed"):
        if payload.get(key) is True:
            return False
    if payload.get("success") is False:
        return False
    exit_code = payload.get("exit_code", payload.get("exitCode"))
    return not (type(exit_code) is int and exit_code != 0)


def hook_is_post_event(event: str) -> bool:
    return event in _POST_HOOK_EVENTS


def hook_is_pre_event(event: str) -> bool:
    return event in _PRE_HOOK_EVENTS


def command_activity_was_prompted(
    initial_policy_action: GuardAction,
    approval_reuse_status: ActivityApprovalReuseStatus,
) -> bool:
    """Report an actual prompt, excluding approvals reused without interaction."""

    return approval_reuse_status is not ActivityApprovalReuseStatus.ACCEPTED and guard_action_severity(
        initial_policy_action
    ) >= guard_action_severity("review")


def _activity_decision_reason(
    evaluation: CompositeCommandEvaluation,
    *,
    policy_action: GuardAction,
    workflow_authorization_claimed: bool,
) -> ActivityDecisionReason:
    if workflow_authorization_claimed and policy_action == "allow":
        return ActivityDecisionReason.CAPABILITY
    if not evaluation.matches:
        return ActivityDecisionReason.NO_MATCH
    if evaluation.command.confidence == "exact":
        return ActivityDecisionReason.EXTENSION_MATCH
    return ActivityDecisionReason.UNCERTAINTY


def record_command_activity_failure_best_effort(store: GuardStore, error_code: str) -> None:
    """Count an analytics-boundary failure without affecting hook enforcement."""

    _record_persistence_failure(store, error_code)


def _build_shadow_best_effort(
    *,
    evaluation: CompositeCommandEvaluation,
    policy_action: GuardAction,
    activity_id: str,
    occurred_at: datetime,
) -> tuple[CommandShadowObservation | None, bool]:
    try:
        proposal = baseline_command_shadow_proposal(evaluation)
        return (
            build_command_shadow_observation(
                evaluation,
                authoritative_action=policy_action,
                proposal=proposal,
                activity_id=activity_id,
                occurred_at=occurred_at,
                control=load_command_shadow_control(),
            ),
            False,
        )
    except Exception:
        return None, True


def _evaluate_payload_command(
    payload: Mapping[str, object],
    *,
    cwd: Path | None,
    home_dir: Path | None,
):
    arguments = payload.get("tool_input", payload.get("arguments"))
    request = extract_sensitive_tool_action_request(
        payload.get("tool_name"),
        arguments,
        cwd=cwd,
        home_dir=home_dir,
    )
    if request is not None:
        command_text = request.raw_command_text or request.command_text
        return evaluate_command(
            command_text,
            canonical_command=(request.canonical_command if request.raw_command_text is None else None),
            compatibility_action_class=request.action_class,
            compatibility_reason=request.reason,
        )
    command_text = _payload_command_text(payload)
    if command_text is None:
        return None
    return evaluate_command(command_text)


def _payload_command_text(payload: Mapping[str, object]) -> str | None:
    arguments = payload.get("tool_input", payload.get("arguments"))
    if isinstance(arguments, Mapping):
        command_arguments = cast(Mapping[object, object], arguments)
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = command_arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value
    for key in ("command", "cmd"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _record_persistence_failure(store: GuardStore, error_code: str) -> None:
    with suppress(Exception):
        store.record_command_activity_persistence_failure(error_code=error_code, occurred_at=_utc_now())


def _activity_id() -> str:
    return f"activity:{secrets.token_hex(16)}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "command_activity_was_prompted",
    "hook_is_post_event",
    "hook_is_pre_event",
    "hook_post_succeeded",
    "record_command_activity_failure_best_effort",
    "record_post_hook_command_activity_best_effort",
    "record_pre_hook_command_activity_best_effort",
]
