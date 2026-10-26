"""Best-effort command activity recording at hook orchestration boundaries."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from ..models import GuardAction
from ..runtime.command_activity_contract import (
    CommandExecutionStatus,
    CorrelationHandle,
)
from ..runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
)
from ..runtime.command_activity_display import build_invocation_preview_from_payload
from ..runtime.command_activity_lifecycle import (
    build_correlated_post_activity,
    build_unpaired_post_evidence,
)
from ..runtime.command_evaluation import CompositeCommandEvaluation
from ..runtime.command_shadow_evaluation import (
    CommandShadowObservation,
    baseline_command_shadow_proposal,
    build_command_shadow_observation,
    load_command_shadow_control,
)
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


def record_post_hook_command_activity_best_effort(
    *,
    store: GuardStore,
    guard_home: Path,
    harness: str,
    event: str,
    payload: Mapping[str, object],
    succeeded: bool,
    raise_on_persistence_error: bool = False,
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
        return persist_deferred_post_hook_command_activity(
            store=store,
            harness=harness,
            correlation=correlation,
            succeeded=succeeded,
            has_command=_payload_command_text(payload) is not None,
            invocation_preview=build_invocation_preview_from_payload(payload),
        )
    except Exception:
        _record_persistence_failure(store, "post_record_failed")
        if raise_on_persistence_error:
            raise
        return False


def persist_deferred_post_hook_command_activity(
    *,
    store: GuardStore,
    harness: str,
    correlation: CorrelationHandle | None,
    succeeded: bool,
    has_command: bool,
    invocation_preview: str | None = None,
) -> bool:
    """Persist a sanitized deferred post-hook record."""

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
                store.record_command_activity_observation_conflict(occurred_at=_utc_now())
                return False
            current = build_correlated_post_activity(
                previous,
                request_correlation=correlation,
                succeeded=succeeded,
            )
            return store.transition_command_activity(current)
    if not has_command:
        return False
    evidence = build_unpaired_post_evidence(
        activity_id=_activity_id(),
        occurred_at=_utc_now(),
        harness=harness,
        succeeded=succeeded,
    )
    return store.record_command_activity(evidence, invocation_preview=invocation_preview)


def hook_post_succeeded(event: str, payload: Mapping[str, object]) -> bool:
    """Interpret only bounded native failure signals; absence means success."""

    if "failure" in event.strip().lower():
        return False
    for name in ("hook_event_name", "hookEventName"):
        raw_event = payload.get(name)
        if isinstance(raw_event, str) and raw_event.replace("_", "").replace("-", "").lower() == "posttoolusefailure":
            return False
    for key in ("is_error", "isError", "failed"):
        if payload.get(key) is True:
            return False
    if payload.get("success") is False:
        return False
    exit_code = payload.get("exit_code", payload.get("exitCode"))
    return not (type(exit_code) is int and exit_code != 0)


def _build_shadow_best_effort(
    *,
    evaluation: CompositeCommandEvaluation,
    command_text: str | None,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
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
    "hook_post_succeeded",
    "persist_deferred_post_hook_command_activity",
    "record_post_hook_command_activity_best_effort",
]
