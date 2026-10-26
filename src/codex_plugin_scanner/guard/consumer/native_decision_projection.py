"""Resident consumer decision queries.

Python gathers the saved-decision evidence; the resident composes the decision
and, through the projection op, decides what it means for the artifact.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from ..config import GuardConfig
from ..models import GuardAction
from ..native_consumer_artifact_compose import NativeConsumerComposeError
from ..runtime.signals import RiskSignalV2
from ..store import GuardStore

_SAVED_DECISION_KEYS = ("action", "artifact_hash", "scope", "fresh_local_approval", "durable_exact_approval")


_QUALIFICATION_KEYS = ("fresh_local_approval", "durable_exact_approval")


def _native_current_action(
    store: GuardStore,
    config: GuardConfig,
    *,
    removed: bool,
    artifact_type: str | None,
    configured_action: str | None,
    guard_default_action: str | None,
    first_seen: bool,
    changed: bool,
    effective_default_action: GuardAction | None,
    skill_directory_identity_reusable: bool | None,
    scoring: Mapping[str, object],
    composer: Callable[..., dict[str, object]],
    low_trust_action: str | None = None,
) -> dict[str, object]:
    """Ask the resident for the scoring recommendation and current action.

    Without an answer the artifact blocks unscored (``compose_unavailable``
    carries the reason) so the evaluation still completes instead of aborting
    midway; the resident's outcome query presents the refusal.
    """

    try:
        return composer(
            "current_action",
            {
                "removed": removed,
                "artifact_type": artifact_type,
                "configured_action": configured_action,
                "guard_default_action": guard_default_action,
                "first_seen": first_seen,
                "changed": changed,
                "effective_default_action": effective_default_action,
                "config_changed_hash_action": config.changed_hash_action,
                "config_default_action": config.default_action,
                "skill_directory_identity_reusable": skill_directory_identity_reusable,
                **scoring,
                # Sent only when set, so requests without it keep their digest.
                **({"low_trust_action": low_trust_action} if low_trust_action is not None else {}),
            },
            guard_home=getattr(store, "guard_home", None),
        )
    except NativeConsumerComposeError as error:
        return {"current_action": "block", "scanner_action": None, "verdict": None, "compose_unavailable": error.code}


@dataclass(frozen=True)
class _ConsumerAuthorityInputs:
    """Per-evaluation authority evidence shared by every artifact query."""

    store: GuardStore
    harness: str
    workspace: str | None
    now: str
    trusted_request_overrides: Mapping[str, str]
    claimed_saved_approval_overrides: Mapping[str, str]
    retained_saved_approval_overrides: Mapping[str, str]
    saved_approval_qualification_overrides: Mapping[str, Mapping[str, object]]
    runtime_detector_composition: dict[str, object] | None
    runtime_detector_block_reason: str | None
    runtime_signals: list[dict[str, object]]
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] | None


def _native_runtime_decision(
    inputs: _ConsumerAuthorityInputs,
    *,
    artifact_id: str,
    approval_context_hash: str,
    publisher: str | None,
    memory_command: str | None,
    memory_artifact_type: str | None,
    memory_artifact_name: str | None,
    current_action: GuardAction,
    configured_action: str | None,
    scanner_action: GuardAction | None,
    raw_scoring_recommendation: object,
    skill_directory_identity_reusable: bool | None,
    compose_unavailable: object = None,
    decision_signals: Sequence[RiskSignalV2] = (),
    composer: Callable[..., dict[str, object]],
) -> dict[str, object] | str:
    """Gather saved-decision evidence; the resident composes the final authority.

    Returns the composed answer, or the error code of a failed current-action
    query or of this one; the artifact then blocks.
    """

    if isinstance(compose_unavailable, str):
        return compose_unavailable
    store = inputs.store
    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        inputs.harness,
        artifact_id,
        artifact_hash=approval_context_hash,
        workspace=inputs.workspace,
        publisher=publisher,
        now=inputs.now,
        memory_command=memory_command,
        memory_artifact_type=memory_artifact_type,
        memory_artifact_name=memory_artifact_name,
        consume_one_shot=False,
    )
    saved_decision = lookup["decision"]
    ignored_integrity = lookup["ignored_local_integrity"] is not None
    diagnosed_reason = (
        store.approval_reuse_validation_reason(
            inputs.harness,
            artifact_id,
            approval_context_hash,
            inputs.workspace,
            publisher,
            inputs.now,
        )
        if saved_decision is None and not ignored_integrity
        else None
    )
    qualification = inputs.saved_approval_qualification_overrides.get(artifact_id)
    try:
        answer = composer(
            "runtime_authoritative",
            {
                "signals": [signal.to_dict() for signal in decision_signals],
                "runtime": {
                    "current_action": current_action,
                    "configured_action": configured_action,
                    "scanner_action": scanner_action,
                    "raw_scoring_recommendation": raw_scoring_recommendation,
                    "skill_directory_identity_reusable": skill_directory_identity_reusable,
                    "approval_context_hash": approval_context_hash,
                    "saved_decision": (
                        None
                        if saved_decision is None
                        else {key: saved_decision.get(key) for key in _SAVED_DECISION_KEYS}
                    ),
                    "ignored_local_integrity": ignored_integrity,
                    "diagnosed_reason": diagnosed_reason,
                    "trusted_request_override_hash": inputs.trusted_request_overrides.get(artifact_id),
                    "claimed_saved_approval_hash": inputs.claimed_saved_approval_overrides.get(artifact_id),
                    "retained_saved_approval_hash": inputs.retained_saved_approval_overrides.get(artifact_id),
                    "saved_approval_qualification": (
                        None
                        if qualification is None
                        else {key: qualification.get(key) is True for key in _QUALIFICATION_KEYS}
                    ),
                    "runtime_detector_composition": inputs.runtime_detector_composition,
                    "runtime_detector_block_reason": inputs.runtime_detector_block_reason,
                    "runtime_signals": inputs.runtime_signals,
                },
            },
            guard_home=getattr(store, "guard_home", None),
        )
    except NativeConsumerComposeError as error:
        return error.code
    pending = inputs.pending_approval_claims
    if answer["append_pending_claim"] is True and saved_decision is not None and pending is not None:
        pending.append((saved_decision, artifact_id, approval_context_hash))
    return answer
