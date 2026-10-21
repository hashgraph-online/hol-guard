"""Resident consumer decision queries and mechanical result projection."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any, cast

from ..config import GuardConfig
from ..models import GuardAction
from ..native_consumer_artifact_compose import NativeConsumerComposeError
from ..runtime.decisions import AuthoritativeGuardDecision, project_native_authoritative_decision
from ..runtime.signals import RiskSignalV2
from ..store import GuardStore

_SAVED_DECISION_KEYS = ("action", "artifact_hash", "scope", "fresh_local_approval", "durable_exact_approval")


_QUALIFICATION_KEYS = ("fresh_local_approval", "durable_exact_approval")


_COMPOSE_UNAVAILABLE_REASON = "consumer_artifact_compose_unavailable"


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

    Without an answer the artifact blocks (``compose_unavailable`` carries the
    reason) so the evaluation still completes instead of aborting midway.
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
        return {
            "current_action": "block",
            "scanner_action": None,
            "verdict": {
                "action": "block",
                "confidence": 0.0,
                "evidence_sources": [],
                "provenance_state": "none",
                "reasons": ["Guard could not score this artifact, so it stays blocked."],
                "recommended_next_actions": ["open_investigation"],
                "review_priority": "critical",
                "severity": 9,
                "suppressible": False,
            },
            "compose_unavailable": error.code,
        }


def _compose_unavailable_decision(
    code: str,
    *,
    configured_action: str | None,
    scanner_action: GuardAction | None,
    raw_scoring_recommendation: object,
) -> dict[str, object]:
    """Transport refusal presentation when the resident composed nothing.

    No authoritative decision or permission is synthesized. The public report
    blocks the failed evaluation and carries the transport error for diagnosis.
    """

    return {
        "approval_claim": None,
        "approval_reuse": {
            "action": "block",
            "current_action": "block",
            "current_normalization_reason_code": None,
            "original_current_action": "block",
            "original_current_type": "str",
            "original_saved_action": None,
            "original_saved_type": None,
            "reason_code": _COMPOSE_UNAVAILABLE_REASON,
            "saved_action": None,
            "saved_normalization_reason_code": None,
            "should_claim": False,
            "status": "not-applicable",
        },
        "approval_source": "policy",
        "append_pending_claim": False,
        "evaluation_error": {"code": code, "component": "consumer_artifact_compose"},
        "decision_reason": _COMPOSE_UNAVAILABLE_REASON,
        "policy_action": "block",
        "policy_composition": {
            "configured_action": configured_action,
            "current_action": "block",
            "final_action": "block",
            "native_compose_error": code,
            "raw_scoring_recommendation": raw_scoring_recommendation,
            "saved_action": None,
            "saved_state_present": False,
            "scanner_action": scanner_action,
            "scoring_recommendation_non_authoritative": True,
            "trusted_request_override": False,
        },
        "saved_state_present": False,
        "scanner_evidence": [],
        "trusted_request_override": False,
    }


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
) -> dict[str, object]:
    """Gather saved-decision evidence; the resident composes the final authority.

    A failed current-action query, or no answer here, blocks the artifact.
    """

    unavailable = partial(
        _compose_unavailable_decision,
        configured_action=configured_action,
        scanner_action=scanner_action,
        raw_scoring_recommendation=raw_scoring_recommendation,
    )
    if isinstance(compose_unavailable, str):
        return unavailable(compose_unavailable)
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
        return unavailable(error.code)
    pending = inputs.pending_approval_claims
    if answer["append_pending_claim"] is True and saved_decision is not None and pending is not None:
        pending.append((saved_decision, artifact_id, approval_context_hash))
    return answer


def _project_runtime_decision(runtime: dict[str, object]) -> AuthoritativeGuardDecision | None:
    if "authoritative_decision" in runtime:
        return project_native_authoritative_decision(cast(dict[str, Any], runtime["authoritative_decision"]))
    if "evaluation_error" in runtime:
        return None
    raise ValueError("native_consumer_artifact_compose_authoritative_decision_missing")


def _runtime_artifact_projection(
    runtime: dict[str, object], decision: AuthoritativeGuardDecision | None
) -> dict[str, object]:
    if decision is not None:
        return decision.to_artifact_projection()
    return {
        "policy_action": "block",
        "decision_reason": runtime["decision_reason"],
        "policy_composition": runtime["policy_composition"],
        "evaluation_error": runtime["evaluation_error"],
    }
