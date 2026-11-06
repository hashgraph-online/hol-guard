"""Guard wrapper-mode run orchestration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..models import HarnessDetection
from ..store import GuardStore
from . import runner_native_authority as _authority
from .actions import GuardActionEnvelope
from .approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED,
)
from .guard_run_evaluation import (
    _detection_with_prompt_artifacts,
    _evaluation_with_action_envelope,
    _evaluation_with_detector_registry,
    _guard_run_action_envelope,
    detect_harness,
    evaluate_detection,
)
from .guard_run_launch import (
    _guard_run_finalize_authorized_launch_plan,
    _guard_run_launch_previews,
    _GuardRunLaunchPlan,
)
from .guard_run_receipts import _append_authority_evidence_to_receipts, _receipt_rowid_cursor
from .wrapper_run_finish import finish_guard_run

_APPROVAL_METADATA_KEYS = (
    "approval_center_url",
    "approval_delivery",
    "approval_queue_unavailable",
    "approval_requests",
    "approval_wait",
    "daemon_queue_unavailable",
    "review_hint",
)


def _copy_approval_metadata(target: dict[str, Any], resolved: Mapping[str, Any]) -> None:
    for key in _APPROVAL_METADATA_KEYS:
        if key in resolved:
            target[key] = resolved[key]


def _detector_pass(
    detection: HarnessDetection,
    store: GuardStore,
    config: GuardConfig,
    *,
    default_action: str | None,
    action_envelope: GuardActionEnvelope,
    context: HarnessContext,
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] | None = None,
) -> tuple[dict[str, Any], Any, GuardConfig]:
    base_evaluation = evaluate_detection(
        detection,
        store,
        config,
        default_action=default_action,
        persist=False,
        pending_approval_claims=pending_approval_claims,
    )
    detector_evaluation = _evaluation_with_detector_registry(base_evaluation, action_envelope, context, config)
    detector_authority = _authority.detector_authority(detector_evaluation)
    authority_config = config
    if detector_authority.action in {"warn", "review"}:
        authority_config = _authority.config_with_current_authority(config, base_evaluation, detector_authority.action)
    return detector_evaluation, detector_authority, authority_config


def guard_run(
    harness: str,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    dry_run: bool,
    passthrough_args: list[str],
    default_action: str | None = None,
    interactive_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
    blocked_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
    current_config_provider: Callable[[], GuardConfig] | None = None,
) -> dict[str, Any]:
    """Evaluate and launch with native authority bound to the actual store."""

    from ..native_context import bound_context_digest_home

    context = replace(context, guard_home=store.guard_home)
    with bound_context_digest_home(store.guard_home):
        return _guard_run_bound(
            harness,
            context,
            store,
            config,
            dry_run,
            passthrough_args,
            default_action,
            interactive_resolver,
            blocked_resolver,
            current_config_provider,
        )


def _guard_run_bound(
    harness: str,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    dry_run: bool,
    passthrough_args: list[str],
    default_action: str | None = None,
    interactive_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
    blocked_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
    current_config_provider: Callable[[], GuardConfig] | None = None,
) -> dict[str, Any]:
    """Evaluate local harness state and optionally launch the harness."""

    # `guard run` is often the first native caller in a fresh install and the
    # resident refuses requests until this store's verifier key exists. Reuse the
    # publisher's store-derived bootstrap; never substitute Python authority.
    from ..native_policy_snapshot_publisher import provision_native_verifier_key_for_store

    provision_native_verifier_key_for_store(store)
    detection = _detection_with_prompt_artifacts(detect_harness(harness, context), context, passthrough_args)
    launch_plan: _GuardRunLaunchPlan | None = None
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] = []
    action_envelope = _guard_run_action_envelope(harness, context, passthrough_args)
    detector_evaluation, detector_authority, authority_config = _detector_pass(
        detection,
        store,
        config,
        default_action=default_action,
        action_envelope=action_envelope,
        context=context,
        pending_approval_claims=pending_approval_claims,
    )
    detector_action = detector_authority.action
    detector_context = detector_authority.context
    if detector_context is not None:
        pending_approval_claims = []
        evaluation = evaluate_detection(
            detection,
            store,
            authority_config,
            default_action=default_action,
            persist=False,
            pending_approval_claims=pending_approval_claims,
            runtime_detector_context=detector_context,
        )
        evaluation = _authority.with_recorded_detector_result(evaluation, detector_evaluation)
    else:
        evaluation = detector_evaluation
    authoritative_detector_block = detector_authority.blocked_by_detector
    if evaluation["blocked"]:
        evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)

    resolved_evaluation: dict[str, Any] | None = None
    trusted_request_overrides: dict[str, str] = {}
    trusted_request_override_labels: dict[str, str] = {}
    if (
        not dry_run
        and authoritative_detector_block is None
        and interactive_resolver is not None
        and evaluation["blocked"]
    ):
        resolved_evaluation = interactive_resolver(detection, evaluation)
        trusted_request_overrides, trusted_request_override_labels = _authority.interactive_request_overrides(
            resolved_evaluation
        )
    elif (
        not dry_run and authoritative_detector_block is None and blocked_resolver is not None and evaluation["blocked"]
    ):
        resolved_evaluation = blocked_resolver(detection, evaluation)
        trusted_request_overrides = _authority.exact_request_overrides(resolved_evaluation)
        trusted_request_override_labels = {artifact_id: "approval-center" for artifact_id in trusted_request_overrides}
    if resolved_evaluation is not None:
        # A terminal prompt or browser wait is an authority boundary even when
        # the user chose the unpersisted ``allow-once`` path. Reload policy
        # before applying that exact request override; post-claim refresh below
        # cannot protect an approval that intentionally created no stored row.
        resolution_config_refresh_failed = False
        if current_config_provider is not None:
            try:
                provided_config = current_config_provider()
            except Exception:
                resolution_config_refresh_failed = True
            else:
                if isinstance(provided_config, GuardConfig):
                    config = provided_config
                else:
                    resolution_config_refresh_failed = True
        if resolution_config_refresh_failed:
            trusted_request_overrides = {}
            trusted_request_override_labels = {}
        detection = _detection_with_prompt_artifacts(detect_harness(harness, context), context, passthrough_args)
        detector_evaluation, detector_authority, authority_config = _detector_pass(
            detection,
            store,
            config,
            default_action=default_action,
            action_envelope=action_envelope,
            context=context,
        )
        detector_action = detector_authority.action
        detector_context = detector_authority.context
        pending_approval_claims = []
        evaluation = evaluate_detection(
            detection,
            store,
            authority_config,
            default_action=default_action,
            persist=False,
            trusted_request_overrides=trusted_request_overrides,
            trusted_request_override_labels=trusted_request_override_labels,
            pending_approval_claims=pending_approval_claims,
            runtime_detector_context=detector_context,
        )
        evaluation = _authority.with_recorded_detector_result(evaluation, detector_evaluation)
        authoritative_detector_block = detector_authority.blocked_by_detector
        if evaluation["blocked"]:
            evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)
        _copy_approval_metadata(evaluation, resolved_evaluation)
    if evaluation["blocked"] or dry_run:
        receipt_cursor = _receipt_rowid_cursor(store)
        persisted = evaluate_detection(
            detection,
            store,
            authority_config,
            default_action=default_action,
            persist=True,
            trusted_request_overrides=trusted_request_overrides,
            trusted_request_override_labels=trusted_request_override_labels,
            runtime_detector_context=detector_context,
            runtime_detector_block_reason=authoritative_detector_block,
        )
        if persisted["blocked"]:
            persisted = _evaluation_with_action_envelope(persisted, action_envelope)
        persisted = _authority.with_recorded_detector_result(persisted, detector_evaluation)
        detector_evidence = detector_authority.nonterminal_evidence
        if detector_evidence is not None and detector_action is not None:
            _append_authority_evidence_to_receipts(
                store,
                after_rowid=receipt_cursor,
                evaluation=persisted,
                evidence=detector_evidence,
                approval_source="runtime-detector",
                source_actions=frozenset({detector_action}),
            )
        if resolved_evaluation is not None:
            _copy_approval_metadata(persisted, resolved_evaluation)
        evaluation = persisted
    else:
        decisions_to_claim = [decision for decision, _artifact_id, _artifact_hash in pending_approval_claims]
        preclaim_launch_previews: tuple[_GuardRunLaunchPlan, ...] = ()
        preclaim_signature: dict[str, Any] | None = None
        preclaim_failure_reason: str | None = None
        if decisions_to_claim:
            try:
                preclaim_launch_previews = _guard_run_launch_previews(harness, context, passthrough_args)
            except Exception:
                preclaim_launch_previews = ()
            preclaim_signature = _authority.authority_signature(detection, evaluation, preclaim_launch_previews)
            if preclaim_signature is None:
                preclaim_failure_reason = APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED
            else:
                try:
                    claim_succeeded = store.claim_approval_reuse_decisions(decisions_to_claim, now=_now())
                except Exception:
                    claim_succeeded = False
                if not claim_succeeded:
                    preclaim_failure_reason = APPROVAL_REUSE_CLAIM_FAILED
        if decisions_to_claim and preclaim_failure_reason is not None:
            failed_ids = {artifact_id for _decision, artifact_id, _artifact_hash in pending_approval_claims}
            failure_config = _authority.config_with_current_authority(
                authority_config,
                evaluation,
                "require-reapproval",
                artifact_ids=failed_ids,
            )
            receipt_cursor = _receipt_rowid_cursor(store)
            evaluation = evaluate_detection(
                detection,
                store,
                failure_config,
                default_action=default_action,
                persist=True,
                trusted_request_overrides=trusted_request_overrides,
                trusted_request_override_labels=trusted_request_override_labels,
                runtime_detector_context=detector_context,
                runtime_detector_block_reason=authoritative_detector_block,
            )
            evaluation = _authority.with_recorded_detector_result(evaluation, detector_evaluation)
            evaluation, failure_evidence = _authority.with_preclaim_failure(
                evaluation,
                affected_artifact_ids=failed_ids,
                reason_code=preclaim_failure_reason,
            )
            detector_evidence = detector_authority.nonterminal_evidence
            if detector_evidence is not None and detector_action is not None:
                _append_authority_evidence_to_receipts(
                    store,
                    after_rowid=receipt_cursor,
                    evaluation=evaluation,
                    evidence=detector_evidence,
                    approval_source="runtime-detector",
                    source_actions=frozenset({detector_action}),
                )
            _append_authority_evidence_to_receipts(
                store,
                after_rowid=receipt_cursor,
                evaluation=evaluation,
                evidence=failure_evidence,
                approval_source="approval-reuse",
                source_actions=frozenset({"review", "require-reapproval", "sandbox-required", "block"}),
                replace_existing_source=True,
            )
            if resolved_evaluation is not None:
                _copy_approval_metadata(evaluation, resolved_evaluation)
            evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)
        else:
            consumed_claim_overrides, retained_claim_overrides, saved_approval_qualifications = (
                _authority.claim_partition(pending_approval_claims)
            )
            if decisions_to_claim:
                config_refresh_failed = False
                fresh_config = config
                if current_config_provider is not None:
                    try:
                        provided_config = current_config_provider()
                    except Exception:
                        config_refresh_failed = True
                    else:
                        if isinstance(provided_config, GuardConfig):
                            fresh_config = provided_config
                        else:
                            config_refresh_failed = True
                detection = _detection_with_prompt_artifacts(
                    detect_harness(harness, context),
                    context,
                    passthrough_args,
                )
                fresh_detector_evaluation, fresh_detector_authority, fresh_authority_config = _detector_pass(
                    detection,
                    store,
                    fresh_config,
                    default_action=default_action,
                    action_envelope=action_envelope,
                    context=context,
                )
                fresh_detector_action = fresh_detector_authority.action
                fresh_detector_context = fresh_detector_authority.context
                fresh_evaluation = evaluate_detection(
                    detection,
                    store,
                    fresh_authority_config,
                    default_action=default_action,
                    persist=False,
                    trusted_request_overrides=trusted_request_overrides,
                    trusted_request_override_labels=trusted_request_override_labels,
                    claimed_saved_approval_overrides=consumed_claim_overrides,
                    retained_saved_approval_overrides=retained_claim_overrides,
                    saved_approval_qualification_overrides=saved_approval_qualifications,
                    runtime_detector_context=fresh_detector_context,
                )
                fresh_evaluation = _authority.with_recorded_detector_result(
                    fresh_evaluation,
                    fresh_detector_evaluation,
                )
                try:
                    fresh_launch_previews = _guard_run_launch_previews(harness, context, passthrough_args)
                except Exception:
                    fresh_launch_previews = ()
                postclaim_signature = _authority.authority_signature(detection, fresh_evaluation, fresh_launch_previews)
                finalized_launch_plan: _GuardRunLaunchPlan | None = None
                if (
                    not config_refresh_failed
                    and preclaim_signature is not None
                    and postclaim_signature == preclaim_signature
                ):
                    try:
                        finalized_launch_plan = _guard_run_finalize_authorized_launch_plan(
                            harness,
                            context,
                            passthrough_args,
                            fresh_launch_previews,
                        )
                    except Exception:
                        finalized_launch_plan = None
                if (
                    config_refresh_failed
                    or preclaim_signature is None
                    or postclaim_signature != preclaim_signature
                    or finalized_launch_plan is None
                ):
                    stale_config = _authority.config_with_current_authority(
                        fresh_authority_config,
                        fresh_evaluation,
                        "require-reapproval",
                    )
                    authoritative_fresh_block = fresh_detector_authority.blocked_by_detector
                    receipt_cursor = _receipt_rowid_cursor(store)
                    evaluation = evaluate_detection(
                        detection,
                        store,
                        stale_config,
                        default_action=default_action,
                        persist=True,
                        runtime_detector_context=fresh_detector_context,
                        runtime_detector_block_reason=authoritative_fresh_block,
                    )
                    evaluation = _authority.with_recorded_detector_result(
                        evaluation,
                        fresh_detector_evaluation,
                    )
                    evaluation, context_failure_evidence = _authority.with_claim_context_failure(
                        evaluation,
                        claimed_artifact_ids={
                            artifact_id for _decision, artifact_id, _artifact_hash in pending_approval_claims
                        },
                    )
                    fresh_detector_evidence = fresh_detector_authority.nonterminal_evidence
                    if fresh_detector_evidence is not None:
                        _append_authority_evidence_to_receipts(
                            store,
                            after_rowid=receipt_cursor,
                            evaluation=evaluation,
                            evidence=fresh_detector_evidence,
                            approval_source="runtime-detector",
                            source_actions=frozenset(),
                        )
                    _append_authority_evidence_to_receipts(
                        store,
                        after_rowid=receipt_cursor,
                        evaluation=evaluation,
                        evidence=context_failure_evidence,
                        approval_source="approval-reuse",
                        source_actions=frozenset({"review", "require-reapproval", "sandbox-required", "block"}),
                        replace_existing_source=True,
                    )
                    evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)
                else:
                    detector_evaluation = fresh_detector_evaluation
                    detector_action = fresh_detector_action
                    detector_authority = fresh_detector_authority
                    detector_context = fresh_detector_context
                    authority_config = fresh_authority_config
                    evaluation = fresh_evaluation
                    launch_plan = finalized_launch_plan

            if not evaluation["blocked"]:
                receipt_cursor = _receipt_rowid_cursor(store)
                evaluation = evaluate_detection(
                    detection,
                    store,
                    authority_config,
                    default_action=default_action,
                    persist=True,
                    trusted_request_overrides=trusted_request_overrides,
                    trusted_request_override_labels=trusted_request_override_labels,
                    claimed_saved_approval_overrides=consumed_claim_overrides,
                    retained_saved_approval_overrides=retained_claim_overrides,
                    saved_approval_qualification_overrides=saved_approval_qualifications,
                    runtime_detector_context=detector_context,
                )
                if evaluation["blocked"]:
                    evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)
                evaluation = _authority.with_recorded_detector_result(evaluation, detector_evaluation)
                detector_evidence = detector_authority.nonterminal_evidence
                if detector_evidence is not None and detector_action is not None:
                    _append_authority_evidence_to_receipts(
                        store,
                        after_rowid=receipt_cursor,
                        evaluation=evaluation,
                        evidence=detector_evidence,
                        approval_source="runtime-detector",
                        source_actions=frozenset({detector_action}),
                    )
                if resolved_evaluation is not None:
                    _copy_approval_metadata(evaluation, resolved_evaluation)
    return finish_guard_run(
        evaluation,
        detection=detection,
        harness=harness,
        context=context,
        store=store,
        passthrough_args=passthrough_args,
        dry_run=dry_run,
        launch_plan=launch_plan,
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
