"""Execution.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def guard_run(
    harness: str,
    context: runner.HarnessContext,
    store: runner.GuardStore,
    config: runner.GuardConfig,
    dry_run: bool,
    passthrough_args: list[str],
    default_action: str | None = None,
    interactive_resolver: runner.Callable[[runner.HarnessDetection, dict[str, runner.Any]], dict[str, runner.Any]]
    | None = None,
    blocked_resolver: runner.Callable[[runner.HarnessDetection, dict[str, runner.Any]], dict[str, runner.Any]]
    | None = None,
    current_config_provider: runner.Callable[[], runner.GuardConfig] | None = None,
) -> dict[str, runner.Any]:
    """Evaluate local harness state and optionally launch the harness."""

    detection = runner._detection_with_prompt_artifacts(
        runner.detect_harness(harness, context), context, passthrough_args
    )
    launch_plan: runner._GuardRunLaunchPlan | None = None
    pending_approval_claims: list[tuple[runner.Mapping[str, object], str, str]] = []
    base_evaluation = runner.evaluate_detection(
        detection,
        store,
        config,
        default_action=default_action,
        persist=False,
        pending_approval_claims=pending_approval_claims,
    )

    action_envelope = runner._guard_run_action_envelope(harness, context, passthrough_args)
    detector_evaluation = runner._evaluation_with_detector_registry(
        base_evaluation,
        action_envelope,
        context,
        config,
    )
    detector_action, _detector_reason = runner._runtime_detector_authority(detector_evaluation)
    detector_context = runner._runtime_detector_context(detector_evaluation)
    authority_config = config
    if detector_action in {"warn", "review"}:
        # The first evaluation is deliberately non-consuming and exists only
        # to recover each artifact's current policy action. Re-evaluate with
        # nonterminal detector authority bound into the current authority
        # before trusting or scheduling any saved approval claim.
        authority_config = runner._config_with_current_authority(config, base_evaluation, detector_action)
    if detector_context is not None:
        pending_approval_claims = []
        evaluation = runner.evaluate_detection(
            detection,
            store,
            authority_config,
            default_action=default_action,
            persist=False,
            pending_approval_claims=pending_approval_claims,
            runtime_detector_context=detector_context,
        )
        evaluation = runner._evaluation_with_recorded_detector_result(evaluation, detector_evaluation)
    else:
        evaluation = detector_evaluation
    detector_block_reason = detector_evaluation.get("blocked_by_detector")
    authoritative_detector_block = (
        detector_block_reason if isinstance(detector_block_reason, str) and detector_block_reason else None
    )
    if evaluation["blocked"]:
        evaluation = runner._evaluation_with_action_envelope(evaluation, action_envelope)

    resolved_evaluation: dict[str, runner.Any] | None = None
    trusted_request_overrides: dict[str, str] = {}
    trusted_request_override_labels: dict[str, str] = {}
    if (
        not dry_run
        and authoritative_detector_block is None
        and interactive_resolver is not None
        and evaluation["blocked"]
    ):
        resolved_evaluation = interactive_resolver(detection, evaluation)
        trusted_request_overrides, trusted_request_override_labels = runner._resolved_interactive_request_overrides(
            resolved_evaluation
        )
    elif (
        not dry_run and authoritative_detector_block is None and blocked_resolver is not None and evaluation["blocked"]
    ):
        resolved_evaluation = blocked_resolver(detection, evaluation)
        trusted_request_overrides = runner._resolved_exact_request_overrides(resolved_evaluation)
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
                if isinstance(provided_config, runner.GuardConfig):
                    config = provided_config
                else:
                    resolution_config_refresh_failed = True
        if resolution_config_refresh_failed:
            trusted_request_overrides = {}
            trusted_request_override_labels = {}
        detection = runner._detection_with_prompt_artifacts(
            runner.detect_harness(harness, context), context, passthrough_args
        )
        base_evaluation = runner.evaluate_detection(
            detection,
            store,
            config,
            default_action=default_action,
            persist=False,
        )
        detector_evaluation = runner._evaluation_with_detector_registry(
            base_evaluation,
            action_envelope,
            context,
            config,
        )
        detector_action, _detector_reason = runner._runtime_detector_authority(detector_evaluation)
        detector_context = runner._runtime_detector_context(detector_evaluation)
        authority_config = config
        if detector_action in {"warn", "review"}:
            authority_config = runner._config_with_current_authority(config, base_evaluation, detector_action)
        pending_approval_claims = []
        evaluation = runner.evaluate_detection(
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
        evaluation = runner._evaluation_with_recorded_detector_result(evaluation, detector_evaluation)
        detector_block_reason = detector_evaluation.get("blocked_by_detector")
        authoritative_detector_block = (
            detector_block_reason if isinstance(detector_block_reason, str) and detector_block_reason else None
        )
        if evaluation["blocked"]:
            evaluation = runner._evaluation_with_action_envelope(evaluation, action_envelope)
        for key in runner._APPROVAL_METADATA_KEYS:
            if key in resolved_evaluation:
                evaluation[key] = resolved_evaluation[key]
    if evaluation["blocked"] or dry_run:
        receipt_cursor = runner._receipt_rowid_cursor(store)
        persisted = runner.evaluate_detection(
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
            persisted = runner._evaluation_with_action_envelope(persisted, action_envelope)
        persisted = runner._evaluation_with_recorded_detector_result(persisted, detector_evaluation)
        detector_evidence = runner._runtime_detector_nonterminal_evidence(detector_action, _detector_reason)
        if detector_evidence is not None and detector_action is not None:
            runner._append_authority_evidence_to_receipts(
                store,
                after_rowid=receipt_cursor,
                evaluation=persisted,
                evidence=detector_evidence,
                approval_source="runtime-detector",
                source_actions=frozenset({detector_action}),
            )
        if resolved_evaluation is not None:
            for key in runner._APPROVAL_METADATA_KEYS:
                if key in resolved_evaluation:
                    persisted[key] = resolved_evaluation[key]
        evaluation = persisted
    else:
        decisions_to_claim = [decision for decision, _artifact_id, _artifact_hash in pending_approval_claims]
        preclaim_launch_previews: tuple[runner._GuardRunLaunchPlan, ...] = ()
        preclaim_signature: tuple[object, ...] | None = None
        preclaim_failure_reason: str | None = None
        if decisions_to_claim:
            try:
                preclaim_launch_previews = runner._guard_run_launch_previews(harness, context, passthrough_args)
            except Exception:
                preclaim_launch_previews = ()
            if preclaim_launch_previews and all(plan.reusable for plan in preclaim_launch_previews):
                preclaim_signature = runner._guard_run_authority_signature(
                    detection,
                    evaluation,
                    preclaim_launch_previews,
                )
            if preclaim_signature is None:
                preclaim_failure_reason = runner.APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED
            else:
                try:
                    claim_succeeded = store.claim_approval_reuse_decisions(decisions_to_claim, now=runner._now())
                except Exception:
                    claim_succeeded = False
                if not claim_succeeded:
                    preclaim_failure_reason = runner.APPROVAL_REUSE_CLAIM_FAILED
        if decisions_to_claim and preclaim_failure_reason is not None:
            failed_ids = {artifact_id for _decision, artifact_id, _artifact_hash in pending_approval_claims}
            failure_config = runner._config_with_current_authority(
                authority_config,
                evaluation,
                "require-reapproval",
                artifact_ids=failed_ids,
            )
            if preclaim_failure_reason == runner.APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED:
                failure_reason = (
                    "saved approval could not be reused because the harness launch identity was not stable "
                    "and path-pinned"
                )
                claim_status = "rejected"
                revalidation_status = "unverified"
            else:
                failure_reason = "saved approval could not be atomically claimed"
                claim_status = "failed"
                revalidation_status = "claim-failed"
            receipt_cursor = runner._receipt_rowid_cursor(store)
            evaluation = runner.evaluate_detection(
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
            evaluation = runner._evaluation_with_recorded_detector_result(evaluation, detector_evaluation)
            evaluation = runner._evaluation_with_preclaim_failure(
                evaluation,
                affected_artifact_ids=failed_ids,
                reason_code=preclaim_failure_reason,
                reason=failure_reason,
                claim_status=claim_status,
                revalidation_status=revalidation_status,
            )
            detector_evidence = runner._runtime_detector_nonterminal_evidence(detector_action, _detector_reason)
            if detector_evidence is not None and detector_action is not None:
                runner._append_authority_evidence_to_receipts(
                    store,
                    after_rowid=receipt_cursor,
                    evaluation=evaluation,
                    evidence=detector_evidence,
                    approval_source="runtime-detector",
                    source_actions=frozenset({detector_action}),
                )
            runner._append_authority_evidence_to_receipts(
                store,
                after_rowid=receipt_cursor,
                evaluation=evaluation,
                evidence={
                    "source": "approval_reuse",
                    "status": "rejected",
                    "reason_code": preclaim_failure_reason,
                    "reason": failure_reason,
                },
                approval_source="approval-reuse",
                source_actions=frozenset({"review", "require-reapproval", "sandbox-required", "block"}),
                replace_existing_source=True,
            )
            if resolved_evaluation is not None:
                for key in runner._APPROVAL_METADATA_KEYS:
                    if key in resolved_evaluation:
                        evaluation[key] = resolved_evaluation[key]
            evaluation = runner._evaluation_with_action_envelope(evaluation, action_envelope)
        else:
            consumed_claim_overrides = {
                artifact_id: artifact_hash
                for decision, artifact_id, artifact_hash in pending_approval_claims
                if not runner._saved_decision_is_retained(decision)
            }
            retained_claim_overrides = {
                artifact_id: artifact_hash
                for decision, artifact_id, artifact_hash in pending_approval_claims
                if runner._saved_decision_is_retained(decision)
            }
            if decisions_to_claim:
                config_refresh_failed = False
                fresh_config = config
                if current_config_provider is not None:
                    try:
                        provided_config = current_config_provider()
                    except Exception:
                        config_refresh_failed = True
                    else:
                        if isinstance(provided_config, runner.GuardConfig):
                            fresh_config = provided_config
                        else:
                            config_refresh_failed = True
                detection = runner._detection_with_prompt_artifacts(
                    runner.detect_harness(harness, context),
                    context,
                    passthrough_args,
                )
                fresh_base_evaluation = runner.evaluate_detection(
                    detection,
                    store,
                    fresh_config,
                    default_action=default_action,
                    persist=False,
                )
                fresh_detector_evaluation = runner._evaluation_with_detector_registry(
                    fresh_base_evaluation,
                    action_envelope,
                    context,
                    fresh_config,
                )
                fresh_detector_action, fresh_detector_reason = runner._runtime_detector_authority(
                    fresh_detector_evaluation
                )
                fresh_detector_context = runner._runtime_detector_context(fresh_detector_evaluation)
                fresh_authority_config = fresh_config
                if fresh_detector_action in {"warn", "review"}:
                    fresh_authority_config = runner._config_with_current_authority(
                        fresh_config,
                        fresh_base_evaluation,
                        fresh_detector_action,
                    )
                fresh_evaluation = runner.evaluate_detection(
                    detection,
                    store,
                    fresh_authority_config,
                    default_action=default_action,
                    persist=False,
                    trusted_request_overrides=trusted_request_overrides,
                    trusted_request_override_labels=trusted_request_override_labels,
                    claimed_saved_approval_overrides=consumed_claim_overrides,
                    retained_saved_approval_overrides=retained_claim_overrides,
                    runtime_detector_context=fresh_detector_context,
                )
                fresh_evaluation = runner._evaluation_with_recorded_detector_result(
                    fresh_evaluation,
                    fresh_detector_evaluation,
                )
                try:
                    fresh_launch_previews = runner._guard_run_launch_previews(harness, context, passthrough_args)
                except Exception:
                    fresh_launch_previews = ()
                postclaim_signature = (
                    runner._guard_run_authority_signature(detection, fresh_evaluation, fresh_launch_previews)
                    if fresh_launch_previews and all(plan.reusable for plan in fresh_launch_previews)
                    else None
                )
                finalized_launch_plan: runner._GuardRunLaunchPlan | None = None
                if (
                    not config_refresh_failed
                    and preclaim_signature is not None
                    and postclaim_signature == preclaim_signature
                ):
                    try:
                        finalized_launch_plan = runner._guard_run_finalize_authorized_launch_plan(
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
                    stale_config = runner._config_with_current_authority(
                        fresh_authority_config,
                        fresh_evaluation,
                        "require-reapproval",
                    )
                    fresh_block_reason = fresh_detector_evaluation.get("blocked_by_detector")
                    authoritative_fresh_block = (
                        fresh_block_reason if isinstance(fresh_block_reason, str) and fresh_block_reason else None
                    )
                    receipt_cursor = runner._receipt_rowid_cursor(store)
                    evaluation = runner.evaluate_detection(
                        detection,
                        store,
                        stale_config,
                        default_action=default_action,
                        persist=True,
                        runtime_detector_context=fresh_detector_context,
                        runtime_detector_block_reason=authoritative_fresh_block,
                    )
                    evaluation = runner._evaluation_with_recorded_detector_result(
                        evaluation,
                        fresh_detector_evaluation,
                    )
                    evaluation = runner._evaluation_with_claim_context_failure(
                        evaluation,
                        claimed_artifact_ids={
                            artifact_id for _decision, artifact_id, _artifact_hash in pending_approval_claims
                        },
                    )
                    fresh_detector_evidence = runner._runtime_detector_nonterminal_evidence(
                        fresh_detector_action,
                        fresh_detector_reason,
                    )
                    if fresh_detector_evidence is not None:
                        runner._append_authority_evidence_to_receipts(
                            store,
                            after_rowid=receipt_cursor,
                            evaluation=evaluation,
                            evidence=fresh_detector_evidence,
                            approval_source="runtime-detector",
                            source_actions=frozenset(),
                        )
                    runner._append_authority_evidence_to_receipts(
                        store,
                        after_rowid=receipt_cursor,
                        evaluation=evaluation,
                        evidence={
                            "source": "approval_reuse",
                            "status": "rejected",
                            "reason_code": runner._APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
                            "reason": "launch authority changed after the saved approval was claimed",
                        },
                        approval_source="approval-reuse",
                        source_actions=frozenset({"review", "require-reapproval", "sandbox-required", "block"}),
                        replace_existing_source=True,
                    )
                    evaluation = runner._evaluation_with_action_envelope(evaluation, action_envelope)
                else:
                    detector_evaluation = fresh_detector_evaluation
                    detector_action = fresh_detector_action
                    _detector_reason = fresh_detector_reason
                    detector_context = fresh_detector_context
                    authority_config = fresh_authority_config
                    evaluation = fresh_evaluation
                    launch_plan = finalized_launch_plan

            if not evaluation["blocked"]:
                receipt_cursor = runner._receipt_rowid_cursor(store)
                evaluation = runner.evaluate_detection(
                    detection,
                    store,
                    authority_config,
                    default_action=default_action,
                    persist=True,
                    trusted_request_overrides=trusted_request_overrides,
                    trusted_request_override_labels=trusted_request_override_labels,
                    claimed_saved_approval_overrides=consumed_claim_overrides,
                    retained_saved_approval_overrides=retained_claim_overrides,
                    runtime_detector_context=detector_context,
                )
                if evaluation["blocked"]:
                    evaluation = runner._evaluation_with_action_envelope(evaluation, action_envelope)
                evaluation = runner._evaluation_with_recorded_detector_result(evaluation, detector_evaluation)
                detector_evidence = runner._runtime_detector_nonterminal_evidence(detector_action, _detector_reason)
                if detector_evidence is not None and detector_action is not None:
                    runner._append_authority_evidence_to_receipts(
                        store,
                        after_rowid=receipt_cursor,
                        evaluation=evaluation,
                        evidence=detector_evidence,
                        approval_source="runtime-detector",
                        source_actions=frozenset({detector_action}),
                    )
                if resolved_evaluation is not None:
                    for key in runner._APPROVAL_METADATA_KEYS:
                        if key in resolved_evaluation:
                            evaluation[key] = resolved_evaluation[key]
    return runner._complete_guard_run_launch(
        harness=harness,
        context=context,
        store=store,
        dry_run=dry_run,
        passthrough_args=passthrough_args,
        detection=detection,
        evaluation=evaluation,
        launch_plan=launch_plan,
    )
