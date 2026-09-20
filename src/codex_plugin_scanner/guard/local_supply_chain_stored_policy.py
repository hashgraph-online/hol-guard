"""Stored policy helpers using the original live supply-chain namespace."""

from __future__ import annotations


def apply_stored_package_policy_override(
    evaluation: _api.Any,
    *,
    store: _api.Any,
    artifact: _api.GuardArtifact,
    artifact_hash: str,
    workspace_dir: _api.Path,
    now: str,
    execution_context: _api.PackageExecutionContext | None = None,
    current_action: object | None = None,
    claim_saved_approval: bool = True,
) -> _api.Any:
    """Apply a saved package approval when the content hash still matches."""

    return _api._apply_stored_package_policy_override(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=execution_context,
        current_action=current_action,
        claim_saved_approval=claim_saved_approval,
    )


def _apply_stored_package_policy_override(
    evaluation: _api.Any,
    *,
    store: _api.Any,
    artifact: _api.GuardArtifact,
    artifact_hash: str,
    workspace_dir: _api.Path,
    now: str,
    execution_context: _api.PackageExecutionContext | None = None,
    current_action: object | None = None,
    claim_saved_approval: bool = True,
) -> _api.Any:
    return _api._resolve_stored_package_policy_override(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=execution_context,
        current_action=current_action,
        claim_saved_approval=claim_saved_approval,
    ).evaluation


def _resolve_stored_package_policy_override(
    evaluation: _api.Any,
    *,
    store: _api.Any,
    artifact: _api.GuardArtifact,
    artifact_hash: str,
    workspace_dir: _api.Path,
    now: str,
    execution_context: _api.PackageExecutionContext | None = None,
    current_action: object | None = None,
    claim_saved_approval: bool = True,
) -> _api._StoredPackagePolicyResolution:
    from .mcp_authority_binding import check_current_mcp_authority

    check_current_mcp_authority()
    effective_current_action = (
        evaluation.policy_action
        if current_action is None
        else _api.most_restrictive_guard_action(evaluation.policy_action, current_action, unknown_action="block")
    )
    current_evaluation = _api._package_evaluation_with_current_policy_action(
        evaluation,
        current_action=effective_current_action,
    )
    resolved_execution_context = execution_context or _api.build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    decision = None
    ignored_integrity = None
    daemon_authority = None
    policy_workspaces = _api._package_policy_workspace_candidates(
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        execution_context=resolved_execution_context,
    )
    check_current_mcp_authority()
    for policy_workspace in policy_workspaces:
        check_current_mcp_authority()
        lookup = store.resolve_policy_decision_lookup(
            artifact.harness,
            artifact.artifact_id,
            artifact_hash,
            policy_workspace,
            artifact.publisher,
            now,
            consume_one_shot=False,
        )
        check_current_mcp_authority()
        decision = lookup["decision"]
        ignored_integrity = lookup["ignored_local_integrity"]
        check_current_mcp_authority()
        if isinstance(decision, dict):
            break
        if ignored_integrity is not None:
            break
    if not isinstance(decision, dict) and ignored_integrity is not None:
        from .daemon.policy_authority_client import resolve_package_policy

        check_current_mcp_authority()
        daemon_resolution = resolve_package_policy(
            guard_home=store.guard_home,
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
            workspaces=policy_workspaces,
            publisher=artifact.publisher,
        )
        check_current_mcp_authority()
        daemon_authority = daemon_resolution.authority
        if daemon_resolution.decision is not None:
            decision = daemon_resolution.decision
            ignored_integrity = None
        check_current_mcp_authority()
    diagnosed_reason: _api.ApprovalReuseValidationFailure | None = None
    if not isinstance(decision, dict) and ignored_integrity is None:
        for policy_workspace in policy_workspaces:
            check_current_mcp_authority()
            raw_diagnosed_reason = store.approval_reuse_validation_reason(
                artifact.harness,
                artifact.artifact_id,
                artifact_hash,
                policy_workspace,
                artifact.publisher,
                now,
            )
            check_current_mcp_authority()
            if raw_diagnosed_reason is not None:
                diagnosed_reason = _api.cast(_api.ApprovalReuseValidationFailure, raw_diagnosed_reason)
                break
        if diagnosed_reason is None:
            return _api._StoredPackagePolicyResolution(current_evaluation)
    if isinstance(decision, dict) and _api._stored_package_policy_is_stale_policy_bundle_family(decision, store=store):
        check_current_mcp_authority()
        return _api._StoredPackagePolicyResolution(current_evaluation)
    check_current_mcp_authority()
    action = (
        decision.get("action")
        if isinstance(decision, dict)
        else ("require-reapproval" if ignored_integrity is not None else "allow")
    )
    validation_reason: _api.ApprovalReuseValidationFailure | None = (
        "approval_reuse_integrity_failure"
        if ignored_integrity is not None
        else (
            _api.cast(
                _api.ApprovalReuseValidationFailure,
                _api.package_saved_allow_validation_reason(decision, artifact_hash=artifact_hash),
            )
            if isinstance(decision, dict)
            else diagnosed_reason
        )
    )
    legacy_local_approval = isinstance(decision, dict) and _api._is_legacy_package_local_approval(
        decision,
        store=store,
    )
    check_current_mcp_authority()
    fresh_local_approval = isinstance(decision, dict) and (
        _api._is_fresh_artifact_approval(decision, store=store) or legacy_local_approval
    )
    check_current_mcp_authority()
    durable_exact_approval = isinstance(decision, dict) and _api._is_durable_exact_artifact_approval(decision)
    reuse = _api.evaluate_approval_reuse(
        effective_current_action,
        action,
        saved_decision_present=True,
        validation_reason=validation_reason,
        fresh_local_approval=fresh_local_approval,
        durable_exact_approval=durable_exact_approval,
    )
    claim_disposition: _api._PackageApprovalClaimDisposition | None = None
    disposition_resolver = getattr(store, "approval_reuse_claim_disposition", None)
    check_current_mcp_authority()
    if fresh_local_approval:
        claim_disposition = "consumed"
    elif isinstance(decision, dict) and callable(disposition_resolver):
        raw_disposition = disposition_resolver(decision)
        check_current_mcp_authority()
        if raw_disposition in {"consumed", "retained"}:
            claim_disposition = _api.cast(_api._PackageApprovalClaimDisposition, raw_disposition)
    claim_succeeded = True
    check_current_mcp_authority()
    if claim_saved_approval and reuse.should_claim and isinstance(decision, dict):
        if daemon_authority is not None:
            from .daemon.policy_authority_client import claim_package_policy

            claim_succeeded = claim_package_policy(daemon_authority, decision)
        elif legacy_local_approval:
            approval_id = decision.get("approval_id")
            assert isinstance(approval_id, str)
            claim_succeeded = store.claim_local_once_approval(
                approval_id,
                claimed_at=now,
                expected_decision=decision,
            )
        else:
            claim_succeeded = store.claim_approval_reuse_decision(decision, now=now)
        check_current_mcp_authority()
    if claim_saved_approval and reuse.should_claim and not claim_succeeded:
        reuse = _api.evaluate_approval_reuse(
            effective_current_action,
            action,
            saved_decision_present=True,
            validation_reason=_api.APPROVAL_REUSE_CLAIM_FAILED,
        )
    if reuse.accepted and reuse.saved_action == "allow":
        if not isinstance(decision, dict) or decision.get("action") != "allow":
            failed_reuse = _api.evaluate_approval_reuse(
                _api.most_restrictive_guard_action(
                    effective_current_action,
                    "require-reapproval",
                    unknown_action="block",
                ),
                "allow",
                saved_decision_present=True,
                validation_reason=_api.APPROVAL_REUSE_CLAIM_FAILED,
            )
            return _api._StoredPackagePolicyResolution(
                _api._package_evaluation_with_rejected_reuse(current_evaluation, failed_reuse)
            )
        return _api._StoredPackagePolicyResolution(
            _api._package_policy_override_evaluation(
                current_evaluation,
                decision="allow",
                policy_action="allow",
                title="Allowed by saved approval",
                summary="HOL Guard reused your saved approval for this package request.",
                harness_message=(
                    "HOL Guard verified the same repository, package manager, dependency files, settings, and "
                    "registry environment before reusing your saved approval."
                ),
                reason_code="saved_package_approval",
                reason_message="HOL Guard reused your saved approval for this package request.",
                approval_reuse=reuse,
                approval_claim_disposition=claim_disposition,
            ),
            approval_reuse_decision=decision,
            claim_disposition=claim_disposition,
        )
    if reuse.saved_action == "block":
        assert isinstance(decision, dict)
        clear_command = _api._saved_package_policy_clear_command(
            artifact=artifact,
            artifact_hash=artifact_hash,
            matched_policy=decision,
            workspace_dir=workspace_dir,
        )
        return _api._StoredPackagePolicyResolution(
            _api._package_policy_override_evaluation(
                current_evaluation,
                decision="block",
                policy_action="block",
                title="Blocked by saved policy",
                summary="HOL Guard kept this package blocked because a saved package policy already exists.",
                harness_message=(
                    "HOL Guard kept this package blocked because a saved package policy already exists. "
                    f"To reconsider, run `{clear_command}`, then retry the install."
                ),
                next_step=clear_command,
                reason_code="saved_package_block",
                reason_message="HOL Guard kept this package blocked because a saved package policy already exists.",
                approval_reuse=reuse,
            )
        )
    return _api._StoredPackagePolicyResolution(_api._package_evaluation_with_rejected_reuse(current_evaluation, reuse))


def _is_fresh_artifact_approval(decision: dict[str, object], *, store: _api.Any) -> bool:
    decision_id = decision.get("decision_id")
    if not (
        isinstance(decision_id, int)
        and not isinstance(decision_id, bool)
        and decision.get("source") == "approval-gate"
        and decision.get("scope") == "artifact"
        and isinstance(decision.get("expires_at"), str)
    ):
        return False
    request_id = decision.get("request_id")
    request_getter = getattr(store, "get_approval_request", None)
    if isinstance(request_id, str) and request_id:
        if not callable(request_getter):
            return False
        try:
            request = request_getter(request_id)
        except Exception:
            return False
        return isinstance(request, dict) and request.get("resolution_scope") == "artifact"
    # resolve_policy_decision_lookup has already applied expiry and local-row
    # integrity checks. Expiring package rows do not retain request_id in
    # policy_decisions, so their canonical local identity and context token are
    # the bounded fresh-proof.
    artifact_id = decision.get("artifact_id")
    return (
        decision.get("harness") == _api._LOCAL_SUPPLY_CHAIN_HARNESS
        and isinstance(artifact_id, str)
        and artifact_id.startswith(f"{_api._LOCAL_SUPPLY_CHAIN_HARNESS}:project:package-request:")
        and _api.parse_approval_context_token(decision.get("artifact_hash")) is not None
    )


def _is_durable_exact_artifact_approval(decision: dict[str, object]) -> bool:
    decision_id = decision.get("decision_id")
    return (
        isinstance(decision_id, int)
        and not isinstance(decision_id, bool)
        and decision.get("action") == "allow"
        and decision.get("source") == "approval-gate"
        and decision.get("scope") == "artifact"
        and decision.get("expires_at") is None
        and _api.parse_approval_context_token(decision.get("artifact_hash")) is not None
    )


def _is_legacy_package_local_approval(decision: dict[str, object], *, store: _api.Any) -> bool:
    approval_id = decision.get("approval_id")
    request_id = decision.get("request_id")
    if (
        not isinstance(approval_id, str)
        or not approval_id
        or not isinstance(request_id, str)
        or not request_id
        or decision.get("workspace") is not None
    ):
        return False
    request_getter = getattr(store, "get_approval_request", None)
    if not callable(request_getter):
        return False
    try:
        request = request_getter(request_id)
    except Exception:
        return False
    return (
        isinstance(request, dict)
        and request.get("artifact_type") == "package_request"
        and request.get("status") == "resolved"
        and request.get("resolution_action") == "allow"
        and request.get("resolution_scope") == "artifact"
        and request.get("artifact_id") == decision.get("artifact_id")
        and request.get("artifact_hash") == decision.get("artifact_hash")
    )


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
