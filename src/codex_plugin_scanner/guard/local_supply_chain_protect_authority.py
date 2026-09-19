"""Protect authority helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _build_package_protect_authority(
    *,
    command: _api.Sequence[str],
    store: _api.Any,
    workspace_dir: _api.Path,
    now: str,
    config: _api.GuardConfig | None,
    additional_current_action: object | None,
    additional_policy_context: dict[str, object] | None,
    external_archive_network_authorized: bool = False,
    invoking_harness: str | None = None,
) -> _api._PackageProtectAuthority | None:
    try:
        launch_cwd = workspace_dir.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("package workspace must resolve to an existing directory") from None
    if not launch_cwd.is_dir():
        raise ValueError("package workspace must resolve to an existing directory")
    launch_environment = _api._package_manager_launch_environment(
        _api.os.environ,
        guard_home=store.guard_home,
        launch_cwd=launch_cwd,
    )
    intent = _api._package_intent_parser_module().parse_package_intent(
        _api.shlex.join(command),
        workspace=launch_cwd,
        environment=launch_environment,
    )
    if intent is None:
        return None
    sanitized_intent = _api.replace(intent, redacted_command=_api.shlex.join(_api.redacted_command_tokens(command)))
    artifact = _api.build_package_request_artifact(
        _api._LOCAL_SUPPLY_CHAIN_HARNESS,
        sanitized_intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    evaluation = _api.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=launch_cwd,
        now=now,
        external_archive_network_authorized=external_archive_network_authorized,
        retain_external_archive_blob=external_archive_network_authorized,
    )
    try:
        current_action = _api.compose_current_package_policy_action(
            artifact=artifact,
            evaluation=evaluation,
            config=config,
            additional_current_action=additional_current_action,
        )
        executable = sanitized_intent.command_tokens[0] if sanitized_intent.command_tokens else None
        executable_args = sanitized_intent.command_tokens[1:] if executable is not None else ()
        if sanitized_intent.command_tokens and ";" in sanitized_intent.command_tokens:
            executable = None
            executable_args = ()
        execution_context = _api.build_package_execution_context(
            workspace_dir=launch_cwd,
            artifact=artifact,
            executable=executable,
            executable_args=executable_args,
            environment=launch_environment,
        )
        launch_identity = _api.build_runtime_launch_identity(
            str(command[0]) if command else None,
            args=tuple(str(item) for item in command[1:]),
            structured_command=True,
            direct_executable=True,
            cwd=launch_cwd,
            launch_env=launch_environment,
        )
        if command and executable is not None and str(command[0]) != executable:
            launch_identity["wrapper_resolution"] = {
                "reason": "package_command_wrapper_unresolved",
                "reuse_nonce": _api.uuid4().hex,
                "status": "unproven",
            }
        artifact_hash = _api._package_request_artifact_hash(
            artifact,
            workspace_dir=launch_cwd,
            store=store,
            evaluation=evaluation,
            execution_context=execution_context,
            launch_identity=launch_identity,
            config=config,
            additional_current_action=additional_current_action,
            additional_policy_context=additional_policy_context,
        )
        return _api._PackageProtectAuthority(
            invoking_harness=invoking_harness
            if invoking_harness is not None
            else _api._resolve_local_supply_chain_harness(),
            intent=sanitized_intent,
            artifact=artifact,
            evaluation=evaluation,
            current_action=current_action,
            execution_context=execution_context,
            artifact_hash=artifact_hash,
            launch_identity=launch_identity,
            launch_cwd=launch_cwd,
            launch_environment=launch_environment,
            additional_current_action=additional_current_action,
            additional_policy_context=additional_policy_context,
            observe_mode=config is not None and config.mode == "observe",
        )
    except BaseException:
        _api._cleanup_external_archive_downloads(evaluation)
        raise


def _final_package_protect_authority(
    *,
    initial: _api._PackageProtectAuthority,
    initial_saved_evaluation: _api.Any,
    saved_approval_pending: bool,
    command: _api.Sequence[str],
    store: _api.Any,
    workspace_dir: _api.Path,
    now: str,
    config: _api.GuardConfig | None,
    current_config_provider: _api.Callable[[], _api.GuardConfig] | None,
    additional_authority_provider: _api.Callable[[], tuple[object | None, dict[str, object] | None]] | None,
) -> tuple[_api._PackageProtectAuthority, _api.Any]:
    """Refresh mode, claim required approval, then rebuild authority before spawn."""

    additional_action: object | None = initial.additional_current_action
    additional_context: dict[str, object] | None = initial.additional_policy_context
    current_config = config
    config_refresh_failed = False
    if current_config_provider is not None:
        try:
            current_config = current_config_provider()
            if not isinstance(current_config, _api.GuardConfig):
                raise TypeError("current config provider returned an invalid value")
        except Exception:
            config_refresh_failed = True
    saved_approval_claimed = False
    saved_approval_claim_disposition: _api._PackageApprovalClaimDisposition | None = None
    saved_approval_claim_failure: _api.Any | None = None
    if (
        saved_approval_pending
        and not config_refresh_failed
        and (current_config is None or current_config.mode != "observe")
    ):
        claimed_resolution = _api._resolve_stored_package_policy_override(
            initial_saved_evaluation,
            store=store,
            artifact=initial.artifact,
            artifact_hash=initial.artifact_hash,
            workspace_dir=workspace_dir,
            now=now,
            execution_context=initial.execution_context,
            current_action=initial.current_action,
            claim_saved_approval=True,
        )
        claimed_action = _api._protect_action_for_policy_action(claimed_resolution.evaluation.policy_action)
        if not _api.is_execution_permitted(claimed_action):
            saved_approval_claim_failure = claimed_resolution.evaluation
        else:
            saved_approval_claimed = True
            saved_approval_claim_disposition = claimed_resolution.claim_disposition
    if additional_authority_provider is not None:
        try:
            additional_action, additional_context = additional_authority_provider()
        except Exception as error:
            additional_action = "block"
            additional_context = {
                "available": False,
                "error": type(error).__name__,
                "status": "authority_refresh_failed",
                "version": 1,
            }
    if config_refresh_failed:
        additional_action = _api.most_restrictive_guard_action(
            additional_action,
            "block",
            unknown_action="block",
        )
        additional_context = {
            "additional": additional_context,
            "available": False,
            "reason_code": "package_config_refresh_failed",
            "status": "authority_refresh_failed",
            "version": 1,
        }
    current = _api._build_package_protect_authority(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=current_config,
        additional_current_action=additional_action,
        additional_policy_context=additional_context,
        external_archive_network_authorized=saved_approval_claimed,
        invoking_harness=initial.invoking_harness,
    )
    if current is None:
        reuse = _api.evaluate_approval_reuse(
            "review",
            "allow",
            saved_decision_present=True,
            validation_reason="approval_reuse_identity_changed",
        )
        return initial, _api._package_evaluation_with_rejected_reuse(initial.evaluation, reuse)
    validation_reason: _api.ApprovalReuseValidationFailure | None
    if current.artifact.artifact_id != initial.artifact.artifact_id:
        validation_reason = "approval_reuse_identity_changed"
    else:
        validation_reason = _api.cast(
            _api.ApprovalReuseValidationFailure | None,
            _api.approval_context_tokens_validation_reason(initial.artifact_hash, current.artifact_hash),
        )
    current_evaluation = _api._package_evaluation_with_current_policy_action(
        current.evaluation,
        current_action=current.current_action,
    )
    if saved_approval_claim_failure is not None:
        return current, _api._package_evaluation_with_current_policy_action(
            saved_approval_claim_failure,
            current_action=current.current_action,
        )
    if current.observe_mode:
        return current, current_evaluation
    if saved_approval_claimed:
        if validation_reason is not None:
            reuse = _api.evaluate_approval_reuse(
                current.current_action,
                "allow",
                saved_decision_present=True,
                validation_reason=validation_reason,
            )
            return current, _api._package_evaluation_with_rejected_reuse(current_evaluation, reuse)
        refreshed_saved_policy = _api._apply_stored_package_policy_override(
            current_evaluation,
            store=store,
            artifact=current.artifact,
            artifact_hash=current.artifact_hash,
            workspace_dir=workspace_dir,
            now=now,
            execution_context=current.execution_context,
            current_action=current.current_action,
            claim_saved_approval=False,
        )
        if _api._evaluation_uses_saved_package_approval(refreshed_saved_policy):
            return current, refreshed_saved_policy
        if _api._package_approval_reuse_evidence(refreshed_saved_policy):
            return current, refreshed_saved_policy
        if saved_approval_claim_disposition != "consumed":
            reuse = _api.evaluate_approval_reuse(
                current.current_action,
                "allow",
                saved_decision_present=True,
                validation_reason=_api.APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            )
            return current, _api._package_evaluation_with_rejected_reuse(current_evaluation, reuse)
        reuse = _api.evaluate_approval_reuse(
            current.current_action,
            "allow",
            saved_decision_present=True,
            fresh_local_approval=True,
        )
        if reuse.accepted and reuse.saved_action == "allow":
            return current, _api._package_policy_override_evaluation(
                current_evaluation,
                decision="allow",
                policy_action="allow",
                title="Allowed by saved approval",
                summary="HOL Guard reused your saved approval for this package request.",
                harness_message=(
                    "HOL Guard revalidated the repository, package manager, dependency files, settings, "
                    "registry environment, and current advisory authority after atomically claiming approval."
                ),
                reason_code="saved_package_approval",
                reason_message="HOL Guard reused your saved approval for this package request.",
                approval_reuse=reuse,
            )
        return current, _api._package_evaluation_with_rejected_reuse(current_evaluation, reuse)
    if validation_reason is not None:
        reuse = _api.evaluate_approval_reuse(
            current.current_action,
            "require-reapproval",
            saved_decision_present=True,
            validation_reason=validation_reason,
        )
        return current, _api._package_evaluation_with_rejected_reuse(current_evaluation, reuse)
    resolved = _api._apply_stored_package_policy_override(
        current_evaluation,
        store=store,
        artifact=current.artifact,
        artifact_hash=current.artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=current.execution_context,
        current_action=current.current_action,
        claim_saved_approval=False,
    )
    if _api._evaluation_uses_saved_package_approval(resolved):
        reuse = _api.evaluate_approval_reuse(
            current.current_action,
            "allow",
            saved_decision_present=True,
            validation_reason=_api.APPROVAL_REUSE_CLAIM_FAILED,
        )
        resolved = _api._package_evaluation_with_rejected_reuse(current_evaluation, reuse)
    return current, resolved


def _package_execution_policy_action(
    authority: _api._PackageProtectAuthority,
    evaluation: _api.Any,
) -> _api.GuardAction:
    """Project package policy into execution without discarding watch-only evidence."""

    observed_action = _api._protect_action_for_policy_action(evaluation.policy_action)
    if not authority.observe_mode:
        return observed_action
    return "warn" if observed_action == "warn" else "allow"


def _package_protect_verdict_context(
    *,
    authority: _api._PackageProtectAuthority,
    evaluation: _api.Any,
    execution_policy_action: _api.GuardAction | None,
) -> _api.PackageProtectVerdictContext:
    """Resolve the verdict presentation and stored receipt for one projection."""

    intent = authority.intent
    public_targets = [target.to_dict() for target in intent.targets]
    artifact = authority.artifact
    observed_policy_action = _api._protect_action_for_policy_action(evaluation.policy_action)
    verdict_action = execution_policy_action or observed_policy_action
    observe_projected = authority.observe_mode and verdict_action != observed_policy_action
    verdict_reason = evaluation.user_copy.summary
    if observe_projected:
        verdict_reason = (
            f"Watch only observed a `{observed_policy_action}` package-policy decision. "
            "HOL Guard allowed the install to continue."
        )
    risk_signals = tuple(_api._evaluation_risk_signals(evaluation))
    approval_reuse_evidence = _api._package_approval_reuse_evidence(evaluation)
    receipt_policy_metadata: dict[str, object] = {
        "matched_rule_id": evaluation.matched_rule_id,
        "package_execution_context": authority.execution_context.to_evidence(),
        "package_manager": intent.package_manager,
        "package_targets": [str(target.get("raw_spec") or "") for target in public_targets],
        "policy_action": verdict_action,
        "policy_version": evaluation.policy_version,
        "redacted_command": intent.redacted_command,
    }
    if observe_projected:
        receipt_policy_metadata["observe_mode"] = True
        receipt_policy_metadata["observed_policy_action"] = observed_policy_action
    if evaluation.bundle_version is not None:
        receipt_policy_metadata["bundle_version"] = evaluation.bundle_version
    if authority.additional_policy_context is not None:
        receipt_policy_metadata["additional_policy_context"] = authority.additional_policy_context
    if approval_reuse_evidence:
        receipt_policy_metadata["approval_reuse"] = list(approval_reuse_evidence)
    if authority.invoking_harness != _api._LOCAL_SUPPLY_CHAIN_HARNESS:
        receipt_policy_metadata["invoking_harness"] = authority.invoking_harness
    receipt = _api._build_guard_receipt(
        harness=authority.invoking_harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=authority.artifact_hash,
        policy_decision=verdict_action,
        capabilities_summary=verdict_reason,
        changed_capabilities=[
            target.package_name or str(public_target.get("raw_spec") or "")
            for target, public_target in zip(intent.targets, public_targets, strict=True)
        ],
        provenance_summary=evaluation.user_copy.harness_message,
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
        scanner_evidence=approval_reuse_evidence,
    )
    return _api.PackageProtectVerdictContext(
        matched_advisories=_api._matched_advisories(evaluation),
        observe_projected=observe_projected,
        observed_policy_action=observed_policy_action,
        public_targets=public_targets,
        receipt=receipt,
        receipt_policy_metadata=receipt_policy_metadata,
        risk_signals=risk_signals,
        verdict_action=verdict_action,
        verdict_reason=verdict_reason,
    )


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
