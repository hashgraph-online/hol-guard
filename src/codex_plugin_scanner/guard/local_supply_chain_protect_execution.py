"""Protect execution helpers using the original live supply-chain namespace."""

from __future__ import annotations


def build_package_protect_payload(
    *,
    command: _api.Sequence[str],
    store: _api.Any,
    workspace_dir: _api.Path,
    dry_run: bool,
    allow_saved_approval_execution: bool = False,
    now: str,
    config: _api.GuardConfig | None,
    unsafe_raw_output: bool,
    timeout_seconds: int,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
    current_config_provider: _api.Callable[[], _api.GuardConfig] | None = None,
    additional_authority_provider: _api.Callable[[], tuple[object | None, dict[str, object] | None]] | None = None,
) -> tuple[dict[str, object], int] | None:
    authority = _api._build_package_protect_authority(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=config,
        additional_current_action=additional_current_action,
        additional_policy_context=additional_policy_context,
    )
    if authority is None:
        return None
    artifact = authority.artifact
    evaluation = authority.evaluation
    current_action = authority.current_action
    package_execution_context = authority.execution_context
    artifact_hash = authority.artifact_hash
    initial_policy_resolution = _api._resolve_stored_package_policy_override(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=package_execution_context,
        current_action=current_action,
        claim_saved_approval=False,
    )
    evaluation = initial_policy_resolution.evaluation
    effective_dry_run = dry_run and not (
        allow_saved_approval_execution and _api._evaluation_uses_saved_package_approval(evaluation)
    )
    execution_policy_action = _api._package_execution_policy_action(authority, evaluation)
    execution_permitted = _api.is_execution_permitted(execution_policy_action)
    payload: dict[str, object] = {
        "generated_at": now,
        "executed": False,
        "dry_run": dry_run,
    }
    projection = _api._apply_package_protect_projection(
        payload=payload,
        authority=authority,
        evaluation=evaluation,
        command=command,
        blocking=not execution_permitted,
        executed=False,
        execution_policy_action=execution_policy_action,
    )
    if config is not None:
        payload["supply_chain"] = _api.build_local_supply_chain_posture(store, config, now=now)
    if not execution_permitted or effective_dry_run:
        store.add_receipt(projection.receipt)
        store.set_receipt_action_envelope(
            projection.receipt.receipt_id,
            projection.receipt_policy_metadata,
        )
        store.add_event(
            f"install_time_{projection.verdict_action}",
            _api._install_time_event_payload(
                authority=authority,
                command=command,
                action=projection.verdict_action,
                risk_signals=projection.risk_signals,
            ),
            now,
        )
        return (payload, _api._package_execution_exit_code(execution_policy_action))
    final_authority, final_evaluation = _api._final_package_protect_authority(
        initial=authority,
        initial_saved_evaluation=evaluation,
        saved_approval_pending=_api._evaluation_uses_saved_package_approval(evaluation),
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=config,
        current_config_provider=current_config_provider,
        additional_authority_provider=additional_authority_provider,
    )
    final_execution_action = _api._package_execution_policy_action(final_authority, final_evaluation)
    if not _api.is_execution_permitted(final_execution_action):
        denied = _api._package_protect_denied_after_final_boundary(
            payload=payload,
            authority=final_authority,
            evaluation=final_evaluation,
            command=command,
            store=store,
            now=now,
        )
        _api._cleanup_external_archive_downloads(final_evaluation)
        return denied
    launch_command = _api.resolved_runtime_launch_argv(
        final_authority.launch_identity,
        args=tuple(str(item) for item in command[1:]),
    )
    if launch_command is None or not _api.runtime_launch_identity_is_reusable(final_authority.launch_identity):
        reuse = _api.evaluate_approval_reuse(
            final_authority.current_action,
            "require-reapproval",
            saved_decision_present=True,
            validation_reason="approval_reuse_identity_changed",
        )
        denied_evaluation = _api._package_evaluation_with_rejected_reuse(final_authority.evaluation, reuse)
        denied = _api._package_protect_denied_after_final_boundary(
            payload=payload,
            authority=final_authority,
            evaluation=denied_evaluation,
            command=command,
            store=store,
            now=now,
        )
        _api._cleanup_external_archive_downloads(final_evaluation)
        return denied
    bound_launch_command = _api._bound_external_archive_launch_command(
        launch_command,
        evaluation=final_evaluation,
    )
    if bound_launch_command is None:
        denied_evaluation = _api._package_policy_override_evaluation(
            final_evaluation,
            decision="block",
            policy_action="block",
            title="External archive blocked",
            summary="The inspected external archive could not be bound to the installer launch.",
            harness_message="HOL Guard blocked an external archive whose digest-bound blob was unavailable.",
            reason_code="external_archive_digest_mismatch",
            reason_message="The inspected external archive changed or was not present in the installer command.",
        )
        denied = _api._package_protect_denied_after_final_boundary(
            payload=payload,
            authority=final_authority,
            evaluation=denied_evaluation,
            command=command,
            store=store,
            now=now,
        )
        _api._cleanup_external_archive_downloads(final_evaluation)
        return denied
    authority = final_authority
    artifact = authority.artifact
    evaluation = final_evaluation
    final_projection = _api._apply_package_protect_projection(
        payload=payload,
        authority=authority,
        evaluation=evaluation,
        command=command,
        blocking=False,
        executed=True,
        execution_policy_action=final_execution_action,
    )
    verdict_action = final_projection.verdict_action
    risk_signals = final_projection.risk_signals
    try:
        execution = _api.subprocess.run(
            bound_launch_command,
            cwd=authority.launch_cwd,
            env=authority.launch_environment,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except (_api.subprocess.TimeoutExpired, OSError) as error:
        payload["execution"] = _api._build_command_execution_payload(
            stdout=_api._coerce_command_output(getattr(error, "stdout", None)),
            stderr=_api._coerce_command_error_output(error),
            returncode=-1,
            unsafe_raw_output=unsafe_raw_output,
        )
        store.add_event(
            "install_time_execution_failed",
            _api._install_time_event_payload(
                authority=authority,
                command=command,
                action=verdict_action,
                risk_signals=risk_signals,
                error=type(error).__name__,
            ),
            now,
        )
        _api._cleanup_external_archive_downloads(final_evaluation)
        return (payload, 1)
    payload["execution"] = _api._build_command_execution_payload(
        stdout=execution.stdout,
        stderr=execution.stderr,
        returncode=execution.returncode,
        unsafe_raw_output=unsafe_raw_output,
    )
    if execution.returncode == 0:
        store.add_receipt(final_projection.receipt)
        store.set_receipt_action_envelope(
            final_projection.receipt.receipt_id,
            final_projection.receipt_policy_metadata,
        )
        store.add_event(
            f"install_time_{verdict_action}",
            _api._install_time_event_payload(
                authority=authority,
                command=command,
                action=verdict_action,
                risk_signals=risk_signals,
            ),
            now,
        )
    else:
        store.add_event(
            "install_time_execution_failed",
            _api._install_time_event_payload(
                authority=authority,
                command=command,
                action=verdict_action,
                risk_signals=risk_signals,
                returncode=execution.returncode,
            ),
            now,
        )
    _api._cleanup_external_archive_downloads(final_evaluation)
    return (payload, int(execution.returncode))


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
