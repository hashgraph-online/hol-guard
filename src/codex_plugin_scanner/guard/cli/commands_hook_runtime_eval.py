"""Guard CLI runtime artifact hook evaluation."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_permission_store import (
        _persist_claude_native_permission_for_runtime_artifact,
        _record_cursor_pending_shell_permission,
    )
    from .commands_support_prompts import _runtime_artifact_native_reason
    from .commands_support_runtime_artifacts import _hook_event_name, _optional_string
    from .commands_support_runtime_policy import (
        _runtime_artifact_policy_action,
        _runtime_data_flow_summary,
        _runtime_saved_allow_validation_reason,
        _runtime_stored_policy_decision,
    )
    from .commands_support_runtime_resolution import (
        _canonical_harness_name,
        _legacy_claude_alias_runtime_artifact,
        _runtime_capabilities_summary,
        _runtime_request_summary,
        _runtime_requested_path,
    )


from ..action_lattice import (
    GuardActionNormalization,
    coerce_guard_action,
    guard_action_severity,
    most_restrictive_guard_action,
    normalize_guard_action,
    normalize_guard_action_result,
)
from ..approval_scope_support import package_request_runtime_workspace_scope
from ..models import GuardAction
from ..package_execution_context import PackageExecutionContext, build_package_execution_context
from ..runtime.approval_context import approval_context_tokens_validation_reason
from ..runtime.approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
    ApprovalReuseDecision,
    ApprovalReuseValidationFailure,
    evaluate_approval_reuse,
)
from ._commands_shared import *
from .commands_hook_github_workflow import (
    claimed_approval_request_id,
    github_workflow_approval_evidence,
    prepare_github_workflow_hook_state,
)
from .commands_hook_runtime_state import RuntimeArtifactHookState
from .commands_parser_helpers import *
from .commands_support_hook_state import _load_cursor_native_shell_allowance
from .commands_support_runtime_policy import (
    _remembered_rule_rejection_reason,
    _runtime_artifact_exact_match_context,
    _runtime_hook_approval_context_token,
    _runtime_saved_allow_validation_reason,
    _runtime_stored_policy_decision,
)


def _resolved_guard_action(value: object, fallback: GuardAction) -> GuardAction:
    return coerce_guard_action(value) or fallback


def _requested_policy_action_normalization(
    cli_action: object | None,
    stored_action: object | None,
    payload: Mapping[str, object],
) -> GuardActionNormalization | None:
    if cli_action is not None:
        return normalize_guard_action_result(cli_action, unknown_action="require-reapproval")
    if stored_action is not None:
        return normalize_guard_action_result(stored_action, unknown_action="require-reapproval")
    if "policy_action" in payload:
        return normalize_guard_action_result(payload.get("policy_action"), unknown_action="require-reapproval")
    return None


def _cursor_native_saved_approval_hash(
    store: GuardStore,
    payload: Mapping[str, object],
) -> str | None:
    """Return the context token carried by a fresh Cursor native allowance."""

    approved = _load_cursor_native_shell_allowance(store, payload)
    if approved is None:
        return None
    return _optional_string(approved.get("artifact_hash"))


def _evaluate_runtime_artifact_hook(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    context: HarnessContext,
    data_flow_signals: tuple[RiskSignalV2, ...],
    guard_home: Path,
    payload: Mapping[str, object],
    runtime_artifact: GuardArtifact,
    runtime_workspace: Path | None,
    store: GuardStore,
    trusted_request_override_hash: str | None = None,
    post_claim_revalidator: (Callable[[str, bool, str | None], int | RuntimeArtifactHookState | None] | None) = None,
    _claimed_saved_allow_hash: str | None = None,
    _claimed_trusted_request_override: bool = False,
    _claimed_approval_request_id: str | None = None,
    _claim_saved_approval: bool = True,
    _post_claim_refresh_failed: bool = False,
) -> int | RuntimeArtifactHookState:
    payload_map = dict(payload)

    workflow_state = prepare_github_workflow_hook_state(
        runtime_artifact,
        workspace=runtime_workspace,
        config=config,
        store=store,
        approval_request_id=_claimed_approval_request_id,
    )
    runtime_artifact = workflow_state.artifact

    def revalidate_claimed_allow(
        claimed_hash: str,
        *,
        trusted_request_override: bool,
        approval_request_id: str | None = None,
    ) -> int | RuntimeArtifactHookState:
        refresh_failed = False
        if post_claim_revalidator is not None:
            try:
                refreshed_result = post_claim_revalidator(
                    claimed_hash,
                    trusted_request_override,
                    approval_request_id,
                )
            except Exception:
                refreshed_result = None
            if refreshed_result is not None:
                return refreshed_result
            refresh_failed = True
        return _evaluate_runtime_artifact_hook(
            args,
            action_envelope=action_envelope,
            config=config,
            context=context,
            data_flow_signals=data_flow_signals,
            guard_home=guard_home,
            payload=payload,
            runtime_artifact=runtime_artifact,
            runtime_workspace=runtime_workspace,
            store=store,
            post_claim_revalidator=None,
            _claimed_saved_allow_hash=claimed_hash,
            _claimed_trusted_request_override=trusted_request_override,
            _claimed_approval_request_id=approval_request_id,
            _claim_saved_approval=False,
            _post_claim_refresh_failed=refresh_failed,
        )

    event_name = _hook_event_name(payload_map) or "PreToolUse"
    package_evaluation = None
    package_execution_context: PackageExecutionContext | None = None
    if runtime_artifact.artifact_type == "package_request":
        package_evaluation = evaluate_package_request_artifact(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
        )
        effective_package_workspace = runtime_workspace or Path.cwd()
        package_execution_context = build_package_execution_context(
            workspace_dir=effective_package_workspace,
            artifact=runtime_artifact,
        )
        artifact_content_hash = package_request_policy_hash(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=effective_package_workspace,
            evaluation=package_evaluation,
            execution_context=package_execution_context,
            config=config,
        )
    else:
        artifact_content_hash = artifact_hash(runtime_artifact)
    artifact_id = runtime_artifact.artifact_id
    artifact_name = runtime_artifact.name
    policy_harness = _canonical_harness_name(args.harness)
    cli_action = getattr(args, "policy_action", None)
    cli_action_normalization = (
        normalize_guard_action_result(cli_action, unknown_action="require-reapproval")
        if cli_action is not None
        else None
    )
    payload_action_normalization = (
        normalize_guard_action_result(payload_map.get("policy_action"), unknown_action="require-reapproval")
        if "policy_action" in payload_map
        else None
    )
    requested_action_normalization = cli_action_normalization or payload_action_normalization
    requested_policy_action = (
        requested_action_normalization.original_action if requested_action_normalization is not None else None
    )
    current_config_action = _resolved_guard_action(
        _runtime_artifact_policy_action(config, runtime_artifact, args.harness),
        "warn",
    )
    current_action_override = config.resolve_action_override(
        policy_harness,
        runtime_artifact.artifact_id,
        runtime_artifact.publisher,
    )
    current_action_inputs: list[GuardAction] = [current_config_action]
    if cli_action_normalization is not None:
        current_action_inputs.append(cli_action_normalization.action)
    if payload_action_normalization is not None:
        # Hook payloads are untrusted hints.  They may make a decision stricter,
        # but can never lower current local policy or suppress later scanners.
        current_action_inputs.append(payload_action_normalization.action)
    policy_action = most_restrictive_guard_action(*current_action_inputs)
    changed_capabilities = [runtime_artifact.artifact_type]
    scanner_evidence = (
        scan_action_for_cisco_evidence(action_envelope, workspace=runtime_workspace)
        if action_envelope is not None
        else ()
    )
    scanner_evidence_payload = [signal.to_dict() for signal in scanner_evidence]
    if workflow_state.approval_record is not None:
        scanner_evidence_payload.append(github_workflow_approval_evidence(workflow_state.approval_record))
    for input_source, normalization in (
        ("trusted_cli_override", cli_action_normalization),
        ("untrusted_hook_payload_hint", payload_action_normalization),
    ):
        if normalization is not None and not normalization.recognized:
            scanner_evidence_payload.append(
                {
                    "source": "guard_action_normalizer",
                    "input_source": input_source,
                    "reason_code": normalization.reason_code,
                    "original_action": normalization.original_action,
                    "original_type": normalization.original_type,
                    "normalized_action": normalization.action,
                }
            )
    if package_execution_context is not None:
        scanner_evidence_payload.append(package_execution_context.to_evidence())
    package_policy_action: GuardAction | None = (
        normalize_guard_action(package_evaluation.policy_action) if package_evaluation is not None else None
    )
    if package_policy_action is not None:
        policy_action = most_restrictive_guard_action(policy_action, package_policy_action)
    data_flow_action: GuardAction | None = None
    if data_flow_signals:
        data_flow_action = _resolved_guard_action(
            resolve_risk_action(
                config,
                "data_flow_exfiltration",
                harness=policy_harness,
            ),
            policy_action,
        )
        policy_action = most_restrictive_guard_action(policy_action, data_flow_action)
    _pre_scanner_policy_action = policy_action
    package_controls_pre_scanner_summary = (
        package_evaluation is not None
        and package_policy_action is not None
        and guard_action_severity(package_policy_action) >= guard_action_severity(_pre_scanner_policy_action)
    )
    scanner_action: GuardAction | None = None
    if scanner_evidence:
        scanner_action = policy_action_for_cisco_signals(
            scanner_evidence,
            config=config,
            harness=policy_harness,
        )
        policy_action = most_restrictive_guard_action(policy_action, scanner_action)
    scanner_raised_to_block = (
        policy_action == "block" and _pre_scanner_policy_action != "block" and bool(scanner_evidence)
    )
    base_decision_signals = data_flow_signals or artifact_risk_signals_v2(runtime_artifact)
    scanner_decision_signals = tuple(cisco_risk_signal_v3_to_v2(signal) for signal in scanner_evidence)
    if scanner_raised_to_block and scanner_decision_signals:
        decision_signals = (*scanner_decision_signals, *base_decision_signals)
    else:
        decision_signals = (*base_decision_signals, *scanner_decision_signals)
    scanner_risk_signals = [signal.plain_language_summary for signal in scanner_evidence]
    if data_flow_signals:
        risk_signals = [signal.plain_reason for signal in data_flow_signals]
        risk_summary = _runtime_data_flow_summary(data_flow_signals)
    else:
        risk_signals = list(artifact_risk_signals(runtime_artifact))
        risk_summary = artifact_risk_summary(runtime_artifact)
    if package_controls_pre_scanner_summary and package_evaluation is not None:
        risk_signals = [str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons]
        risk_summary = package_evaluation.risk_summary
        scanner_evidence_payload.extend(
            {
                "decision": package_evaluation.decision,
                "enforcement": package_evaluation.enforcement,
                "exception_id": package_evaluation.exception_id,
                "matched_rule_id": package_evaluation.matched_rule_id,
                "package": package,
            }
            for package in package_evaluation.packages
        )
    if scanner_risk_signals:
        risk_signals.extend(scanner_risk_signals)
        if scanner_raised_to_block:
            risk_summary = scanner_risk_signals[0]
    current_policy_action = policy_action
    runtime_artifact_hash = _runtime_hook_approval_context_token(
        artifact=runtime_artifact,
        content_hash=artifact_content_hash,
        runtime_workspace=runtime_workspace,
        action_envelope=action_envelope,
        config=config,
        current_config_action=current_config_action,
        trusted_cli_action=cli_action_normalization.action if cli_action_normalization is not None else None,
        untrusted_payload_action=(
            payload_action_normalization.action if payload_action_normalization is not None else None
        ),
        package_action=package_policy_action,
        data_flow_action=data_flow_action,
        scanner_action=scanner_action,
        current_action=current_policy_action,
        data_flow_signals=data_flow_signals,
        scanner_evidence=scanner_evidence,
    )
    policy_workspace = str(runtime_workspace) if runtime_workspace else None
    if package_execution_context is not None:
        policy_workspace = package_request_runtime_workspace_scope(
            artifact_id=runtime_artifact.artifact_id,
            artifact_hash=runtime_artifact_hash,
            artifact_type=runtime_artifact.artifact_type,
            execution_context=package_execution_context,
        )
    claude_native_approval_observed = False
    claude_native_approval_saved = False
    if _canonical_harness_name(args.harness) == "claude-code" and event_name in {
        "PostToolUse",
        "PostToolUseFailure",
    }:
        native_reuse = evaluate_approval_reuse(
            current_policy_action,
            "allow",
            saved_decision_present=True,
        )
        claude_native_approval_observed, claude_native_approval_saved = (
            _persist_claude_native_permission_for_runtime_artifact(
                store=store,
                payload=payload_map,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                action="allow",
                authoritative_action=native_reuse.action,
                reason="Approved in Claude native approval prompt.",
            )
        )
        scanner_evidence_payload.append(
            {
                "source": "claude_native_approval",
                "native_action": "allow",
                "observed": claude_native_approval_observed,
                "reusable_policy_saved": claude_native_approval_saved,
                "current_action": current_policy_action,
                "authoritative_action": native_reuse.action,
                "approval_reuse": native_reuse.to_evidence(),
            }
        )

    # Resolve saved evidence only after all current policy, package, data-flow,
    # scanner, configuration, workspace, and sandbox inputs are frozen above.
    runtime_exact_match_context = _runtime_artifact_exact_match_context(runtime_artifact)
    policy_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        policy_harness,
        artifact_id,
        artifact_hash=runtime_artifact_hash,
        workspace=policy_workspace,
        publisher=runtime_artifact.publisher,
        runtime_exact_match_context=runtime_exact_match_context,
        memory_command=runtime_artifact.command,
        memory_artifact_type=runtime_artifact.artifact_type,
        memory_artifact_name=runtime_artifact.name,
        consume_one_shot=False,
    )
    stored_policy_decision = _runtime_stored_policy_decision(
        store=store,
        harness=policy_harness,
        artifact=runtime_artifact,
        artifact_id=artifact_id,
        artifact_hash=runtime_artifact_hash,
        workspace=policy_workspace,
        decision_lookup=policy_lookup,
        consume_one_shot=False,
    )
    # Legacy exact hashes cannot authorize an allow, but they must still be
    # inspected even when a v1 decision exists: a new exact allow must never
    # hide an intentionally retained pre-v1 block during migration.
    legacy_policy_workspace = str(runtime_workspace) if runtime_workspace else None
    if package_execution_context is not None:
        legacy_policy_workspace = package_request_runtime_workspace_scope(
            artifact_id=runtime_artifact.artifact_id,
            artifact_hash=artifact_content_hash,
            artifact_type=runtime_artifact.artifact_type,
            execution_context=package_execution_context,
        )
    legacy_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        policy_harness,
        artifact_id,
        artifact_hash=artifact_content_hash,
        workspace=legacy_policy_workspace,
        publisher=runtime_artifact.publisher,
        runtime_exact_match_context=runtime_exact_match_context,
        memory_command=runtime_artifact.command,
        memory_artifact_type=runtime_artifact.artifact_type,
        memory_artifact_name=runtime_artifact.name,
        consume_one_shot=False,
    )
    legacy_decision = _runtime_stored_policy_decision(
        store=store,
        harness=policy_harness,
        artifact=runtime_artifact,
        artifact_id=artifact_id,
        artifact_hash=artifact_content_hash,
        workspace=legacy_policy_workspace,
        decision_lookup=legacy_lookup,
        consume_one_shot=False,
    )
    if legacy_lookup.get("ignored_local_integrity") is not None:
        policy_lookup = {
            **policy_lookup,
            "ignored_local_integrity": legacy_lookup["ignored_local_integrity"],
        }
    if legacy_decision is not None and (
        stored_policy_decision is None
        or guard_action_severity(legacy_decision.get("action"), unknown_action="block")
        > guard_action_severity(stored_policy_decision.get("action"), unknown_action="block")
    ):
        merged_integrity = policy_lookup.get("ignored_local_integrity")
        policy_lookup = dict(legacy_lookup)
        if merged_integrity is not None:
            policy_lookup["ignored_local_integrity"] = merged_integrity
        stored_policy_decision = legacy_decision
    if stored_policy_decision is None and runtime_artifact.artifact_type != "package_request":
        legacy_artifact = _legacy_claude_alias_runtime_artifact(
            artifact=runtime_artifact,
            requested_harness=args.harness,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
        )
        if legacy_artifact is not None:
            stored_policy_decision = _runtime_stored_policy_decision(
                store=store,
                harness=args.harness,
                artifact=legacy_artifact,
                artifact_id=legacy_artifact.artifact_id,
                artifact_hash=artifact_hash(legacy_artifact),
                workspace=str(runtime_workspace) if runtime_workspace else None,
                consume_one_shot=False,
            )
    stored_policy_action = (
        _optional_string(stored_policy_decision.get("action")) if stored_policy_decision is not None else None
    )
    remembered_rule_rejection = policy_lookup.get("ignored_local_integrity")
    trust_status = policy_lookup["trust_status"]
    cursor_native_approval_hash = (
        _cursor_native_saved_approval_hash(store, payload)
        if policy_harness == "cursor"
        and event_name == "PreToolUse"
        and runtime_artifact.artifact_type == "tool_action_request"
        else None
    )
    approval_reuse: ApprovalReuseDecision | None = None
    package_approval_reuse_evidence: dict[str, object] | None = None
    approval_reuse_source: str | None = None
    if package_evaluation is not None:
        # Package approval lookup/claim is deferred until every current policy,
        # data-flow, and scanner input has been composed.
        package_evaluation = apply_stored_package_policy_override(
            package_evaluation,
            store=store,
            artifact=runtime_artifact,
            artifact_hash=runtime_artifact_hash,
            workspace_dir=runtime_workspace or Path.cwd(),
            now=_now(),
            execution_context=package_execution_context,
            current_action=current_policy_action,
            claim_saved_approval=_claim_saved_approval,
        )
        package_reuse_applied = False
        package_saved_allow_applied = False
        for reason in package_evaluation.reasons:
            if reason.get("code") in {"saved_package_approval", "saved_package_block"}:
                package_reuse_applied = True
                approval_reuse_source = "saved_package_policy"
            if reason.get("code") == "saved_package_approval":
                package_saved_allow_applied = True
            raw_reuse = reason.get("approval_reuse")
            if isinstance(raw_reuse, Mapping):
                package_reuse_applied = True
                package_approval_reuse_evidence = dict(raw_reuse)
                scanner_evidence_payload.append(
                    {
                        "source": "approval_reuse",
                        "input_source": "saved_package_policy",
                        **dict(raw_reuse),
                    }
                )
                approval_reuse_source = "saved_package_policy"
                break
        if package_saved_allow_applied and _claim_saved_approval:
            return revalidate_claimed_allow(
                runtime_artifact_hash,
                trusted_request_override=False,
            )
        policy_action = (
            _resolved_guard_action(package_evaluation.policy_action, current_policy_action)
            if package_reuse_applied
            else current_policy_action
        )
        if stored_policy_action == "block":
            approval_reuse = evaluate_approval_reuse(
                current_policy_action,
                "block",
                saved_decision_present=True,
            )
            policy_action = most_restrictive_guard_action(policy_action, approval_reuse.action)
            approval_reuse_source = approval_reuse_source or "saved_policy_decision"
            if not package_reuse_applied:
                scanner_evidence_payload.append(
                    {
                        "source": "approval_reuse",
                        "input_source": approval_reuse_source,
                        **approval_reuse.to_evidence(),
                    }
                )
        if policy_action != current_policy_action:
            risk_signals = [str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons]
            risk_summary = package_evaluation.risk_summary
    else:
        saved_action: object | None = stored_policy_action
        saved_present = stored_policy_decision is not None
        validation_reason: ApprovalReuseValidationFailure | None = None
        if policy_lookup.get("ignored_local_integrity") is not None:
            # A matching integrity-invalid local rule is security-relevant even
            # when a different, valid saved allow also matched.  Letting the
            # valid row win would make a tampered broader block invisible.
            validation_reason = "approval_reuse_integrity_failure"
        elif stored_policy_decision is not None:
            stored_validation_reason = _runtime_saved_allow_validation_reason(
                stored_policy_decision,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
            )
            if stored_validation_reason is not None:
                validation_reason = cast(ApprovalReuseValidationFailure, stored_validation_reason)
        if not saved_present and cursor_native_approval_hash is not None:
            saved_action = "allow"
            saved_present = True
            approval_reuse_source = "cursor_native_approval"
            cursor_validation_reason = approval_context_tokens_validation_reason(
                cursor_native_approval_hash,
                runtime_artifact_hash,
            )
            if cursor_validation_reason is not None:
                validation_reason = cast(ApprovalReuseValidationFailure, cursor_validation_reason)
        elif not saved_present and validation_reason is None:
            diagnosed_reason = store.approval_reuse_validation_reason(
                policy_harness,
                artifact_id,
                runtime_artifact_hash,
                policy_workspace,
                runtime_artifact.publisher,
                _now(),
            )
            if diagnosed_reason is not None:
                validation_reason = cast(ApprovalReuseValidationFailure, diagnosed_reason)
                saved_action = "allow"
        if saved_present:
            approval_reuse_source = approval_reuse_source or "saved_policy_decision"
        elif validation_reason is not None:
            saved_present = True
            approval_reuse_source = (
                "saved_policy_integrity"
                if validation_reason == "approval_reuse_integrity_failure"
                else "invalidated_saved_policy"
            )
        approval_reuse = evaluate_approval_reuse(
            current_policy_action,
            saved_action,
            saved_decision_present=saved_present,
            validation_reason=validation_reason,
        )
        if approval_reuse.should_claim and stored_policy_decision is not None and _claim_saved_approval:
            if not store.claim_approval_reuse_decision(stored_policy_decision, now=_now()):
                approval_reuse = evaluate_approval_reuse(
                    current_policy_action,
                    saved_action,
                    saved_decision_present=True,
                    validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
                )
            else:
                return revalidate_claimed_allow(
                    runtime_artifact_hash,
                    trusted_request_override=False,
                    approval_request_id=claimed_approval_request_id(stored_policy_decision),
                )
        policy_action = approval_reuse.action
        if approval_reuse_source is not None:
            scanner_evidence_payload.append(
                {
                    "source": "approval_reuse",
                    "input_source": approval_reuse_source,
                    **approval_reuse.to_evidence(),
                }
            )
    trusted_request_override_applied = False
    trusted_request_override_reason: str | None = None
    if trusted_request_override_hash is not None:
        trusted_request_override_reason = approval_context_tokens_validation_reason(
            trusted_request_override_hash,
            runtime_artifact_hash,
        )
        if trusted_request_override_reason is None and policy_action in {
            "review",
            "require-reapproval",
        }:
            if remembered_rule_rejection is not None or (
                approval_reuse is not None and approval_reuse.reason_code == "approval_reuse_integrity_failure"
            ):
                trusted_request_override_reason = "trusted_request_override_integrity_failure"
            elif (
                stored_policy_decision is not None
                and stored_policy_decision.get("action") == "allow"
                and stored_policy_decision.get("source")
                in {
                    "approval-gate",
                    "approval-gate-once",
                }
                and _runtime_saved_allow_validation_reason(
                    stored_policy_decision,
                    artifact=runtime_artifact,
                    artifact_hash=runtime_artifact_hash,
                )
                is None
            ):
                if store.claim_approval_reuse_decision(
                    stored_policy_decision,
                    now=_now(),
                ):
                    return revalidate_claimed_allow(
                        runtime_artifact_hash,
                        trusted_request_override=True,
                        approval_request_id=claimed_approval_request_id(stored_policy_decision),
                    )
                else:
                    trusted_request_override_reason = "trusted_request_override_claim_failed"
            else:
                trusted_request_override_reason = "trusted_request_override_allow_missing"
        scanner_evidence_payload.append(
            {
                "source": "trusted_request_override",
                "applied": trusted_request_override_applied,
                "reason_code": trusted_request_override_reason,
                "authoritative_action": policy_action,
            }
        )
    if _claimed_saved_allow_hash is not None:
        context_changed = approval_context_tokens_validation_reason(
            _claimed_saved_allow_hash,
            runtime_artifact_hash,
        )
        claimed_validation_reason: ApprovalReuseValidationFailure | None = (
            APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM
            if _post_claim_refresh_failed or context_changed is not None
            else None
        )
        if remembered_rule_rejection is not None or (
            approval_reuse is not None and approval_reuse.reason_code == "approval_reuse_integrity_failure"
        ):
            claimed_validation_reason = "approval_reuse_integrity_failure"
        if workflow_state.capability_required and not workflow_state.authorization_claimed:
            claimed_validation_reason = "approval_reuse_integrity_failure"

        post_claim_current_action = policy_action
        if (
            approval_reuse is not None and approval_reuse.saved_action == "allow" and approval_reuse.action == "allow"
        ) or (
            package_approval_reuse_evidence is not None
            and package_approval_reuse_evidence.get("saved_action") == "allow"
            and policy_action == "allow"
        ):
            post_claim_current_action = current_policy_action
        if claimed_validation_reason is not None:
            post_claim_current_action = most_restrictive_guard_action(
                post_claim_current_action,
                "require-reapproval",
            )
        elif _claimed_trusted_request_override and post_claim_current_action in {
            "review",
            "require-reapproval",
        }:
            # A just-resolved exact browser request is stronger than ordinary
            # remembered approval evidence. It may satisfy the current request
            # only after its one-shot row has been claimed and the complete
            # runtime authority has been rebuilt.
            post_claim_current_action = "review"
        approval_reuse = evaluate_approval_reuse(
            post_claim_current_action,
            "allow",
            saved_decision_present=True,
            validation_reason=claimed_validation_reason,
        )
        policy_action = approval_reuse.action
        approval_reuse_source = (
            "claimed_trusted_request_override" if _claimed_trusted_request_override else "claimed_saved_policy_decision"
        )
        trusted_request_override_applied = (
            _claimed_trusted_request_override and approval_reuse.accepted and approval_reuse.action == "allow"
        )
        trusted_request_override_reason = (
            "trusted_request_override_exact_context" if trusted_request_override_applied else claimed_validation_reason
        )
        scanner_evidence_payload.append(
            {
                "source": "approval_reuse",
                "input_source": approval_reuse_source,
                **approval_reuse.to_evidence(),
            }
        )
    policy_composition = {
        "current_config_action": current_config_action,
        "current_action_override": current_action_override,
        "trusted_cli_override": cli_action_normalization.action if cli_action_normalization is not None else None,
        "untrusted_hook_payload_hint": (
            payload_action_normalization.action if payload_action_normalization is not None else None
        ),
        "package_action": package_policy_action,
        "data_flow_action": data_flow_action,
        "scanner_action": scanner_action,
        "current_composed_action": current_policy_action,
        "saved_policy_action": stored_policy_action,
        "approval_reuse_source": approval_reuse_source,
        "trusted_request_override": trusted_request_override_applied,
        "trusted_request_override_reason": trusted_request_override_reason,
        "authoritative_action": policy_action,
    }
    scanner_evidence_payload.append(
        {
            "source": "policy_composition",
            **policy_composition,
        }
    )
    if action_envelope is not None:
        action_envelope = action_envelope.with_pre_execution_result(policy_action)
    decision_v2 = build_decision_v2(policy_action, reason=policy_action, signals=decision_signals)
    decision_v2_payload = decision_v2.to_dict()
    if package_evaluation is not None and package_policy_action == policy_action:
        decision_v2_payload["user_title"] = package_evaluation.user_copy.title
        decision_v2_payload["user_body"] = package_evaluation.user_copy.summary
        decision_v2_payload["harness_message"] = package_evaluation.user_copy.harness_message
        decision_v2_payload["dashboard_primary_detail"] = package_evaluation.user_copy.summary
    incident = build_incident_context(
        harness=args.harness,
        artifact=runtime_artifact,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        artifact_type=runtime_artifact.artifact_type,
        source_scope=runtime_artifact.source_scope,
        config_path=runtime_artifact.config_path,
        changed_fields=changed_capabilities,
        policy_action=policy_action,  # type: ignore[arg-type]
        launch_target=_runtime_request_summary(runtime_artifact),
        risk_summary=risk_summary,
    )
    receipt = build_receipt(
        harness=args.harness,
        artifact_id=artifact_id,
        artifact_hash=runtime_artifact_hash,
        policy_decision=policy_action,
        capabilities_summary=_runtime_capabilities_summary(runtime_artifact),
        changed_capabilities=changed_capabilities,
        provenance_summary=f"runtime tool request evaluated from {runtime_artifact.config_path}",
        artifact_name=artifact_name,
        source_scope=runtime_artifact.source_scope,
        user_override=(
            "claude-native-approve"
            if claude_native_approval_observed
            else _optional_string(payload_map.get("user_override"))
        ),
        scanner_evidence=scanner_evidence_payload,
        approval_source=(
            "inline"
            if claude_native_approval_observed or _optional_string(payload_map.get("user_override")) is not None
            else "approval_center"
            if policy_action == "require-reapproval"
            else "policy"
        ),
    )
    response_payload: dict[str, object] = {
        # Receipt persistence is intentionally delayed until the browser wait,
        # when present, has produced the authoritative final action.
        "recorded": False,
        "harness": _canonical_harness_name(args.harness),
        "artifact_id": artifact_id,
        "artifact_hash": runtime_artifact_hash,
        "artifact_name": artifact_name,
        "artifact_type": runtime_artifact.artifact_type,
        "policy_action": policy_action,
        "risk_signals": risk_signals,
        "risk_summary": risk_summary,
        "scanner_evidence": scanner_evidence_payload,
        "decision_v2_json": decision_v2_payload,
        "artifact_label": incident["artifact_label"],
        "source_label": incident["source_label"],
        "trigger_summary": incident["trigger_summary"],
        "why_now": incident["why_now"],
        "launch_summary": incident["launch_summary"],
        "risk_headline": incident["risk_headline"],
        "path_summary": _runtime_requested_path(runtime_artifact),
        "trust_status": trust_status,
        "policy_composition": policy_composition,
    }
    if approval_reuse is not None:
        response_payload["approval_reuse"] = approval_reuse.to_evidence()
    elif package_approval_reuse_evidence is not None:
        response_payload["approval_reuse"] = package_approval_reuse_evidence
    if remembered_rule_rejection is not None:
        response_payload["remembered_rule_rejection"] = remembered_rule_rejection
        if policy_action in {"review", "require-reapproval"}:
            remembered_rule_reason = _remembered_rule_rejection_reason(
                response_payload=response_payload,
                artifact=runtime_artifact,
            )
        else:
            remembered_rule_reason = None
        if remembered_rule_reason is not None:
            decision_v2_payload["harness_message"] = remembered_rule_reason
            decision_v2_payload["dashboard_primary_detail"] = remembered_rule_reason
            decision_v2_payload["detail_reason_code"] = "remembered_rule_ignored_degraded_trust"
            response_payload["risk_headline"] = remembered_rule_reason
    if package_evaluation is not None:
        response_payload["supply_chain_evaluation"] = package_evaluation.to_dict()
    if (
        _canonical_harness_name(args.harness) == "cursor"
        and config.mode != "observe"
        and event_name == "PreToolUse"
        and runtime_artifact.artifact_type == "tool_action_request"
    ):
        from ..adapters.cursor_hooks import cursor_hook_would_prompt_user

        if cursor_hook_would_prompt_user(
            policy_action=policy_action,
            guard_payload=response_payload,
        ):
            native_reason = _runtime_artifact_native_reason(runtime_artifact, response_payload)
            _record_cursor_pending_shell_permission(
                store=store,
                guard_home=context.guard_home,
                payload=payload_map,
                reason=native_reason,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
            )
    return RuntimeArtifactHookState(
        action_envelope=action_envelope,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        browser_approval_daemon_client=None,
        changed_capabilities=changed_capabilities,
        decision_signals=tuple(decision_signals),
        decision_v2_payload=decision_v2_payload,
        event_name=event_name,
        guard_home=context.guard_home,
        hook_payload=payload_map,
        initial_policy_action=policy_action,
        package_evaluation=package_evaluation,
        policy_action=policy_action,
        receipt=receipt,
        requested_policy_action=requested_policy_action,
        response_payload=response_payload,
        risk_summary=risk_summary,
        runtime_artifact=runtime_artifact,
        runtime_artifact_hash=runtime_artifact_hash,
        scanner_evidence_payload=scanner_evidence_payload,
        stored_policy_action=stored_policy_action,
        workflow_authorization_claimed=workflow_state.authorization_claimed,
    )


__all__ = [
    "_evaluate_runtime_artifact_hook",
    "_requested_policy_action_normalization",
]
