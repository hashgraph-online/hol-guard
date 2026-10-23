"""Guard CLI runtime artifact hook evaluation."""

# ruff: noqa: F403, F405

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .commands_support import *

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_hook_payload import _apply_native_edge_envelope_fields
    from .commands_support_permission_store import (
        _persist_claude_native_permission_for_runtime_artifact,
        _record_cursor_pending_shell_permission,
    )
    from .commands_support_prompts import _runtime_artifact_native_reason
    from .commands_support_runtime_policy import (
        _runtime_data_flow_summary,
        _runtime_saved_policy_decision,
    )
    from .commands_support_runtime_resolution import (
        _canonical_harness_name,
        _legacy_claude_alias_runtime_artifact,
        _runtime_capabilities_summary,
        _runtime_request_summary,
        _runtime_requested_path,
    )


from ..approval_scope_support import package_request_runtime_workspace_scope
from ..harness_posture import harness_is_recording_only
from ..local_supply_chain import (
    _package_evaluation_requires_external_archive_binding,
    package_external_archive_override,
)
from ..models import GuardAction
from ..native_hook_artifact_compose import native_hook_compose
from ..native_hook_artifact_reuse_step import ReusePlan, ReuseSettled, native_artifact_reuse_step
from ..native_hook_decision import NativeHookDecisionError
from ..native_shim_admin import NativeShimAdminError
from ..package_execution_context import PackageExecutionContext, build_package_execution_context
from ..protection_posture import is_high_confidence
from ..runtime.approval_reuse import approval_reuse_authority_unavailable, evaluate_approval_reuse
from ..runtime.signals import GuardRiskSignalV3
from ..shims import package_shim_digest_binding_sink
from ..trusted_local_tools import (
    LocalToolApprovalEligibility,
    local_tool_approval_eligibility,
    matching_local_tool_grant,
)
from ._commands_shared import *
from .commands_hook_decision_copy import native_hook_decision_copy
from .commands_hook_github_workflow import github_workflow_approval_evidence, prepare_github_workflow_hook_state
from .commands_hook_native_edge_facts import _native_edge_facts
from .commands_hook_native_floor import (
    _runtime_package_raw_command,
    native_pre_tool_floor,
    runtime_hook_scanner_setup,
    settle_local_grants,
)
from .commands_hook_native_policy_tail import local_eligibility_required, settled_policy_composition
from .commands_hook_native_reuse import (
    claim_saved_decision,
    execute_reuse_plan,
    package_reuse_floor,
    reuse_step_facts,
)
from .commands_hook_native_state import NativeArtifactHookState
from .commands_parser_helpers import *
from .commands_support_hook_state import _load_cursor_native_shell_allowance
from .commands_support_runtime_artifact_policy import (
    artifact_fact_content_hash,
    artifact_fact_risk_classes,
    artifact_fact_skip_native_floor,
    record_policy_auto_stops,
    runtime_policy_artifact_facts_batch,
    runtime_policy_config_facts,
)
from .commands_support_runtime_artifacts import _hook_event_name, _optional_string
from .commands_support_runtime_policy import (
    _remembered_rule_rejection_reason,
    _runtime_hook_approval_context_token,
    _runtime_saved_policy_decision,
)


def _claimed_saved_package_allow(reasons: Sequence[Mapping[str, object]]) -> str | None:
    """The disposition of a saved package allow the resolver already claimed.

    Reading back the claim the resolver made is not a verdict. An approval
    taken out of the store has to be revalidated at the execution boundary
    whether or not the resident can settle the reuse, so an unreachable
    resident must never turn a consumed approval into a silent allow.
    """

    for reason in reasons:
        if reason.get("code") != "saved_package_approval":
            continue
        disposition = reason.get("approval_claim_disposition")
        return str(disposition) if disposition in {"consumed", "retained"} else "retained"
    return None


def _runtime_external_archive_has_digest_binding_sink(
    *,
    artifact: GuardArtifact,
    context: HarnessContext,
    raw_command: str | None,
    runtime_workspace: Path | None,
) -> bool:
    """Does a verified shim own this external-archive download's approval?

    The shim binds the approval to the digest of the bytes it fetches itself,
    so it owns the approval only when the command is a bare launch of that
    shim. The resident parses the command and resolves both paths; this side
    only names the manager and executable the artifact carries. An unreachable
    resident answers no, which leaves the approval with the user rather than
    with an unverified shim.
    """

    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    manager = _optional_string(metadata.get("package_manager"))
    executable = _optional_string(metadata.get("package_executable"))
    if manager is None or executable is None:
        return False
    try:
        return package_shim_digest_binding_sink(
            context,
            manager=manager,
            executable=executable,
            command=raw_command,
            workspace_dir=runtime_workspace,
            path_env=os.environ.get("PATH", ""),
        )
    except NativeShimAdminError:
        return False


def _stamp_runtime_posture_metadata(artifact: object, signals: object) -> None:
    metadata = getattr(artifact, "metadata", None)
    if not isinstance(metadata, dict):
        return
    if isinstance(signals, tuple) and signals:
        metadata["risk_signals"] = [
            {
                "confidence": getattr(signal, "confidence", None),
                "category": getattr(signal, "category", None),
            }
            for signal in signals
        ]
        if any(getattr(signal, "confidence", None) == "strong" for signal in signals):
            metadata["risk_confidence"] = "strong"


def _embedded_script_evidence(command_text: str) -> list[dict[str, object]]:
    """Hash-addressed audit entries for heredoc script bodies (lazy import)."""

    from ..runtime.embedded_script_evidence import embedded_script_evidence_entries

    return embedded_script_evidence_entries(command_text)


def _runtime_cisco_scanner_evidence(
    action_envelope: GuardActionEnvelope,
    *,
    runtime_workspace: Path | None,
    raw_shell_cwds: object,
) -> tuple[GuardRiskSignalV3, ...]:
    """Scan every distinct proven shell cwd that may resolve a relative target.

    The resident plans the action against each of those directories and
    approves the rest for every one of those plans, so the directories are
    handed over as the payload reported them: which of them is a scan root,
    and which findings they share, are the resident's to settle.
    """

    return scan_action_for_cisco_evidence(
        action_envelope,
        workspace=runtime_workspace,
        shell_cwds=raw_shell_cwds if isinstance(raw_shell_cwds, list) else (),
    )


def evaluate_native_artifact_hook(
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
    post_claim_revalidator: (
        Callable[[str, bool, str | None, bool], int | NativeArtifactHookState | None] | None
    ) = None,
    _claimed_saved_allow_hash: str | None = None,
    _claimed_trusted_request_override: bool = False,
    _claimed_package_approval_consumed: bool = False,
    _claimed_approval_request_id: str | None = None,
    _claim_saved_approval: bool = True,
    _post_claim_refresh_failed: bool = False,
    native_edge_result: Mapping[str, object] | None = None,
    native_edge_receipt: Mapping[str, object] | None = None,
    native_recording_only: bool = False,
) -> int | NativeArtifactHookState:
    from ..native_context import bind_context_digest_home

    bind_context_digest_home(guard_home)
    payload_map = dict(payload)
    workflow_state = prepare_github_workflow_hook_state(
        runtime_artifact,
        workspace=runtime_workspace,
        guard_home=guard_home,
        config=config,
        store=store,
        approval_request_id=_claimed_approval_request_id,
    )
    runtime_artifact = workflow_state.artifact
    approval_context_artifact = runtime_artifact
    if workflow_state.approval_record is not None:
        # Native decision outputs and availability may change after a capability
        # claim. Bind reviewed inputs while the full artifact drives enforcement.
        approval_context_metadata = dict(runtime_artifact.metadata)
        for key in ("command_action_floor", "command_decision_plane", "command_evaluation_status"):
            approval_context_metadata.pop(key, None)
        approval_context_artifact = replace(runtime_artifact, metadata=approval_context_metadata)

    def revalidate_claimed_allow(
        claimed_hash: str,
        *,
        trusted_request_override: bool,
        package_approval_consumed: bool = False,
        approval_request_id: str | None = None,
    ) -> int | NativeArtifactHookState:
        refresh_failed = False
        if post_claim_revalidator is not None:
            try:
                refreshed_result = post_claim_revalidator(
                    claimed_hash,
                    trusted_request_override,
                    approval_request_id,
                    package_approval_consumed,
                )
            except Exception:
                refreshed_result = None
            if refreshed_result is not None:
                return refreshed_result
            refresh_failed = True
        return evaluate_native_artifact_hook(
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
            _claimed_package_approval_consumed=package_approval_consumed,
            _claimed_approval_request_id=approval_request_id,
            _claim_saved_approval=False,
            _post_claim_refresh_failed=refresh_failed,
        )

    event_name = _hook_event_name(payload_map) or "PreToolUse"
    package_evaluation = None
    package_execution_context: PackageExecutionContext | None = None
    artifact_content_hash: str | None = None
    if runtime_artifact.artifact_type == "package_request":
        package_evaluation = evaluate_package_request_artifact(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
            external_archive_network_authorized=False,
        )
        if _package_evaluation_requires_external_archive_binding(package_evaluation, guard_home=guard_home):
            has_binding_sink = _runtime_external_archive_has_digest_binding_sink(
                artifact=runtime_artifact,
                context=context,
                raw_command=_runtime_package_raw_command(payload_map, action_envelope),
                runtime_workspace=runtime_workspace,
            )
            if not has_binding_sink:
                package_evaluation = package_external_archive_override(
                    package_evaluation,
                    variant="binding_unavailable",
                )
            else:
                # The verified shim is the sole approval owner: it performs
                # the post-approval restricted download, digest binding, and
                # launch.  Asking under the hook artifact as well would create
                # a second, unrelated approval that cannot authorize the shim.
                package_evaluation = package_external_archive_override(
                    package_evaluation,
                    variant="shim_delegated",
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
    # Anything other than a package request is hashed by the resident: see the
    # facts request below.
    artifact_id = runtime_artifact.artifact_id
    artifact_name = runtime_artifact.name
    policy_harness = _canonical_harness_name(args.harness)
    cli_action = getattr(args, "policy_action", None)
    # A saved approval is keyed by the artifact as it stood before this hook
    # stamped its runtime posture onto the metadata, so the identity is taken
    # before the stamp: keying it by the stamped metadata would stop a saved
    # approval matching the moment a risk signal appeared.
    approval_identity_metadata = None if artifact_content_hash is not None else dict(approval_context_artifact.metadata)
    _stamp_runtime_posture_metadata(runtime_artifact, data_flow_signals)
    _stamp_runtime_posture_metadata(approval_context_artifact, data_flow_signals)
    current_action_override = config.resolve_action_override(
        policy_harness,
        runtime_artifact.artifact_id,
        runtime_artifact.publisher,
    )
    # The alias artifact a pre-rename claude-code approval was saved under is
    # resolved here so its digest rides the same request: it renames the
    # runtime artifact and shares its metadata, so nothing between here and
    # the saved-decision lookup below changes what it hashes to.
    legacy_artifact = (
        None
        if runtime_artifact.artifact_type == "package_request"
        else _legacy_claude_alias_runtime_artifact(
            artifact=runtime_artifact,
            requested_harness=args.harness,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
        )
    )
    # Every artifact's facts are asked for in one request, under the same
    # ``guard_home`` the composition below uses: the facts and the verdict that
    # reads them must come from one resident, and one round trip rather than
    # two keeps the hook off the resident's critical path twice over.
    facts_requests: list[tuple[GuardArtifact, str]] = [
        (runtime_artifact, args.harness),
        (approval_context_artifact, policy_harness),
    ]
    facts_identities: list[Mapping[str, object] | None] = [None, approval_identity_metadata]
    if legacy_artifact is not None:
        # The alias is hashed over the metadata as it now stands, stamp and
        # all: a pre-rename approval was saved under that spelling, so naming
        # the current metadata as the identity leaves the stamp empty and the
        # resident hashes the artifact exactly as it is sent.
        facts_requests.append((legacy_artifact, args.harness))
        facts_identities.append(legacy_artifact.metadata)
    runtime_facts, approval_context_facts, *alias_facts = runtime_policy_artifact_facts_batch(
        config,
        tuple(facts_requests),
        guard_home=guard_home,
        hash_metadata=tuple(facts_identities),
    )
    if artifact_content_hash is None:
        artifact_content_hash = artifact_fact_content_hash(approval_context_facts)
    # The resident says whether the generic command floor applies: a package
    # install is decided by the package evaluator and a verified
    # explicit-permission allow was already adjudicated, so the floor is only
    # asked for when the facts do not skip it.
    native_floor = (
        None
        if artifact_fact_skip_native_floor(runtime_facts)
        else native_pre_tool_floor(
            event_name,
            payload_map,
            action_envelope,
            guard_home=context.guard_home,
            cwd=runtime_workspace,
            home_dir=context.home_dir,
            store=store,
        )
    )
    changed_capabilities, artifact_metadata, scanner_evidence = runtime_hook_scanner_setup(
        runtime_artifact,
        action_envelope,
        runtime_workspace,
        _runtime_cisco_scanner_evidence,
    )
    data_flow_strong = any(is_high_confidence(getattr(signal, "confidence", None)) for signal in data_flow_signals)
    compound_finding_count = artifact_metadata.get("compound_finding_count")
    has_compound_findings = isinstance(compound_finding_count, int) and compound_finding_count > 1
    scanner_risk_signals = [signal.plain_language_summary for signal in scanner_evidence]
    artifact_risk = artifact_risk_profile(runtime_artifact)
    raw_runtime_command = _runtime_package_raw_command(payload_map, action_envelope)
    stack = native_hook_compose(
        "policy_stack",
        {
            "event_name": event_name,
            "artifact_type": runtime_artifact.artifact_type,
            "has_raw_command": raw_runtime_command is not None,
            "policy_config": runtime_policy_config_facts(config, args.harness),
            "runtime": runtime_facts,
            "approval_context": approval_context_facts,
            "data_flow_strong": data_flow_strong,
            "cli_action": cli_action,
            "payload_action_present": "policy_action" in payload_map,
            "payload_action": payload_map.get("policy_action"),
            "native_floor": native_floor,
            "native_edge": _native_edge_facts(
                native_edge_result,
                event_name,
                artifact_type=runtime_artifact.artifact_type,
            ),
            "current_action_override_present": current_action_override is not None,
            "has_package": package_evaluation is not None,
            "package_policy_action": package_evaluation.policy_action if package_evaluation is not None else None,
            "has_data_flow": bool(data_flow_signals),
            "has_scanner": bool(scanner_evidence),
            "scanner_action": (
                policy_action_for_cisco_signals(scanner_evidence, config=config, harness=policy_harness)
                if scanner_evidence
                else None
            ),
            "has_compound_findings": has_compound_findings,
            "artifact_risk_signals": [signal.explanation for signal in artifact_risk.signals],
            "data_flow_reasons": [signal.plain_reason for signal in data_flow_signals],
            "artifact_risk_summary": artifact_risk.summary,
            "data_flow_summary": _runtime_data_flow_summary(data_flow_signals) if data_flow_signals else None,
            "package_risk_signals": (
                [str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons]
                if package_evaluation is not None
                else []
            ),
            "package_risk_summary": package_evaluation.risk_summary if package_evaluation is not None else None,
            "scanner_risk_signals": scanner_risk_signals,
        },
        guard_home=guard_home,
    )
    record_policy_auto_stops(config, stack["auto_stop_events"])
    policy_action = cast(GuardAction, stack["policy_action"])
    approval_context_policy_action = cast(GuardAction, stack["approval_context_policy_action"])
    approval_context_config_action = cast(GuardAction, stack["approval_context_config_action"])
    current_config_action = cast(GuardAction, stack["current_config_action"])
    trusted_cli_action = cast("GuardAction | None", stack["trusted_cli_action"])
    untrusted_payload_action = cast("GuardAction | None", stack["untrusted_payload_action"])
    requested_policy_action = cast("str | None", stack["requested_policy_action"])
    package_policy_action = cast("GuardAction | None", stack["package_policy_action"])
    data_flow_action = cast("GuardAction | None", stack["data_flow_action"])
    approval_context_data_flow_action = cast("GuardAction | None", stack["approval_context_data_flow_action"])
    scanner_action = cast("GuardAction | None", stack["scanner_action"])
    scanner_raised_to_block = bool(stack["scanner_raised_to_block"])
    risk_signals = stack["risk_signals"]
    risk_summary = cast(str, stack["risk_summary"])
    scanner_evidence_payload = [signal.to_dict() for signal in scanner_evidence]
    if action_envelope is not None and isinstance(action_envelope.command, str):
        scanner_evidence_payload.extend(_embedded_script_evidence(action_envelope.command))
    if workflow_state.approval_record is not None:
        scanner_evidence_payload.append(github_workflow_approval_evidence(workflow_state.approval_record))
    scanner_evidence_payload.extend(cast("list[dict[str, object]]", stack["normalizer_evidence"]))
    if package_execution_context is not None:
        scanner_evidence_payload.append(package_execution_context.to_evidence())
    artifact_decision_signals = artifact_risk.signals_v2
    base_decision_signals = tuple(
        {signal.signal_id: signal for signal in (*artifact_decision_signals, *data_flow_signals)}.values()
    )
    scanner_decision_signals = tuple(cisco_risk_signal_v3_to_v2(signal) for signal in scanner_evidence)
    if scanner_raised_to_block and scanner_decision_signals:
        decision_signals = (*scanner_decision_signals, *base_decision_signals)
    else:
        decision_signals = (*base_decision_signals, *scanner_decision_signals)
    if package_evaluation is not None:
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
    current_policy_action = policy_action
    local_tool_eligibility: LocalToolApprovalEligibility | None = None
    local_grants_allowed = bool(stack["local_grants_allowed"])
    if local_eligibility_required(stack, raw_command=raw_runtime_command):
        local_tool_eligibility = local_tool_approval_eligibility(
            cast("str", raw_runtime_command),
            cwd=runtime_workspace or Path.cwd(),
            home_dir=context.home_dir,
        )
    local_tool_grant = (
        matching_local_tool_grant(
            store=store,
            harness=policy_harness,
            eligibility=local_tool_eligibility,
            current_action=current_policy_action,
        )
        if local_grants_allowed
        else None
    )
    if local_tool_eligibility is not None:
        scanner_evidence_payload.append(local_tool_eligibility.to_evidence())
    tool_grant_applied = local_tool_grant is not None and local_tool_eligibility is not None
    if local_tool_eligibility is not None and tool_grant_applied:
        scanner_evidence_payload.append(
            {
                "source": "trusted_local_tool_grant",
                "applied": True,
                "tool_identity_hash": local_tool_eligibility.tool_identity_hash,
                "capability": local_tool_eligibility.capability,
            }
        )
    policy_action, current_policy_action, approval_context_policy_action = settle_local_grants(
        store=store,
        guard_home=guard_home,
        command=raw_runtime_command,
        cwd=runtime_workspace or Path.cwd(),
        home_dir=context.home_dir,
        current_policy_action=current_policy_action,
        policy_action=policy_action,
        approval_context_policy_action=approval_context_policy_action,
        grant_allowed=local_grants_allowed,
        tool_grant_applied=tool_grant_applied,
        native_floor=cast("GuardAction | None", stack["native_floor"]),
    )
    runtime_artifact_hash = _runtime_hook_approval_context_token(
        artifact=approval_context_artifact,
        content_hash=artifact_content_hash,
        runtime_workspace=runtime_workspace,
        action_envelope=action_envelope,
        config=config,
        current_config_action=approval_context_config_action,
        trusted_cli_action=trusted_cli_action,
        untrusted_payload_action=untrusted_payload_action,
        package_action=package_policy_action,
        data_flow_action=approval_context_data_flow_action,
        scanner_action=scanner_action,
        current_action=approval_context_policy_action,
        risk_classes=artifact_fact_risk_classes(approval_context_facts),
        data_flow_signals=data_flow_signals,
        scanner_evidence=scanner_evidence,
        workflow_approval_record=workflow_state.approval_record,
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
        if native_reuse is None:
            # Resident unreachable: the observed approval is evaluated against
            # the recomputed current action; no saved approval is claimed. The
            # persist plan below is also the resident's, so an outage that
            # lasts until then fails closed (NativeHookDecisionError) and
            # nothing is persisted.
            native_reuse = approval_reuse_authority_unavailable(current_policy_action)
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
    cursor_allowance = (
        _load_cursor_native_shell_allowance(store, payload)
        if policy_harness == "cursor"
        and event_name == "PreToolUse"
        and runtime_artifact.artifact_type == "tool_action_request"
        else None
    )
    cursor_native_approval_hash = _optional_string(cursor_allowance.get("artifact_hash")) if cursor_allowance else None
    policy_lookup, stored_policy_decision, saved_reuse = _runtime_saved_policy_decision(
        store=store,
        harness=policy_harness,
        artifact=runtime_artifact,
        artifact_hash=runtime_artifact_hash,
        workspace=policy_workspace,
        legacy_artifact_hash=artifact_content_hash,
        legacy_workspace=legacy_policy_workspace,
        alias_harness=args.harness,
        alias_artifact=legacy_artifact,
        alias_artifact_hash=artifact_fact_content_hash(alias_facts[0]) if legacy_artifact is not None else None,
        alias_workspace=str(runtime_workspace) if runtime_workspace else None,
        risk_classes=artifact_fact_risk_classes(runtime_facts),
        reuse=None
        if package_evaluation is not None
        else {"current_action": current_policy_action, "cursor_native_token": cursor_native_approval_hash},
    )
    stored_policy_action = (
        _optional_string(stored_policy_decision.get("action")) if stored_policy_decision is not None else None
    )
    remembered_rule_rejection = policy_lookup.get("ignored_local_integrity")
    trust_status = policy_lookup["trust_status"]
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
    reuse_facts = reuse_step_facts(
        store=store,
        artifact=runtime_artifact,
        artifact_hash=runtime_artifact_hash,
        current_action=current_policy_action,
        claim_saved_approval=_claim_saved_approval,
        remembered_rule_rejected=remembered_rule_rejection is not None,
        stored_decision=stored_policy_decision,
        saved_reuse=saved_reuse,
        package_reasons=None if package_evaluation is None else package_evaluation.reasons,
        package_policy_action=None if package_evaluation is None else package_evaluation.policy_action,
        workflow_descriptor=workflow_state.descriptor,
        trusted_override_hash=trusted_request_override_hash,
        claimed_hash=_claimed_saved_allow_hash,
        post_claim_refresh_failed=_post_claim_refresh_failed,
        workflow_capability_required=workflow_state.capability_required,
        workflow_authorization_claimed=workflow_state.authorization_claimed,
        claimed_trusted_request_override=_claimed_trusted_request_override,
        claimed_package_approval_consumed=_claimed_package_approval_consumed,
    )
    try:
        reuse_plan: ReusePlan | None = native_artifact_reuse_step(reuse_facts, guard_home=guard_home)
    except NativeHookDecisionError:
        # Only a package request has a floor: its resolver already claimed what
        # the evaluation's reasons record, so an unreachable resident still
        # revalidates a claimed saved allow and never weakens the action.
        reuse_plan = (
            package_reuse_floor(
                reuse_facts,
                claimed_disposition=(
                    _claimed_saved_package_allow(package_evaluation.reasons) if _claim_saved_approval else None
                ),
            )
            if package_evaluation is not None
            else None
        )
        if reuse_plan is None:
            raise

    reuse_settled = execute_reuse_plan(
        reuse_plan,
        claim=lambda: claim_saved_decision(store, stored_policy_decision, now=_now()),
        revalidate=lambda step: revalidate_claimed_allow(
            runtime_artifact_hash,
            trusted_request_override=step.trusted_request_override,
            package_approval_consumed=step.package_approval_consumed,
            approval_request_id=step.request_id,
        ),
    )
    if not isinstance(reuse_settled, ReuseSettled):
        return reuse_settled
    policy_action = cast(GuardAction, reuse_settled.policy_action)
    approval_reuse_source = reuse_settled.approval_reuse_source
    trusted_request_override_applied = reuse_settled.trusted_request_override_applied
    trusted_request_override_reason = reuse_settled.trusted_request_override_reason
    scanner_evidence_payload.extend(reuse_settled.evidence)
    if reuse_settled.package_risk_refresh and package_evaluation is not None:
        risk_signals = [str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons]
        risk_summary = package_evaluation.risk_summary
    user_override = _optional_string(payload_map.get("user_override"))
    composed = settled_policy_composition(
        guard_home=guard_home,
        current_config_action=current_config_action,
        current_action_override=current_action_override,
        trusted_cli_action=trusted_cli_action,
        untrusted_payload_action=untrusted_payload_action,
        package_policy_action=package_policy_action,
        data_flow_action=data_flow_action,
        scanner_action=scanner_action,
        current_composed_action=current_policy_action,
        saved_policy_action=stored_policy_action,
        approval_reuse_source=approval_reuse_source,
        trusted_request_override=trusted_request_override_applied,
        trusted_request_override_reason=trusted_request_override_reason,
        authoritative_action=policy_action,
        claude_native_approval_observed=claude_native_approval_observed,
        user_override_present=user_override is not None,
    )
    policy_composition = composed.policy_composition
    scanner_evidence_payload.append(composed.evidence)
    if action_envelope is not None:
        action_envelope = action_envelope.with_pre_execution_result(policy_action)
    copy_answer = native_hook_decision_copy(
        composer=native_hook_compose,
        guard_home=guard_home,
        policy_action=policy_action,
        decision_signals=decision_signals,
        package_evaluation=package_evaluation,
        package_policy_action=package_policy_action,
        has_compound_findings=has_compound_findings,
        compound_finding_count=compound_finding_count,
        risk_summary=risk_summary,
        scanner_raised_to_block=scanner_raised_to_block,
        has_scanner_evidence=bool(scanner_evidence),
        scanner_risk_signals=scanner_risk_signals,
        remembered_rule_reason=(
            _remembered_rule_rejection_reason(
                composer=native_hook_compose,
                guard_home=guard_home,
                response_payload={"remembered_rule_rejection": remembered_rule_rejection},
                artifact=runtime_artifact,
            )
            if remembered_rule_rejection is not None
            else None
        ),
    )
    decision_v2_payload = cast("dict[str, object]", copy_answer["decision_v2"])
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
        guard_home=guard_home,
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
        user_override="claude-native-approve" if claude_native_approval_observed else user_override,
        scanner_evidence=scanner_evidence_payload,
        approval_source=composed.approval_source,
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
    if reuse_settled.approval_reuse is not None:
        response_payload["approval_reuse"] = reuse_settled.approval_reuse
    if remembered_rule_rejection is not None:
        response_payload["remembered_rule_rejection"] = remembered_rule_rejection
    if copy_answer["risk_headline"] is not None:
        response_payload["risk_headline"] = copy_answer["risk_headline"]
    if package_evaluation is not None:
        response_payload["supply_chain_evaluation"] = package_evaluation.to_dict()
    if event_name == "PostToolUse":
        _apply_native_edge_envelope_fields(response_payload, native_edge_result)
    elif event_name == "UserPromptSubmit":
        _apply_native_edge_envelope_fields(
            response_payload,
            native_edge_result,
            project_decision=False,
        )
    if (
        _canonical_harness_name(args.harness) == "cursor"
        and not harness_is_recording_only(config, args.harness)
        and event_name == "PreToolUse"
        and runtime_artifact.artifact_type == "tool_action_request"
    ):
        from ..adapters.cursor_hooks import cursor_hook_would_prompt_user

        if cursor_hook_would_prompt_user(
            policy_action=policy_action,
            guard_payload=response_payload,
        ):
            native_reason = _runtime_artifact_native_reason(
                runtime_artifact,
                response_payload,
                composer=native_hook_compose,
                guard_home=context.guard_home,
            )
            _record_cursor_pending_shell_permission(
                store=store,
                guard_home=context.guard_home,
                payload=payload_map,
                reason=native_reason,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
            )
    return NativeArtifactHookState(
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
        native_edge_result=native_edge_result,
        native_edge_receipt=native_edge_receipt,
        native_recording_only=native_recording_only,
    )


__all__ = ["evaluate_native_artifact_hook"]
