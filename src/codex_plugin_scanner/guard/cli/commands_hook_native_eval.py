"""Guard CLI runtime artifact hook evaluation."""

# ruff: noqa: F403, F405

from __future__ import annotations

import os
import shlex
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


from ..action_lattice import coerce_guard_action, guard_action_severity, most_restrictive_guard_action
from ..approval_scope_support import package_request_runtime_workspace_scope
from ..local_supply_chain import (
    _package_evaluation_requires_external_archive_binding,
    package_external_archive_override,
)
from ..models import GuardAction
from ..native_hook_artifact_compose import NativeHookComposeError, native_hook_compose
from ..package_execution_context import PackageExecutionContext, build_package_execution_context
from ..runtime.approval_context import approval_context_tokens_validation_reason
from ..runtime.approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_REAPPROVAL_REQUIRED,
    ApprovalReuseDecision,
    ApprovalReuseMalformedResultError,
    _decision_from_native_payload,
    approval_reuse_authority_unavailable,
    evaluate_approval_reuse,
)
from ..runtime.github_workflow_runtime import resolved_github_workflow_capability_preflight
from ..runtime.signals import GuardRiskSignalV3
from ..shims import package_shim_status
from ..trusted_local_tools import (
    LocalToolApprovalEligibility,
    local_tool_approval_eligibility,
    matching_local_tool_grant,
)
from ._commands_shared import *
from .commands_hook_github_workflow import (
    claimed_approval_request_id,
    github_workflow_approval_evidence,
    prepare_github_workflow_hook_state,
)
from .commands_hook_native_edge_floor import _native_edge_floor_action
from .commands_hook_native_floor import (
    _runtime_package_raw_command,
    native_pre_tool_floor,
    runtime_hook_scanner_setup,
    settle_local_grants,
)
from .commands_hook_native_state import NativeArtifactHookState
from .commands_parser_helpers import *
from .commands_support_hook_state import _load_cursor_native_shell_allowance
from .commands_support_runtime_artifact_policy import _runtime_artifact_has_explicit_permission_allow
from .commands_support_runtime_artifacts import _hook_event_name, _optional_string
from .commands_support_runtime_policy import (
    _remembered_rule_rejection_reason,
    _runtime_artifact_exact_match_context,
    _runtime_hook_approval_context_token,
    _runtime_saved_allow_validation_reason,
    _runtime_stored_policy_decision,
)


def _compose_reuse(
    kind: str,
    fields: dict[str, object],
    *,
    guard_home: Path,
    current_action: GuardAction,
) -> tuple[dict[str, object] | None, ApprovalReuseDecision]:
    """Ask the resident for a saved-approval reuse decision.

    Resident unreachable or malformed: preserve the recomputed action and claim
    no saved approval.
    """

    try:
        answer = native_hook_compose(kind, fields, guard_home=guard_home)
        return answer, _decision_from_native_payload(answer["approval_reuse"])
    except (NativeHookComposeError, ApprovalReuseMalformedResultError, KeyError):
        return None, approval_reuse_authority_unavailable(current_action)


def _cursor_native_saved_approval_hash(
    store: GuardStore,
    payload: Mapping[str, object],
) -> str | None:
    """Return the context token carried by a fresh Cursor native allowance."""

    approved = _load_cursor_native_shell_allowance(store, payload)
    if approved is None:
        return None
    return _optional_string(approved.get("artifact_hash"))


def _runtime_external_archive_command_matches_executable(raw_command: str | None, executable: str) -> bool:
    if (
        raw_command is None
        or os.name == "nt"
        or "`" in raw_command
        or "$(" in raw_command
        or "\n" in raw_command
        or "\r" in raw_command
    ):
        return False
    lexer = shlex.shlex(raw_command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens or tokens[0] != executable:
        return False
    return not any(token and all(character in "();<>|&" for character in token) for token in tokens)


def _runtime_external_archive_has_digest_binding_sink(
    *,
    artifact: GuardArtifact,
    context: HarnessContext,
    raw_command: str | None,
    runtime_workspace: Path | None,
) -> bool:
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    manager = _optional_string(metadata.get("package_manager"))
    executable = _optional_string(metadata.get("package_executable"))
    if manager is None or executable is None:
        return False
    if not any(separator in executable for separator in ("/", "\\")):
        return False
    if not _runtime_external_archive_command_matches_executable(raw_command, executable):
        return False
    try:
        status = package_shim_status(context, path_env=os.environ.get("PATH", ""))
    except (OSError, RuntimeError, ValueError):
        return False
    details = status.get("manager_details")
    if not isinstance(details, list):
        return False
    detail = next(
        (
            item
            for item in details
            if isinstance(item, Mapping) and item.get("manager") == manager and item.get("integrity") == "ok"
        ),
        None,
    )
    if detail is None:
        return False
    shim_path_value = detail.get("shim_path")
    if not isinstance(shim_path_value, str):
        return False
    try:
        shim_path = Path(shim_path_value).resolve(strict=True)
        candidate = Path(executable).expanduser()
        if not candidate.is_absolute():
            candidate = (runtime_workspace or Path.cwd()) / candidate
        resolved_executable = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return resolved_executable == shim_path


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
    action_class = metadata.get("action_class")
    if isinstance(action_class, str):
        lowered = action_class.lower()
        if any(token in lowered for token in ("launch agent", "login item", "launchctl", "cron", "systemd", "launchd")):
            metadata["persistence_writes_launch_agent"] = True


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
    """Scan every distinct proven shell cwd that may resolve a relative target."""

    workspaces: list[Path | None] = []
    if isinstance(raw_shell_cwds, list):
        for value in raw_shell_cwds:
            if not isinstance(value, str) or not value.strip():
                continue
            candidate = Path(value).expanduser().resolve(strict=False)
            if candidate not in workspaces:
                workspaces.append(candidate)
    if not workspaces:
        workspaces.append(runtime_workspace)

    primary_workspace = runtime_workspace or next((item for item in workspaces if item is not None), None)
    approved_scan_roots = tuple(item for item in workspaces if item is not None)
    evidence: list[GuardRiskSignalV3] = []
    for workspace in workspaces:
        for signal in scan_action_for_cisco_evidence(
            action_envelope,
            workspace=workspace or primary_workspace,
            approved_scan_roots=approved_scan_roots,
        ):
            if signal not in evidence:
                evidence.append(signal)
    return tuple(evidence)


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
    if runtime_artifact.artifact_type == "package_request":
        package_evaluation = evaluate_package_request_artifact(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
            external_archive_network_authorized=False,
        )
        if _package_evaluation_requires_external_archive_binding(package_evaluation):
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
    else:
        artifact_content_hash = artifact_hash(approval_context_artifact)
    artifact_id = runtime_artifact.artifact_id
    artifact_name = runtime_artifact.name
    policy_harness = _canonical_harness_name(args.harness)
    cli_action = getattr(args, "policy_action", None)
    _stamp_runtime_posture_metadata(runtime_artifact, data_flow_signals)
    _stamp_runtime_posture_metadata(approval_context_artifact, data_flow_signals)
    current_action_override = config.resolve_action_override(
        policy_harness,
        runtime_artifact.artifact_id,
        runtime_artifact.publisher,
    )
    # ``package_request`` artifacts are decided by the package evaluator, not
    # the generic command floor: the evaluator is the fail-closed semantic
    # authority for installs, and an unproven-command ``review`` floor would
    # force every install to pause regardless of its supply-chain verdict.
    # The same holds for a verified explicit-permission allow: the artifact's
    # own native-evidence-bound evaluation already adjudicated this exact
    # command against the published control layer, so a control-blind floor
    # re-review can only re-raise the cataloged risk the grant accepted.
    native_floor = (
        None
        if runtime_artifact.artifact_type == "package_request"
        or _runtime_artifact_has_explicit_permission_allow(runtime_artifact)
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
    configured_data_flow_action = None
    if data_flow_signals:
        configured_data_flow_action = resolve_risk_action(
            config,
            "data_flow_exfiltration",
            harness=policy_harness,
        )
        from ..protection_posture import apply_posture_confidence, is_high_confidence

        if configured_data_flow_action is not None:
            configured_data_flow_action = apply_posture_confidence(
                posture=config.protection_posture,
                explicit=config.protection_posture_explicit,
                risk_class="data_flow_exfiltration",
                action=configured_data_flow_action,
                confidence=(
                    "strong"
                    if any(is_high_confidence(getattr(signal, "confidence", None)) for signal in data_flow_signals)
                    else None
                ),
            )
    compound_finding_count = artifact_metadata.get("compound_finding_count")
    has_compound_findings = isinstance(compound_finding_count, int) and compound_finding_count > 1
    scanner_risk_signals = [signal.plain_language_summary for signal in scanner_evidence]
    stack = native_hook_compose(
        "policy_stack",
        {
            "config_action": _runtime_artifact_policy_action(config, runtime_artifact, args.harness),
            "approval_context_config_action": _runtime_artifact_policy_action(
                config, approval_context_artifact, policy_harness
            ),
            "cli_action": cli_action,
            "payload_action_present": "policy_action" in payload_map,
            "payload_action": payload_map.get("policy_action"),
            "native_floor": native_floor,
            "edge_floor": _native_edge_floor_action(
                native_edge_result,
                event_name,
                artifact_default_action=runtime_artifact.metadata.get("guard_default_action"),
                artifact_type=runtime_artifact.artifact_type,
            ),
            "current_action_override_present": current_action_override is not None,
            "has_package": package_evaluation is not None,
            "package_policy_action": package_evaluation.policy_action if package_evaluation is not None else None,
            "has_data_flow": bool(data_flow_signals),
            "data_flow_configured_action": configured_data_flow_action,
            "has_scanner": bool(scanner_evidence),
            "scanner_action": (
                policy_action_for_cisco_signals(scanner_evidence, config=config, harness=policy_harness)
                if scanner_evidence
                else None
            ),
            "has_compound_findings": has_compound_findings,
            "artifact_risk_signals": list(artifact_risk_signals(runtime_artifact)),
            "data_flow_reasons": [signal.plain_reason for signal in data_flow_signals],
            "artifact_risk_summary": artifact_risk_summary(runtime_artifact),
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
    artifact_decision_signals = artifact_risk_signals_v2(runtime_artifact)
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
    raw_runtime_command = _runtime_package_raw_command(payload_map, action_envelope)
    local_grants_allowed = bool(stack["local_grants_allowed"])
    if (
        event_name == "PreToolUse"
        and runtime_artifact.artifact_type in {"tool_action_request", "package_request"}
        and raw_runtime_command is not None
    ):
        local_tool_eligibility = local_tool_approval_eligibility(
            raw_runtime_command,
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
            # Resident unreachable: the observed approval is recorded against
            # the recomputed current action; no saved approval is claimed.
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
        package_approval_claim_disposition: str | None = None
        for reason in package_evaluation.reasons:
            if reason.get("code") in {"saved_package_approval", "saved_package_block"}:
                package_reuse_applied = True
                approval_reuse_source = "saved_package_policy"
            if reason.get("code") == "saved_package_approval":
                package_saved_allow_applied = True
                raw_claim_disposition = reason.get("approval_claim_disposition")
                if raw_claim_disposition in {"consumed", "retained"}:
                    package_approval_claim_disposition = str(raw_claim_disposition)
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
                package_approval_consumed=package_approval_claim_disposition == "consumed",
            )
        policy_action = (
            coerce_guard_action(package_evaluation.policy_action) or current_policy_action
            if package_reuse_applied
            else current_policy_action
        )
        if stored_policy_action == "block":
            block_answer, approval_reuse = _compose_reuse(
                "saved_block_reuse",
                {
                    "current_action": current_policy_action,
                    "policy_action": policy_action,
                    "stored_artifact_hash": (
                        stored_policy_decision.get("artifact_hash") if stored_policy_decision is not None else None
                    ),
                },
                guard_home=guard_home,
                current_action=current_policy_action,
            )
            if block_answer is not None:
                policy_action = cast(GuardAction, block_answer["policy_action"])
                approval_reuse_source = approval_reuse_source or "saved_policy_decision"
            else:
                # Resident unreachable: hold the stored block and never end weaker
                # than the recomputed action; no saved decision is claimed as the source.
                policy_action = most_restrictive_guard_action(policy_action, approval_reuse.action, "block")
            if not package_reuse_applied:
                scanner_evidence_payload.append(
                    {
                        "source": "approval_reuse",
                        "input_source": approval_reuse_source or "saved_policy_decision",
                        **approval_reuse.to_evidence(),
                    }
                )
        if policy_action != current_policy_action:
            risk_signals = [str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons]
            risk_summary = package_evaluation.risk_summary
    else:
        stored_validation_reason = (
            _runtime_saved_allow_validation_reason(
                stored_policy_decision,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
            )
            if stored_policy_decision is not None and policy_lookup.get("ignored_local_integrity") is None
            else None
        )
        cursor_validation_reason = (
            approval_context_tokens_validation_reason(cursor_native_approval_hash, runtime_artifact_hash)
            if cursor_native_approval_hash is not None
            else None
        )
        diagnostic_reason: str | None = None
        diagnostic_stored_hash: object | None = None
        if (
            stored_policy_decision is None
            and cursor_native_approval_hash is None
            and policy_lookup.get("ignored_local_integrity") is None
        ):
            diagnostic_reason, diagnostic_stored_hash = store.approval_reuse_diagnostic(
                policy_harness,
                artifact_id,
                runtime_artifact_hash,
                policy_workspace,
                runtime_artifact.publisher,
                _now(),
            )
        saved_fields: dict[str, object] = {
            "current_action": current_policy_action,
            "stored_present": stored_policy_decision is not None,
            "stored_action": stored_policy_action,
            "stored_artifact_hash": (
                stored_policy_decision.get("artifact_hash") if stored_policy_decision is not None else None
            ),
            "integrity_failure": policy_lookup.get("ignored_local_integrity") is not None,
            "stored_validation_reason": stored_validation_reason,
            "cursor_native_present": cursor_native_approval_hash is not None,
            "cursor_validation_reason": cursor_validation_reason,
            "diagnostic_reason": diagnostic_reason,
            "diagnostic_stored_hash": diagnostic_stored_hash,
        }
        saved_answer, approval_reuse = _compose_reuse(
            "saved_reuse",
            saved_fields,
            guard_home=guard_home,
            current_action=current_policy_action,
        )
        if saved_answer is not None:
            approval_reuse_source = cast("str | None", saved_answer["approval_reuse_source"])
        workflow_request_id = (
            claimed_approval_request_id(stored_policy_decision) if stored_policy_decision is not None else None
        )
        workflow_reapproval_pending = (
            approval_reuse.reason_code == APPROVAL_REUSE_REAPPROVAL_REQUIRED
            and workflow_state.descriptor is not None
            and workflow_request_id is not None
            and resolved_github_workflow_capability_preflight(
                store,
                workflow_request_id,
                workflow_state.descriptor,
            )
        )
        if (
            (approval_reuse.should_claim or workflow_reapproval_pending)
            and stored_policy_decision is not None
            and _claim_saved_approval
        ):
            if not store.claim_approval_reuse_decision(stored_policy_decision, now=_now()):
                _, approval_reuse = _compose_reuse(
                    "saved_reuse",
                    {
                        **saved_fields,
                        "stored_present": True,
                        "integrity_failure": False,
                        "stored_validation_reason": APPROVAL_REUSE_CLAIM_FAILED,
                    },
                    guard_home=guard_home,
                    current_action=current_policy_action,
                )
            else:
                return revalidate_claimed_allow(
                    runtime_artifact_hash,
                    trusted_request_override=False,
                    approval_request_id=workflow_request_id,
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
        override_fields: dict[str, object] = {
            "token_validation_reason": approval_context_tokens_validation_reason(
                trusted_request_override_hash,
                runtime_artifact_hash,
            ),
            "policy_action": policy_action,
            "remembered_rule_rejected": remembered_rule_rejection is not None,
            "prior_reuse_reason_code": approval_reuse.reason_code if approval_reuse is not None else None,
            "stored_present": stored_policy_decision is not None,
            "stored_action": stored_policy_decision.get("action") if stored_policy_decision is not None else None,
            "stored_source": stored_policy_decision.get("source") if stored_policy_decision is not None else None,
            "stored_validation_reason": (
                _runtime_saved_allow_validation_reason(
                    stored_policy_decision,
                    artifact=runtime_artifact,
                    artifact_hash=runtime_artifact_hash,
                )
                if stored_policy_decision is not None
                else None
            ),
            "claim_succeeded": None,
        }
        override_answer = native_hook_compose("trusted_override", override_fields, guard_home=guard_home)
        if override_answer["claim_required"] and stored_policy_decision is not None:
            if store.claim_approval_reuse_decision(stored_policy_decision, now=_now()):
                return revalidate_claimed_allow(
                    runtime_artifact_hash,
                    trusted_request_override=True,
                    approval_request_id=claimed_approval_request_id(stored_policy_decision),
                )
            override_answer = native_hook_compose(
                "trusted_override",
                {**override_fields, "claim_succeeded": False},
                guard_home=guard_home,
            )
        trusted_request_override_reason = cast("str | None", override_answer["reason_code"])
        scanner_evidence_payload.append(cast("dict[str, object]", override_answer["evidence"]))
    if _claimed_saved_allow_hash is not None:
        claim_answer = native_hook_compose(
            "claimed_reuse",
            {
                "claimed_hash": _claimed_saved_allow_hash,
                "token_validation_reason": approval_context_tokens_validation_reason(
                    _claimed_saved_allow_hash,
                    runtime_artifact_hash,
                ),
                "post_claim_refresh_failed": _post_claim_refresh_failed,
                "remembered_rule_rejected": remembered_rule_rejection is not None,
                "prior_reuse": (
                    {
                        "action": approval_reuse.action,
                        "saved_action": approval_reuse.saved_action,
                        "reason_code": approval_reuse.reason_code,
                    }
                    if approval_reuse is not None
                    else None
                ),
                "package_reuse_saved_action": (
                    package_approval_reuse_evidence.get("saved_action")
                    if package_approval_reuse_evidence is not None
                    else None
                ),
                "workflow_capability_required": workflow_state.capability_required,
                "workflow_authorization_claimed": workflow_state.authorization_claimed,
                "policy_action": policy_action,
                "current_policy_action": current_policy_action,
                "claimed_trusted_request_override": _claimed_trusted_request_override,
                "claimed_package_approval_consumed": _claimed_package_approval_consumed,
            },
            guard_home=guard_home,
        )
        approval_reuse = _decision_from_native_payload(claim_answer["approval_reuse"])
        policy_action = cast(GuardAction, claim_answer["policy_action"])
        approval_reuse_source = cast("str | None", claim_answer["approval_reuse_source"])
        trusted_request_override_applied = bool(claim_answer["trusted_request_override_applied"])
        trusted_request_override_reason = cast("str | None", claim_answer["trusted_request_override_reason"])
        scanner_evidence_payload.append(cast("dict[str, object]", claim_answer["evidence"]))
    policy_composition = {
        "current_config_action": current_config_action,
        "current_action_override": current_action_override,
        "trusted_cli_override": trusted_cli_action,
        "untrusted_hook_payload_hint": untrusted_payload_action,
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
    copy_answer = native_hook_compose(
        "decision_copy",
        {
            "policy_action": policy_action,
            "package": (
                {
                    "reason_codes": [
                        _optional_string(reason.get("code")) or ""
                        for reason in package_evaluation.reasons
                        if isinstance(reason, Mapping)
                    ],
                    "user_title": package_evaluation.user_copy.title,
                    "user_summary": package_evaluation.user_copy.summary,
                    "user_harness_message": package_evaluation.user_copy.harness_message,
                }
                if package_evaluation is not None
                else None
            ),
            "package_policy_action": package_policy_action,
            "has_compound_findings": has_compound_findings,
            "compound_finding_count": compound_finding_count if has_compound_findings else None,
            "risk_summary": risk_summary,
            "scanner_raised_to_block": scanner_raised_to_block,
            "has_scanner_evidence": bool(scanner_evidence),
            "scanner_primary_signal": scanner_risk_signals[0] if scanner_risk_signals else None,
            "base_user_body": decision_v2_payload.get("user_body"),
            "base_harness_message": decision_v2_payload.get("harness_message"),
            "base_dashboard_primary_detail": decision_v2_payload.get("dashboard_primary_detail"),
            "remembered_rule_reason": (
                _remembered_rule_rejection_reason(
                    response_payload={"remembered_rule_rejection": remembered_rule_rejection},
                    artifact=runtime_artifact,
                )
                if remembered_rule_rejection is not None
                else None
            ),
        },
        guard_home=guard_home,
    )
    decision_v2_payload.update(cast("dict[str, object]", copy_answer["decision_overrides"]))
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
