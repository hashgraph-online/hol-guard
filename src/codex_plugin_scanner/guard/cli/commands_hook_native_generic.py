"""Guard CLI generic hook fallback flow."""

# ruff: noqa: E402, F403, F405

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from .commands_support import *


def _coalesce_string(*values: object | None) -> str:
    """Return a display-safe fallback while CLI helper modules are importing."""

    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown-artifact"


def _artifact_id_from_event(harness: str, payload: dict[str, object], guard_home: Path | None) -> str:
    """Name the runtime artifact the event belongs to; the resident owns the rule.

    The name selects the configured action override for the event, so Python
    never derives it. A resident that cannot answer leaves the caller with no
    artifact identity, which the pipeline turns into the harness outage
    response rather than a guessed name that no override would match.
    """

    from ..native_hook_decision import NativeHookDecisionError
    from ..native_hook_render import native_artifact_id_from_event

    artifact_id = native_artifact_id_from_event(
        harness, _canonical_harness_name(harness), payload, guard_home=guard_home
    )
    if artifact_id is None:
        raise NativeHookDecisionError("native_artifact_id_unavailable")
    return artifact_id


def _embedded_script_evidence(command_text: str | None) -> list[dict[str, object]]:
    """Hash-addressed audit entries for heredoc script bodies (lazy import)."""

    from ..runtime.embedded_script_evidence import embedded_script_evidence_entries

    return embedded_script_evidence_entries(command_text)


def _embedded_script_remediation(command_text: str | None) -> str | None:
    """Guidance for agents whose command carries an inline script body."""

    from ..runtime.embedded_script_evidence import (
        EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE,
        command_has_embedded_script,
    )

    if command_has_embedded_script(command_text):
        return EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE
    return None


def _optional_string(value: object | None) -> str | None:
    """Return a non-empty string value without depending on aggregator imports."""

    return value.strip() if isinstance(value, str) and value.strip() else None


def _string_list(value: object | None) -> list[str]:
    """Normalize a payload list without depending on aggregator imports."""

    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _observed_action_detail(
    command_text: str | None,
    *,
    action_envelope: GuardActionEnvelope | None,
    home_dir: Path | None,
) -> str | None:
    command_detail = _command_detail(command_text, home_dir=home_dir)
    if command_detail is not None or action_envelope is None:
        return command_detail
    tool_name = action_envelope.tool_name
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    target_summary = " ".join(action_envelope.target_paths)
    detail = f"{tool_name.strip()} {target_summary}" if target_summary else tool_name.strip()
    return _command_detail(detail, home_dir=home_dir)


if TYPE_CHECKING:
    from ._commands_shared import _hook_command_text, _now
    from .commands_support_interaction import _record_harness_usage_for_hook
    from .commands_support_prompts import (
        _copilot_hook_reason,
        _decision_v2_harness_message,
        _emit_copilot_hook_response,
    )
    from .commands_support_runtime_policy import _localize_pending_approval_copy
    from .commands_support_runtime_resolution import _canonical_harness_name


from ..harness_posture import harness_is_recording_only
from ..local_cli_hook import local_cli_grant_action
from ..models import GuardAction, GuardArtifact, HarnessDetection
from ..native_approval_proof import claimed_row_is_still_the_authority
from ..native_hook_approval_context import generic_hook_approval_context_inputs, native_hook_approval_context_token
from ..native_hook_decision import native_compose_current, native_finalize, native_post_claim_decision
from ..retry_lineage import capture_retry_lineage
from ..runtime.actions import _command_detail
from ..runtime.approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    ApprovalReuseDecision,
    ApprovalReuseValidationFailure,
    _decision_from_native_payload,
    approval_reuse_authority_unavailable,
    evaluate_approval_reuse,
    with_saved_artifact_hash_provenance,
)
from ..runtime.command_activity_contract import ActivityApprovalReuseStatus
from ..trusted_local_tools import (
    LocalToolApprovalEligibility,
    local_tool_approval_eligibility,
    matching_local_tool_grant,
)
from ._commands_shared import *
from .commands_hook_native_generic_facts import composition_inputs, hook_classifiers
from .commands_hook_native_generic_render import directive_exit_code, render_generic_hook
from .commands_parser_helpers import *
from .commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
    record_pre_hook_command_activity_best_effort,
)
from .commands_support_observe_queue import queue_observe_mode_request
from .commands_support_runtime_policy import _runtime_hook_effective_policy_config

# Bump when generic-hook classification or action-composition semantics change.
_GENERIC_HOOK_EVALUATOR_POLICY_VERSION = "generic-hook-evaluation-v3"


def _generic_hook_approval_context_inputs(
    *,
    action_envelope: GuardActionEnvelope | None,
    artifact_id: str,
    artifact_name: str,
    config: GuardConfig,
    current_action: str,
    daemon_status: str | None,
    fail_mode: str | None,
    harness: str,
    home_dir: Path | None,
    payload: Mapping[str, object],
    publisher: str | None,
    runtime_workspace: Path | None,
    token: Mapping[str, object],
    tool_command: str | None,
) -> dict[str, object]:
    """Inputs that bind a generic fallback approval to its exact recomputed context.

    ``token`` carries the composition values the resident decided.
    """

    return generic_hook_approval_context_inputs(
        action_envelope=action_envelope,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        canonical_harness=_canonical_harness_name(harness),
        harness=harness,
        publisher=publisher,
        home_dir=home_dir,
        runtime_workspace=runtime_workspace,
        payload=payload,
        tool_command=tool_command,
        config=config,
        policy_config=_runtime_hook_effective_policy_config(config),
        evaluator_policy_version=_GENERIC_HOOK_EVALUATOR_POLICY_VERSION,
        composition={
            "current_action": current_action,
            "current_config_action": token["current_config_action"],
            "daemon_hint_disposition": token["daemon_hint_disposition"],
            "daemon_hint_reason_code": token["daemon_hint_reason_code"],
            "daemon_status": daemon_status,
            "fail_mode": fail_mode,
            "trusted_cli_action": token["trusted_cli_action"],
            "untrusted_payload_action": token["untrusted_payload_action"],
            "untrusted_payload_action_disposition": token["untrusted_payload_action_disposition"],
            "untrusted_payload_action_reason": token["untrusted_payload_action_reason"],
        },
        current_action=current_action,
    )


def _generic_hook_saved_decision(
    *,
    approval_context_inputs: dict[str, object],
    artifact_id: str,
    artifact_name: str,
    current_action: GuardAction,
    harness: str,
    legacy_artifact_hash: str | None,
    payload: Mapping[str, object],
    publisher: str | None,
    runtime_workspace: Path | None,
    store: GuardStore,
    tool_command: str | None,
) -> tuple[str, dict[str, object] | None, dict[str, object] | None, ApprovalReuseDecision, bool]:
    """Build the approval context token, peek saved evidence and compose its reuse verdict in one resident call.

    Legacy blocks are retained without trusting legacy allows. Returns the
    current approval context token, the saved decision, the ignored
    local-integrity evidence, the reuse verdict and whether saved evidence was
    present.
    """

    workspace = str(runtime_workspace) if runtime_workspace is not None else None
    from ..store import runtime_tool_action_exact_match_context, runtime_tool_action_policy_artifact_id

    memory_command = _coalesce_string(tool_command, payload.get("command"), payload.get("tool_name"))
    runtime_exact_match_context = runtime_tool_action_exact_match_context(
        config_path=workspace,
        source_scope=_coalesce_string(payload.get("source_scope"), "project"),
        raw_command_text=memory_command,
        permission_mode=_optional_string(payload.get("permission_mode"))
        or _optional_string(payload.get("permissionMode")),
    )
    # ``None`` is the current token; a legacy hash equal to it is dropped by the resident.
    probes: list[tuple[str, str | None]] = [(artifact_id, None)]
    policy_artifact_id = runtime_tool_action_policy_artifact_id(artifact_id)
    if policy_artifact_id is not None and policy_artifact_id != artifact_id:
        probes.append((policy_artifact_id, None))
    if legacy_artifact_hash is not None:
        probes.append((artifact_id, legacy_artifact_hash))
    saved = store.peek_saved_decision_groups(
        harness,
        probes,
        workspace=workspace,
        publisher=publisher,
        runtime_exact_match_context=runtime_exact_match_context,
        memory_command=memory_command,
        memory_artifact_type=_coalesce_string(payload.get("artifact_type"), payload.get("tool_type")),
        memory_artifact_name=artifact_name,
        current_action=current_action,
        approval_context_inputs=approval_context_inputs,
    )
    if saved is None:
        # No saved authority to read: a near match can still explain the miss.
        # Naming the recomputed action lets the resident compose what the miss
        # means in the same call, so the miss path costs one round trip rather
        # than three and nothing here has to name a saved action for a row the
        # resident just rejected.
        artifact_hash = native_hook_approval_context_token("generic_hook_approval_context", approval_context_inputs)
        diagnosed_reason, diagnosed_stored_hash, diagnosed_reuse = store.approval_reuse_miss(
            harness, artifact_id, artifact_hash, workspace, publisher, current_action=current_action
        )
        saved_present = diagnosed_reason is not None
        if diagnosed_reuse is not None:
            return artifact_hash, None, None, _decision_from_native_payload(diagnosed_reuse), saved_present
        # The resident composed nothing: either there were no saved rows to
        # diagnose, or it could not answer at all. Ask the sole authority for
        # the composition; an unreachable one preserves the recomputed action
        # unchanged and claims no saved decision.
        verdict = evaluate_approval_reuse(
            current_action,
            "allow" if saved_present else None,
            saved_decision_present=saved_present,
            validation_reason=cast(ApprovalReuseValidationFailure | None, diagnosed_reason),
        )
        reuse = with_saved_artifact_hash_provenance(
            verdict if verdict is not None else approval_reuse_authority_unavailable(current_action),
            diagnosed_stored_hash,
        )
        return artifact_hash, None, None, reuse, saved_present
    current_token = saved.get("current_token")
    if not isinstance(current_token, str):
        raise ValueError("native_policy_decision_lookup_invalid")
    reuse = with_saved_artifact_hash_provenance(
        _decision_from_native_payload(saved.get("reuse")), saved.get("saved_artifact_hash")
    )
    return (
        current_token,
        saved.get("decision"),
        saved.get("ignored_local_integrity"),
        reuse,
        saved.get("saved_present") is True,
    )


def _generic_hook_changed_capabilities(payload_map: Mapping[str, object]) -> list[str]:
    changed_capabilities = _string_list(payload_map.get("changed_capabilities"))
    if not changed_capabilities and isinstance(payload_map.get("event"), str):
        changed_capabilities = [str(payload_map["event"])]
    return changed_capabilities


def _generic_hook_tool_artifact(
    *,
    action_class: str,
    artifact_id: str,
    artifact_name: str,
    command: str | None,
    config_path: str,
    harness: str,
    request_summary: str,
) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name=artifact_name,
        harness=harness,
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=config_path,
        command=command,
        metadata={"action_class": action_class, "request_summary": request_summary},
    )


def _generic_hook_detection(harness: str, config_path: str, artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(config_path,),
        artifacts=(artifact,),
    )


def _generic_hook_evaluation_artifact(
    *,
    action_envelope: GuardActionEnvelope | None,
    artifact: GuardArtifact,
    artifact_hash: str,
    artifact_id: str,
    artifact_name: str,
    changed_fields: list[str],
    command: str | None,
    policy_action: str,
    risk_summary: str,
    scanner_evidence: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_hash": artifact_hash,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "policy_action": policy_action,
        "changed_fields": changed_fields,
        "launch_target": command,
        "risk_summary": risk_summary,
        "action_envelope_json": (
            action_envelope.with_pre_execution_result(None).to_dict() if action_envelope is not None else None
        ),
    }
    if scanner_evidence is not None:
        entry["scanner_evidence"] = scanner_evidence
    return entry


def _queue_generic_hook_approval(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    artifact_hash: str,
    artifact_id: str,
    artifact_name: str,
    changed_capabilities: list[str],
    command_text: str | None,
    config: GuardConfig,
    hook_event_name: str,
    home_dir: Path | None,
    local_tool_eligibility: LocalToolApprovalEligibility | None,
    payload_map: dict[str, object],
    policy_action: str,
    runtime_workspace: Path | None,
    store: GuardStore,
) -> None:
    approval_center_url = schedule_guard_daemon_ensure(store.guard_home, home_dir=home_dir)
    redacted_command_text = _command_detail(command_text, home_dir=home_dir)
    config_path = str(runtime_workspace) if runtime_workspace is not None else ""
    artifact = _generic_hook_tool_artifact(
        action_class="unmatched tool action",
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        command=redacted_command_text,
        config_path=config_path,
        harness=args.harness,
        request_summary="Guard requires approval because no command rule matched this tool action.",
    )
    queued_at = _now()
    hook_metadata: dict[str, object] = {
        "tool_name": str(payload_map.get("tool_name", "")),
        "hook_event_name": hook_event_name,
        "workspace": str(runtime_workspace) if runtime_workspace else None,
    }
    retry_lineage = capture_retry_lineage(
        payload_map,
        harness=str(args.harness),
        workspace=str(runtime_workspace) if runtime_workspace else None,
        action_envelope=action_envelope.to_dict() if action_envelope is not None else None,
    )
    if retry_lineage is not None:
        hook_metadata["retry_lineage"] = retry_lineage
    queued = queue_blocked_approvals(
        detection=_generic_hook_detection(args.harness, config_path, artifact),
        evaluation={
            "artifacts": [
                _generic_hook_evaluation_artifact(
                    action_envelope=action_envelope,
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    changed_fields=changed_capabilities or ["tool_action"],
                    command=redacted_command_text,
                    policy_action=policy_action,
                    risk_summary="No command rule matched this tool action.",
                    scanner_evidence=[local_tool_eligibility.to_evidence()]
                    if local_tool_eligibility is not None
                    else [],
                )
            ]
        },
        store=store,
        approval_center_url=approval_center_url,
        now=queued_at,
        redaction_level=config.receipt_redaction_level,
        continuation_operation={
            "created_at": queued_at,
            "harness": args.harness,
            "metadata": hook_metadata,
            "status": "waiting_on_approval",
            "updated_at": queued_at,
        },
    )
    payload_map["approval_requests"] = queued
    payload_map["approval_center_url"] = approval_center_url


def _record_generic_hook_silent_review(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    artifact_hash: str,
    artifact_id: str,
    artifact_name: str,
    changed_capabilities: list[str],
    command_text: str | None,
    config: GuardConfig,
    home_dir: Path | None,
    review: Mapping[str, str],
    runtime_workspace: Path | None,
    store: GuardStore,
) -> None:
    from ..approvals import record_unprompted_review

    redacted_command_text = _command_detail(command_text, home_dir=home_dir)
    config_path = str(runtime_workspace) if runtime_workspace is not None else ""
    artifact = _generic_hook_tool_artifact(
        action_class="unmatched tool action",
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        command=redacted_command_text,
        config_path=config_path,
        harness=args.harness,
        request_summary="Guard recorded a blocked review without prompting.",
    )
    record_unprompted_review(
        detection=_generic_hook_detection(args.harness, config_path, artifact),
        evaluation={
            "artifacts": [
                _generic_hook_evaluation_artifact(
                    action_envelope=action_envelope,
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    changed_fields=changed_capabilities or ["tool_action"],
                    command=redacted_command_text,
                    policy_action=review["action"],
                    risk_summary=review["reason"],
                )
            ]
        },
        store=store,
        redaction_level=config.receipt_redaction_level,
    )


def _generic_hook_composition_inputs(
    args: argparse.Namespace,
    *,
    config: GuardConfig,
    configured_narrow_override: object,
    configured_override: object,
    command_text: str | None,
    home_dir: Path | None,
    native_edge_result: Mapping[str, object] | None,
    payload_map: Mapping[str, object],
    runtime_artifact_checked: bool,
    runtime_workspace: Path | None,
) -> dict[str, object]:
    return composition_inputs(
        cli_action=getattr(args, "policy_action", None),
        canonical_harness=_canonical_harness_name(args.harness),
        configured_action=configured_override if configured_override is not None else config.default_action,
        harness=args.harness,
        has_command_text=isinstance(command_text, str) and bool(command_text.strip()),
        has_configured_override=configured_override is not None,
        has_narrow_override=configured_narrow_override is not None,
        home_dir=home_dir,
        native_edge_result=native_edge_result,
        payload=payload_map,
        runtime_artifact_checked=runtime_artifact_checked,
        runtime_workspace=runtime_workspace,
    )


def run_native_generic_payload(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    home_dir: Path | None = None,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    post_claim_revalidator: Callable[[str, Mapping[str, object]], int | None] | None = None,
    runtime_artifact_checked: bool = False,
    _claimed_saved_allow_hash: str | None = None,
    _claimed_saved_approval: Mapping[str, object] | None = None,
    _claim_saved_approval: bool = True,
    _post_claim_refresh_failed: bool = False,
    native_edge_result: Mapping[str, object] | None = None,
    native_edge_receipt: Mapping[str, object] | None = None,
) -> int:
    """Gather facts, ask the resident to decide, execute IO, render the directive.

    Raises ``NativeHookDecisionError`` when the resident cannot decide; the
    pipeline converts that into the harness outage response.
    """

    from ..blocked_request_mode import asks_for_approval, safe_alternative_reason
    from ..native_context import bind_context_digest_home

    bind_context_digest_home(getattr(store, "guard_home", None))
    payload_map = dict(payload)
    payload_map.pop("blocked_request_guidance", None)
    blocked_request_guidance: str | None = None
    # Only ask the resident to name the artifact when the event carried no
    # name of its own; the round trip is on the hook hot path.
    artifact_id = _optional_string(getattr(args, "artifact_id", None)) or _optional_string(
        payload_map.get("artifact_id")
    )
    if artifact_id is None:
        artifact_id = _artifact_id_from_event(args.harness, payload_map, store.guard_home)
    artifact_name = _coalesce_string(
        getattr(args, "artifact_name", None),
        payload_map.get("artifact_name"),
        payload_map.get("tool_name"),
        artifact_id,
    )
    publisher = _optional_string(payload_map.get("publisher"))
    configured_override = config.resolve_action_override(args.harness, artifact_id, publisher)
    configured_narrow_override = config.resolve_artifact_or_publisher_action_override(artifact_id, publisher)
    command_text = _hook_command_text(payload_map)
    has_command_text = isinstance(command_text, str) and bool(command_text.strip())
    command_str = command_text or ""
    cwd = runtime_workspace or Path.cwd()
    inputs = _generic_hook_composition_inputs(
        args,
        config=config,
        configured_narrow_override=configured_narrow_override,
        configured_override=configured_override,
        command_text=command_text,
        home_dir=home_dir,
        native_edge_result=native_edge_result,
        payload_map=payload_map,
        runtime_artifact_checked=runtime_artifact_checked,
        runtime_workspace=runtime_workspace,
    )
    classifiers = hook_classifiers(
        guard_home=store.guard_home,
        home_dir=home_dir,
        payload=payload_map,
        runtime_workspace=runtime_workspace,
    )
    composition, facts = native_compose_current(inputs, classifiers, guard_home=store.guard_home)
    inputs["facts"] = facts
    if composition["permission_decision_reason"] is not None:
        payload_map["permission_decision_reason"] = composition["permission_decision_reason"]
    local_tool_eligibility: LocalToolApprovalEligibility | None = None
    if composition["tool_eligibility_needed"]:
        local_tool_eligibility = local_tool_approval_eligibility(command_str, cwd=cwd, home_dir=home_dir)
    grant_lookups_allowed = composition["grant_lookups_allowed"]
    local_tool_grant = (
        matching_local_tool_grant(
            store=store,
            harness=args.harness,
            eligibility=local_tool_eligibility,
            current_action=composition["composed_action"],
        )
        if grant_lookups_allowed
        else None
    )
    tool_grant_applied = local_tool_grant is not None and local_tool_eligibility is not None
    current_policy_action = composition["action_with_tool_grant" if tool_grant_applied else "action_without_tool_grant"]
    if has_command_text:
        current_policy_action = local_cli_grant_action(
            store=store,
            command=command_str,
            cwd=cwd,
            home_dir=home_dir,
            current_action=current_policy_action,
            grant_allowed=grant_lookups_allowed,
        )
    tool_command = command_text_from_tool_payload(
        payload_map.get("tool_name"),
        payload_map.get("tool_input", payload_map.get("arguments")),
    )
    approval_context_inputs = _generic_hook_approval_context_inputs(
        action_envelope=action_envelope,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        config=config,
        current_action=current_policy_action,
        daemon_status=_optional_string(payload_map.get("daemon_status")),
        fail_mode=_optional_string(payload_map.get("fail_mode")),
        harness=args.harness,
        home_dir=home_dir,
        payload=payload_map,
        publisher=publisher,
        runtime_workspace=runtime_workspace,
        token=composition["token"],
        tool_command=tool_command,
    )
    (
        runtime_artifact_hash,
        stored_policy_decision,
        ignored_integrity,
        approval_reuse,
        saved_decision_present,
    ) = _generic_hook_saved_decision(
        approval_context_inputs=approval_context_inputs,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        current_action=current_policy_action,
        harness=args.harness,
        legacy_artifact_hash=_optional_string(payload_map.get("artifact_hash")),
        payload=payload_map,
        publisher=publisher,
        runtime_workspace=runtime_workspace,
        store=store,
        tool_command=tool_command,
    )
    if approval_reuse.should_claim and stored_policy_decision is not None and _claim_saved_approval:
        if not store.claim_approval_reuse_decision(stored_policy_decision):
            claim_failed_reuse = evaluate_approval_reuse(
                current_policy_action,
                stored_policy_decision.get("action"),
                saved_decision_present=True,
                validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
            )
            approval_reuse = with_saved_artifact_hash_provenance(
                claim_failed_reuse
                if claim_failed_reuse is not None
                else approval_reuse_authority_unavailable(current_policy_action),
                stored_policy_decision.get("artifact_hash"),
            )
        else:
            # A successful one-shot claim is not itself the launch authority.
            # Rebuild the complete current context after the atomic write so a
            # policy/configuration mutation performed by the claiming store (or
            # racing with it) cannot inherit the stale pre-claim allow.
            if post_claim_revalidator is not None:
                try:
                    refreshed_result = post_claim_revalidator(runtime_artifact_hash, stored_policy_decision)
                except Exception:
                    refreshed_result = None
                if refreshed_result is not None:
                    return refreshed_result
                _post_claim_refresh_failed = True
            return run_native_generic_payload(
                args,
                action_envelope=action_envelope,
                config=config,
                home_dir=home_dir,
                output_stream=output_stream,
                payload=payload,
                runtime_workspace=runtime_workspace,
                store=store,
                post_claim_revalidator=None,
                runtime_artifact_checked=runtime_artifact_checked,
                _claimed_saved_allow_hash=runtime_artifact_hash,
                _claimed_saved_approval=stored_policy_decision,
                _claim_saved_approval=False,
                _post_claim_refresh_failed=_post_claim_refresh_failed,
            )
    if _claimed_saved_allow_hash is not None:
        claimed = _claimed_saved_approval or {}
        # Native lookup re-authenticates the row: the resident holds the claimed
        # row beside the freshly selected one and says whether it is still the
        # same authority, disposition included. An unreachable resident answers
        # nothing, which this reads as an invalid row rather than a grant.
        claim_row_invalid = not claimed_row_is_still_the_authority(
            claimed_decision=_claimed_saved_approval,
            current_decision=stored_policy_decision,
            guard_home=store.guard_home,
        )
        # Naming the claimed approval's own context token lets the resident
        # compare it with the recomputed one and compose what the re-evaluated
        # claim means for reuse in the same request.  The claim was already
        # consumed, so its saved authority is an allow by construction and
        # nothing here has to name one; an unreachable resident raises rather
        # than letting this path invent a grant.
        _, _, post_claim_reuse = native_post_claim_decision(
            {
                "current_policy_action": current_policy_action,
                "reuse_action": approval_reuse.action,
                "reuse_saved_action": approval_reuse.saved_action,
                "post_claim_refresh_failed": bool(_post_claim_refresh_failed),
                "claimed_context_token": _claimed_saved_allow_hash,
                "current_context_token": runtime_artifact_hash,
                "fresh_local_approval": claimed.get("fresh_local_approval") is True,
                "durable_exact_approval": claimed.get("durable_exact_approval") is True,
                "has_ignored_integrity": ignored_integrity is not None,
                "claim_row_invalid": claim_row_invalid,
            },
            guard_home=store.guard_home,
        )
        approval_reuse = _decision_from_native_payload(post_claim_reuse)
    final = native_finalize(
        inputs,
        {
            "current_policy_action": current_policy_action,
            "tool_grant_applied": tool_grant_applied,
            "tool_grant_identity": (
                {
                    "tool_identity_hash": local_tool_eligibility.tool_identity_hash,
                    "capability": local_tool_eligibility.capability,
                }
                if tool_grant_applied and local_tool_eligibility is not None
                else None
            ),
            "reuse_action": approval_reuse.action,
            "reuse_status": approval_reuse.status,
            "has_stored_decision": stored_policy_decision is not None,
            "has_ignored_integrity": ignored_integrity is not None,
            "saved_decision_present": bool(saved_decision_present),
            "stored_policy_action": (
                _optional_string(stored_policy_decision.get("action")) if stored_policy_decision is not None else None
            ),
            "claimed_context": _claimed_saved_allow_hash is not None,
            "asks_for_approval": asks_for_approval(config),
            "observe_mode": harness_is_recording_only(config, args.harness),
            "has_approval_requests_list": isinstance(payload_map.get("approval_requests"), list),
            "json_requested": bool(getattr(args, "json", False)),
            "output_stream_present": output_stream is not None,
            "replay_artifact_id": isinstance(payload_map.get("artifact_id"), str),
            "payload_action_is_string": isinstance(payload_map.get("policy_action"), str),
        },
        guard_home=store.guard_home,
    )
    policy_action: str = final["policy_action"]
    observed_policy_action: str | None = final["observed_policy_action"]
    hook_event_name: str = final["effective_event_name"]
    directive: dict[str, object] = final["directive"]
    policy_composition: dict[str, object] = final["policy_composition"]
    scanner_evidence: list[dict[str, object]] = [
        {
            "source": "approval_reuse",
            "input_source": final["approval_reuse_source"],
            **approval_reuse.to_evidence(),
        },
        {"source": "policy_composition", **policy_composition},
        *_embedded_script_evidence(command_text),
        *([local_tool_eligibility.to_evidence()] if local_tool_eligibility is not None else []),
        *final["evidence_tail"],
    ]
    changed_capabilities = _generic_hook_changed_capabilities(payload_map)
    silent_review = final["silent_review"]
    if silent_review is not None:
        payload_map.update(policy_action="block", approval_requests=[], prompted=False)
        blocked_request_guidance = safe_alternative_reason(
            _native_network_reason(native_edge_result) or silent_review["reason"]
        )
        payload_map["blocked_request_guidance"] = blocked_request_guidance
        _record_generic_hook_silent_review(
            args,
            action_envelope=action_envelope,
            artifact_hash=runtime_artifact_hash,
            artifact_id=artifact_id,
            artifact_name=artifact_name,
            changed_capabilities=changed_capabilities,
            command_text=command_text,
            config=config,
            home_dir=home_dir,
            review=silent_review,
            runtime_workspace=runtime_workspace,
            store=store,
        )
    effective_action_envelope = (
        action_envelope.with_pre_execution_result(policy_action) if action_envelope is not None else None
    )
    command_activity_receipt_id: str | None = None
    if final["record_receipt"]:
        receipt = build_receipt(
            harness=args.harness,
            artifact_id=artifact_id,
            artifact_hash=runtime_artifact_hash,
            policy_decision=policy_action,
            capabilities_summary=_coalesce_string(
                payload_map.get("capabilities_summary"),
                f"hook artifact • {args.harness}",
            ),
            changed_capabilities=changed_capabilities or ["hook"],
            provenance_summary=_coalesce_string(
                payload_map.get("provenance_summary"),
                f"hook event for {artifact_name}",
            ),
            artifact_name=artifact_name,
            source_scope=_coalesce_string(payload_map.get("source_scope"), "project"),
            user_override=_optional_string(payload_map.get("user_override")),
            scanner_evidence=scanner_evidence,
            approval_source=("inline" if _optional_string(payload_map.get("user_override")) is not None else "policy"),
        )
        store.add_receipt(receipt, action_envelope=effective_action_envelope)
        command_activity_receipt_id = receipt.receipt_id
    _record_harness_usage_for_hook(
        store=store,
        action_envelope=effective_action_envelope,
        payload=payload_map,
        policy_action=policy_action,
    )
    activity = final["activity"]
    canonical_harness = _canonical_harness_name(args.harness)
    if activity["phase"] == "post":
        record_post_hook_command_activity_best_effort(
            store=store,
            guard_home=store.guard_home,
            harness=canonical_harness,
            event=hook_event_name,
            payload=payload_map,
            succeeded=hook_post_succeeded(hook_event_name, payload_map),
        )
    elif activity["phase"] == "pre":
        record_pre_hook_command_activity_best_effort(
            store=store,
            guard_home=store.guard_home,
            harness=canonical_harness,
            event=hook_event_name,
            payload=payload_map,
            policy_action=cast(GuardAction, policy_action),
            receipt_id=command_activity_receipt_id,
            prompted=activity["prompted"],
            approval_reuse_status=ActivityApprovalReuseStatus(activity["reuse_status"]),
            cwd=runtime_workspace,
            home_dir=home_dir,
        )
    if directive["route"] == "silent_exit":
        return 0
    if directive["route"] == "copilot":
        _emit_copilot_hook_response(
            policy_action=policy_action,
            reason=(
                blocked_request_guidance
                if blocked_request_guidance is not None
                else _copilot_hook_reason(payload_map.get("permission_decision_reason"))
            ),
            output_stream=output_stream,
        )
        return directive_exit_code(directive, policy_action)
    if directive["queue_observe_request"]:
        observed_artifact = _generic_hook_tool_artifact(
            action_class="observed tool action",
            artifact_id=artifact_id,
            artifact_name=artifact_name,
            command=_observed_action_detail(command_text, action_envelope=action_envelope, home_dir=home_dir),
            config_path=str(runtime_workspace) if runtime_workspace is not None else "",
            harness=args.harness,
            request_summary="Guard recorded what watch-only mode would have stopped.",
        )
        queue_observe_mode_request(
            action_envelope=action_envelope,
            artifact=observed_artifact,
            artifact_hash=runtime_artifact_hash,
            changed_fields=changed_capabilities or ["tool_action"],
            executable_action=cast(GuardAction, policy_action),
            observed_policy_action=cast(GuardAction, observed_policy_action),
            redaction_level=config.receipt_redaction_level,
            risk_summary="Watch-only mode allowed an action that current policy would stop.",
            scanner_evidence=scanner_evidence,
            store=store,
        )
    if directive["queue_approval_request"]:
        _queue_generic_hook_approval(
            args,
            action_envelope=action_envelope,
            artifact_hash=runtime_artifact_hash,
            artifact_id=artifact_id,
            artifact_name=artifact_name,
            changed_capabilities=changed_capabilities,
            command_text=command_text,
            config=config,
            hook_event_name=hook_event_name,
            home_dir=home_dir,
            local_tool_eligibility=local_tool_eligibility,
            payload_map=payload_map,
            policy_action=policy_action,
            runtime_workspace=runtime_workspace,
            store=store,
        )
    _localize_pending_approval_copy(payload_map, harness=args.harness)
    incoming_reason = (
        blocked_request_guidance
        or composition["daemon_failure_reason"]
        or _native_network_reason(native_edge_result)
        or _decision_v2_harness_message(payload_map)
        or payload_map.get("permission_decision_reason")
    )
    hook_envelope: dict[str, object] = {
        "recorded": True,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "policy_action": policy_action,
        "approval_reuse": approval_reuse.to_evidence(),
        "policy_composition": policy_composition,
        "scanner_evidence": scanner_evidence,
    }
    if isinstance(payload_map.get("approval_requests"), list):
        hook_envelope["approval_requests"] = payload_map["approval_requests"]
    if blocked_request_guidance is not None:
        hook_envelope["blocked_request_guidance"] = blocked_request_guidance
        hook_envelope["prompted"] = False
    return render_generic_hook(
        args,
        action_envelope=action_envelope,
        approval_context=live_hook_approval_context(payload_map, harness=args.harness, guard_home=store.guard_home),
        canonical_harness=canonical_harness,
        coalesce=_coalesce_string,
        command_text=command_text,
        directive=directive,
        envelope=hook_envelope,
        event_name=hook_event_name,
        incoming_reason=incoming_reason,
        native_edge_result=native_edge_result,
        output_stream=output_stream,
        payload=payload_map,
        policy_action=policy_action,
        remediation=lambda: _embedded_script_remediation(command_text),
        verified_benign=lambda: hook_event_name == "PreToolUse" and bool(composition["verified_benign"]),
    )


def _native_network_reason(native_edge_result: Mapping[str, object] | None) -> str | None:
    """The network protection reason, which names the destination it matched."""
    if not isinstance(native_edge_result, Mapping):
        return None
    reason_code = native_edge_result.get("reason_code")
    reason = native_edge_result.get("reason")
    if isinstance(reason_code, str) and reason_code.startswith("network_") and isinstance(reason, str):
        return reason.strip() or None
    return None


__all__ = [
    "run_native_generic_payload",
]
