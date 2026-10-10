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


def _artifact_id_from_event(harness: str, payload: dict[str, object]) -> str:
    """Resolve runtime-artifact identity after the CLI support graph is loaded."""

    from .commands_support_runtime_artifacts import _artifact_id_from_event as resolve

    return resolve(harness, payload)


def _hook_event_name(payload: dict[str, object]) -> str | None:
    """Resolve event names lazily to keep hook startup independent of import order."""

    from .commands_support_runtime_artifacts import _hook_event_name as resolve

    return resolve(payload)


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
    from .commands_support_hook_payload import _hook_command_has_encoded_markers
    from .commands_support_interaction import _record_harness_usage_for_hook
    from .commands_support_prompts import (
        _copilot_hook_reason,
        _decision_v2_harness_message,
        _emit_copilot_hook_response,
    )
    from .commands_support_runtime_policy import _localize_pending_approval_copy
    from .commands_support_runtime_resolution import _canonical_harness_name


from ..action_lattice import guard_action_severity
from ..local_cli_hook import apply_local_cli_grant, observe_unlisted_cli
from ..models import GuardAction, GuardArtifact, HarnessDetection
from ..native_hook_decision import native_compose_current, native_finalize, native_post_claim_reuse
from ..retry_lineage import capture_retry_lineage
from ..runtime.actions import _command_detail
from ..runtime.approval_context import (
    approval_context_tokens_validation_reason,
    build_approval_context_token,
    build_runtime_launch_identity,
)
from ..runtime.approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    ApprovalReuseDecision,
    ApprovalReuseValidationFailure,
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

_GENERIC_HOOK_EXPLICIT_POSIX_SHELL_TOOLS = frozenset({"ash", "bash", "dash", "sh", "zsh"})

_GENERIC_HOOK_NON_CONTENT_FIELDS = frozenset(
    {
        "action_id",
        "approval_center_url",
        "approval_delivery",
        "approval_request_id",
        "approval_requests",
        "call_id",
        "daemon_status",
        "event_id",
        "event_time",
        "fail_mode",
        "hook_id",
        "invocation_id",
        "message_id",
        "permission_decision_reason",
        "policy_action",
        "received_at",
        "request_id",
        "review_hint",
        "session_id",
        "thread_id",
        "timestamp",
        "tool_call_id",
        "tool_use_id",
        "trace_id",
        "turn_id",
        "user_override",
    }
)


def _generic_hook_payload_digest(payload: Mapping[str, object]) -> str:
    """Return a stable action digest without delivery metadata or policy hints.

    Hook transports assign fresh request, session, tool-use, and timestamp fields
    when an otherwise identical action is retried.  Those top-level delivery
    fields are not part of the action the user reviewed.  Nested fields remain
    intact because, for an opaque tool, a value such as
    ``tool_input.request_id`` can be a real action argument.
    """

    content_payload = {
        key: value
        for key, value in payload.items()
        if _generic_hook_content_key(key) not in _GENERIC_HOOK_NON_CONTENT_FIELDS
        and _generic_hook_content_key(key) != "artifact_hash"
    }
    encoded = json.dumps(
        content_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _generic_hook_content_key(key: str) -> str:
    """Canonicalize top-level hook keys across snake/camel/kebab transports."""

    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).replace("-", "_").lower()


def _generic_hook_workspace_identity(runtime_workspace: Path | None) -> str:
    workspace = runtime_workspace or Path.cwd()
    try:
        return str(workspace.expanduser().resolve(strict=False))
    except (OSError, RuntimeError):
        return str(workspace.expanduser().absolute())


def _generic_hook_memory_command(payload: Mapping[str, object]) -> str:
    command = command_text_from_tool_payload(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
    )
    return _coalesce_string(command, payload.get("command"), payload.get("tool_name"))


def _generic_hook_action_capabilities(
    action_envelope: GuardActionEnvelope | None,
) -> dict[str, object] | None:
    if action_envelope is None:
        return None
    return {
        "action_type": action_envelope.action_type,
        "event_name": action_envelope.event_name,
        "mcp_server": action_envelope.mcp_server,
        "mcp_tool": action_envelope.mcp_tool,
        "network_hosts": list(action_envelope.network_hosts),
        "package_intent_kind": action_envelope.package_intent_kind,
        "package_manager": action_envelope.package_manager,
        "package_targets": list(action_envelope.package_targets),
        "target_paths": list(action_envelope.target_paths),
        "tool_name": action_envelope.tool_name,
    }


def _generic_hook_runtime_launch_identity(
    action_envelope: GuardActionEnvelope | None,
    payload: Mapping[str, object],
    *,
    home_dir: Path | None,
    launch_cwd: Path,
) -> dict[str, object]:
    """Content-bind the complete launch represented by a generic hook action.

    The normalized action envelope is preferred because it has already
    removed transparent shell wrappers.  Payload fallbacks cover harnesses
    that do not produce an action envelope.  The shared launch identity binds
    the executable, argv, launch cwd, and any supported local interpreted
    entrypoint.  Malformed or unresolved launch vectors receive a nonce so
    saved approval reuse fails closed.
    """

    command_source: str | None = None
    command: str | None = None
    tool_command = command_text_from_tool_payload(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
    )
    if action_envelope is not None and isinstance(action_envelope.command, str) and action_envelope.command.strip():
        command_source = "action_envelope"
        command = action_envelope.command.strip()
    else:
        payload_command = payload.get("command")
        if isinstance(payload_command, str) and payload_command.strip():
            command_source = "payload"
            command = payload_command.strip()
        else:
            if isinstance(tool_command, str) and tool_command.strip():
                command_source = "payload_tool_input"
                command = tool_command.strip()

    tool_name = payload.get("tool_name")
    normalized_tool_name = tool_name.strip().lower() if isinstance(tool_name, str) else None
    if (
        normalized_tool_name in _GENERIC_HOOK_EXPLICIT_POSIX_SHELL_TOOLS
        and isinstance(tool_command, str)
        and tool_command.strip()
    ):
        command_source = "payload_tool_input_shell"
        command = tool_command.strip()
        resolved_launch = build_runtime_launch_identity(
            normalized_tool_name,
            args=("-c", command),
            structured_command=True,
            cwd=launch_cwd,
            home_dir=home_dir,
            launch_env=os.environ,
        )
    else:
        resolved_launch = build_runtime_launch_identity(
            command,
            cwd=launch_cwd,
            home_dir=home_dir,
            launch_env=os.environ,
        )

    return {
        "command": command,
        "command_source": command_source,
        "resolved_launch": resolved_launch,
    }


def _generic_hook_approval_context_token(
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
) -> str:
    """Bind a generic fallback approval to its exact recomputed context.

    ``token`` carries the composition values the resident decided.
    """

    launch_cwd = runtime_workspace or Path.cwd()
    return build_approval_context_token(
        identity={
            "artifact_id": artifact_id,
            "artifact_name": artifact_name,
            "canonical_harness": _canonical_harness_name(harness),
            "harness": harness,
            "publisher": publisher,
            "runtime_launch": _generic_hook_runtime_launch_identity(
                action_envelope,
                payload,
                home_dir=home_dir,
                launch_cwd=launch_cwd,
            ),
            "source_scope": _coalesce_string(payload.get("source_scope"), "project"),
            "workspace": _generic_hook_workspace_identity(runtime_workspace),
        },
        content={
            "payload_digest": _generic_hook_payload_digest(payload),
            "provided_artifact_hash": _optional_string(payload.get("artifact_hash")),
        },
        capabilities={
            "action_envelope": _generic_hook_action_capabilities(action_envelope),
            "changed_capabilities": _string_list(payload.get("changed_capabilities")),
            "event_name": _hook_event_name(dict(payload)) or "PreToolUse",
            "tool_name": _optional_string(payload.get("tool_name")),
        },
        policy={
            "config": _runtime_hook_effective_policy_config(config),
            "evaluator_policy_version": _GENERIC_HOOK_EVALUATOR_POLICY_VERSION,
            "composition": {
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
        },
        sandbox={
            "analysis": config.sandbox_analysis,
            "required": current_action == "sandbox-required",
        },
    )


def _generic_hook_saved_decision(
    *,
    artifact_hash: str,
    artifact_id: str,
    artifact_name: str,
    harness: str,
    legacy_artifact_hash: str | None,
    payload: Mapping[str, object],
    publisher: str | None,
    runtime_workspace: Path | None,
    store: GuardStore,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Peek saved evidence, retaining legacy blocks without trusting legacy allows."""

    workspace = str(runtime_workspace) if runtime_workspace is not None else None
    from ..store import runtime_tool_action_exact_match_context, runtime_tool_action_policy_artifact_id

    memory_command = _generic_hook_memory_command(payload)
    runtime_exact_match_context = runtime_tool_action_exact_match_context(
        config_path=workspace,
        source_scope=_coalesce_string(payload.get("source_scope"), "project"),
        raw_command_text=memory_command,
        permission_mode=_optional_string(payload.get("permission_mode"))
        or _optional_string(payload.get("permissionMode")),
    )
    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        harness,
        artifact_id,
        artifact_hash=artifact_hash,
        workspace=workspace,
        publisher=publisher,
        runtime_exact_match_context=runtime_exact_match_context,
        memory_command=memory_command,
        memory_artifact_type=_coalesce_string(payload.get("artifact_type"), payload.get("tool_type")),
        memory_artifact_name=artifact_name,
        consume_one_shot=False,
    )
    selected_decision = lookup["decision"]
    ignored_integrity = lookup.get("ignored_local_integrity")
    policy_artifact_id = runtime_tool_action_policy_artifact_id(artifact_id)
    if policy_artifact_id is not None and policy_artifact_id != artifact_id:
        exact_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
            harness,
            policy_artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            runtime_exact_match_context=runtime_exact_match_context,
            memory_command=memory_command,
            memory_artifact_type=_coalesce_string(payload.get("artifact_type"), payload.get("tool_type")),
            memory_artifact_name=artifact_name,
            consume_one_shot=False,
        )
        exact_decision = exact_lookup["decision"]
        if ignored_integrity is None:
            ignored_integrity = exact_lookup.get("ignored_local_integrity")
        if exact_decision is not None and (
            selected_decision is None
            or guard_action_severity(exact_decision.get("action"), unknown_action="block")
            > guard_action_severity(selected_decision.get("action"), unknown_action="block")
        ):
            selected_decision = exact_decision
            ignored_integrity = exact_lookup.get("ignored_local_integrity")
    if legacy_artifact_hash is not None and legacy_artifact_hash != artifact_hash:
        legacy_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
            harness,
            artifact_id,
            artifact_hash=legacy_artifact_hash,
            workspace=workspace,
            publisher=publisher,
            runtime_exact_match_context=runtime_exact_match_context,
            memory_command=memory_command,
            memory_artifact_type=_coalesce_string(payload.get("artifact_type"), payload.get("tool_type")),
            memory_artifact_name=artifact_name,
            consume_one_shot=False,
        )
        legacy_decision = legacy_lookup["decision"]
        if ignored_integrity is None:
            ignored_integrity = legacy_lookup.get("ignored_local_integrity")
        if legacy_decision is not None and (
            selected_decision is None
            or guard_action_severity(legacy_decision.get("action"), unknown_action="block")
            > guard_action_severity(selected_decision.get("action"), unknown_action="block")
        ):
            selected_decision = legacy_decision
            ignored_integrity = legacy_lookup.get("ignored_local_integrity")
    return selected_decision, ignored_integrity


def _generic_hook_approval_reuse(
    *,
    artifact_hash: str,
    artifact_id: str,
    current_action: GuardAction,
    decision: dict[str, object] | None,
    harness: str,
    ignored_integrity: dict[str, object] | None,
    publisher: str | None,
    runtime_workspace: Path | None,
    store: GuardStore,
) -> tuple[ApprovalReuseDecision, bool]:
    saved_action: object | None = decision.get("action") if decision is not None else None
    saved_present = decision is not None or ignored_integrity is not None
    validation_reason: ApprovalReuseValidationFailure | None = None
    if ignored_integrity is not None:
        if decision is None:
            saved_action = "require-reapproval"
        validation_reason = "approval_reuse_integrity_failure"
    elif decision is not None and decision.get("action") == "allow":
        from ..store import _is_runtime_scoped_exact_match_key

        saved_artifact_hash = decision.get("artifact_hash")
        if not _is_runtime_scoped_exact_match_key(
            saved_artifact_hash if isinstance(saved_artifact_hash, str) else None
        ):
            validation_reason = cast(
                ApprovalReuseValidationFailure | None,
                approval_context_tokens_validation_reason(saved_artifact_hash, artifact_hash),
            )
    diagnosed_stored_hash: str | None = None
    if not saved_present:
        diagnosed_reason, diagnosed_stored_hash = store.approval_reuse_diagnostic(
            harness,
            artifact_id,
            artifact_hash,
            str(runtime_workspace) if runtime_workspace is not None else None,
            publisher,
        )
        if diagnosed_reason is not None:
            saved_action = "allow"
            saved_present = True
            validation_reason = cast(ApprovalReuseValidationFailure, diagnosed_reason)
    # Qualification is produced by native authenticated store lookup.
    fresh_local_approval = decision is not None and decision.get("fresh_local_approval") is True
    durable_exact_approval = decision is not None and decision.get("durable_exact_approval") is True
    reuse_native = evaluate_approval_reuse(
        current_action,
        saved_action,
        saved_decision_present=saved_present,
        validation_reason=validation_reason,
        fresh_local_approval=fresh_local_approval,
        durable_exact_approval=durable_exact_approval,
    )
    reuse = with_saved_artifact_hash_provenance(
        reuse_native
        if reuse_native is not None
        # Resident unreachable: preserve the recomputed action unchanged; the
        # saved decision is not claimed.
        else approval_reuse_authority_unavailable(current_action),
        decision.get("artifact_hash") if decision is not None else diagnosed_stored_hash,
    )
    return reuse, saved_present


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
    native_edge_result: Mapping[str, object] | None,
    payload_map: Mapping[str, object],
    runtime_artifact_checked: bool,
) -> dict[str, object]:
    return composition_inputs(
        cli_action=getattr(args, "policy_action", None),
        canonical_harness=_canonical_harness_name(args.harness),
        configured_action=configured_override if configured_override is not None else config.default_action,
        harness=args.harness,
        has_command_text=isinstance(command_text, str) and bool(command_text.strip()),
        has_configured_override=configured_override is not None,
        has_narrow_override=configured_narrow_override is not None,
        native_edge_result=native_edge_result,
        payload=payload_map,
        runtime_artifact_checked=runtime_artifact_checked,
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
    artifact_id = _coalesce_string(
        getattr(args, "artifact_id", None),
        payload_map.get("artifact_id"),
        _artifact_id_from_event(args.harness, payload_map),
    )
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
        native_edge_result=native_edge_result,
        payload_map=payload_map,
        runtime_artifact_checked=runtime_artifact_checked,
    )
    classifiers = hook_classifiers(
        canonical_harness=_canonical_harness_name(args.harness),
        guard_home=store.guard_home,
        home_dir=home_dir,
        payload=payload_map,
        runtime_artifact_checked=runtime_artifact_checked,
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
        observe_unlisted_cli(store=store, command=command_str, cwd=cwd, home_dir=home_dir)
        if grant_lookups_allowed:
            current_policy_action = apply_local_cli_grant(
                store=store,
                command=command_str,
                cwd=cwd,
                home_dir=home_dir,
                current_action=current_policy_action,
            )
    runtime_artifact_hash = _generic_hook_approval_context_token(
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
    )
    stored_policy_decision, ignored_integrity = _generic_hook_saved_decision(
        artifact_hash=runtime_artifact_hash,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        harness=args.harness,
        legacy_artifact_hash=_optional_string(payload_map.get("artifact_hash")),
        payload=payload_map,
        publisher=publisher,
        runtime_workspace=runtime_workspace,
        store=store,
    )
    approval_reuse, saved_decision_present = _generic_hook_approval_reuse(
        artifact_hash=runtime_artifact_hash,
        artifact_id=artifact_id,
        current_action=current_policy_action,
        decision=stored_policy_decision,
        harness=args.harness,
        ignored_integrity=ignored_integrity,
        publisher=publisher,
        runtime_workspace=runtime_workspace,
        store=store,
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
        # Native lookup re-authenticates the row. Unrelated authority writes
        # advance global revision and integrity ledger counters, not the grant.
        claim_row_invalid = _claimed_saved_approval is None or (
            store.approval_reuse_claim_disposition(_claimed_saved_approval) != "consumed"
            and (
                stored_policy_decision is None
                or any(
                    stored_policy_decision.get(key) != value
                    for key, value in _claimed_saved_approval.items()
                    if key not in {"_approval_authority_revision", "integrity_generation"}
                )
            )
        )
        post_claim_action, post_claim_reason = native_post_claim_reuse(
            {
                "current_policy_action": current_policy_action,
                "reuse_action": approval_reuse.action,
                "reuse_saved_action": approval_reuse.saved_action,
                "post_claim_refresh_failed": bool(_post_claim_refresh_failed),
                "context_changed": approval_context_tokens_validation_reason(
                    _claimed_saved_allow_hash, runtime_artifact_hash
                )
                is not None,
                "has_ignored_integrity": ignored_integrity is not None,
                "claim_row_invalid": claim_row_invalid,
            },
            guard_home=store.guard_home,
        )
        post_claim_reuse = evaluate_approval_reuse(
            post_claim_action,
            "allow",
            saved_decision_present=True,
            validation_reason=cast(ApprovalReuseValidationFailure | None, post_claim_reason),
            fresh_local_approval=claimed.get("fresh_local_approval") is True,
            durable_exact_approval=claimed.get("durable_exact_approval") is True,
        )
        approval_reuse = with_saved_artifact_hash_provenance(
            post_claim_reuse
            if post_claim_reuse is not None
            # Resident unreachable after the atomic claim: keep the consumed
            # claim's projected action rather than inventing a new grant.
            else approval_reuse_authority_unavailable(post_claim_action),
            _claimed_saved_allow_hash,
        )
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
            "observe_mode": config.mode == "observe",
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
        blocked_request_guidance = safe_alternative_reason(silent_review["reason"])
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
        content_flagged=_hook_command_has_encoded_markers(command_text),
        directive=directive,
        envelope=hook_envelope,
        event_name=hook_event_name,
        incoming_reason=incoming_reason,
        native_edge_result=native_edge_result,
        output_stream=output_stream,
        payload=payload_map,
        policy_action=policy_action,
        remediation=lambda: _embedded_script_remediation(command_text),
        verified_benign=lambda: hook_event_name == "PreToolUse" and classifiers["benign_tool_action"](hook_event_name),
    )


__all__ = [
    "run_native_generic_payload",
]
