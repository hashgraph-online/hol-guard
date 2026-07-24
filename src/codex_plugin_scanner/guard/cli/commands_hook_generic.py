"""Guard CLI generic hook fallback flow."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ._commands_shared import (
        _HOOK_DAEMON_FAIL_MODES,
        _HOOK_DAEMON_FAILURE_STATUSES,
        _HOOK_DAEMON_PRESERVED_DENY_REASON,
        _HOOK_DAEMON_STRICT_REASON,
    )
    from .commands_support_claude_approval import _claude_native_pretooluse_terminal_notice
    from .commands_support_hook_payload import (
        _coalesce_string,
        _emit_native_hook_block_stderr,
        _emit_native_hook_notification_stderr,
        _emit_native_hook_response,
    )
    from .commands_support_interaction import (
        _emit,
        _record_harness_usage_for_hook,
        _should_emit_claude_native_pretooluse_notice,
        _should_emit_copilot_hook_response,
        _should_emit_native_hook_exit_block,
        _should_emit_native_hook_json_response,
        _should_emit_native_hook_response,
    )
    from .commands_support_prompts import (
        _codex_prompt_block_system_message,
        _copilot_hook_reason,
        _decision_v2_harness_message,
        _emit_copilot_hook_response,
    )
    from .commands_support_runtime_artifacts import (
        _artifact_id_from_event,
        _hook_event_name,
        _optional_string,
        _string_list,
    )
    from .commands_support_runtime_policy import (
        _ensure_terminal_punctuation,
        _localize_pending_approval_copy,
        _native_approval_center_context,
        _native_hook_reason,
        _native_hook_reason_for_harness,
    )
    from .commands_support_runtime_resolution import _canonical_harness_name, _copilot_hook_stage


from ..action_lattice import (
    guard_action_severity,
    most_restrictive_guard_action,
    normalize_guard_action_result,
)
from ..models import GuardAction
from ..runtime.approval_context import (
    approval_context_tokens_validation_reason,
    build_approval_context_token,
    build_runtime_launch_identity,
)
from ..runtime.approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
    ApprovalReuseDecision,
    ApprovalReuseValidationFailure,
    evaluate_approval_reuse,
)
from ..runtime.command_activity_contract import ActivityApprovalReuseStatus
from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_codex_paths import _codex_prompt_credential_file_artifact
from .commands_support_command_activity import (
    command_activity_was_prompted,
    hook_is_post_event,
    hook_is_pre_event,
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
    record_pre_hook_command_activity_best_effort,
)
from .commands_support_runtime_policy import _runtime_hook_effective_policy_config

# Bump when generic-hook classification or action-composition semantics change.
_GENERIC_HOOK_EVALUATOR_POLICY_VERSION = "generic-hook-evaluation-v1"

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

_COPILOT_VERIFIED_BENIGN_PAYLOAD_HINT_REASON = "untrusted_hook_payload_hint_ignored_guard_verified_benign"
_VERIFIED_BENIGN_DEFAULT_DISPOSITION_REASON = "configured_default_relaxed_guard_verified_benign"
_UNTRUSTED_DAEMON_PERMISSIVE_REASON = (
    "HOL Guard received an unauthenticated hint that the daemon was unreachable in permissive mode; "
    "the current local policy action was preserved."
)
_UNTRUSTED_DAEMON_PERMISSIVE_REASON_CODE = "untrusted_daemon_permissive_hint_preserved_current_action"
_UNTRUSTED_DAEMON_STRICT_REASON_CODE = "untrusted_daemon_strict_hint_tightened_to_block"


def _generic_hook_ignored_payload_action_reason(
    *,
    args: argparse.Namespace,
    home_dir: Path | None,
    payload: dict[str, object],
    payload_action_recognized: bool,
    runtime_workspace: Path | None,
) -> str | None:
    """Explain why a legacy Copilot policy hint is not an authority input.

    ``policyAction`` is not part of Copilot's native pre-tool input contract,
    and generic hook stdin has no authenticated provenance.  Retain it as a
    conservative hint for opaque actions, but omit it from policy composition
    when Guard's own command classifier has positively established that the
    generic fallback action is read-only.

    Unknown action spellings remain fail-closed through the normalizer.  The
    caller reaches this generic path only after modeled runtime artifacts,
    package requests, and data-flow signals have been evaluated.
    """

    if (
        not payload_action_recognized
        or _canonical_harness_name(args.harness) != "copilot"
        or _copilot_hook_stage(payload) != "pretooluse"
    ):
        return None
    if not is_explicitly_benign_tool_action_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=runtime_workspace,
        home_dir=home_dir,
    ):
        return None
    return _COPILOT_VERIFIED_BENIGN_PAYLOAD_HINT_REASON


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
            launch_env=os.environ,
        )
    else:
        resolved_launch = build_runtime_launch_identity(
            command,
            cwd=launch_cwd,
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
    current_action: GuardAction,
    current_config_action: GuardAction,
    daemon_hint_disposition: str | None,
    daemon_hint_reason_code: str | None,
    daemon_status: str | None,
    fail_mode: str | None,
    harness: str,
    payload: Mapping[str, object],
    publisher: str | None,
    runtime_workspace: Path | None,
    trusted_cli_action: GuardAction | None,
    untrusted_payload_action: GuardAction | None,
    untrusted_payload_action_disposition: str | None,
    untrusted_payload_action_reason: str | None,
) -> str:
    """Bind a generic fallback approval to its exact recomputed context."""

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
                "current_config_action": current_config_action,
                "daemon_hint_disposition": daemon_hint_disposition,
                "daemon_hint_reason_code": daemon_hint_reason_code,
                "daemon_status": daemon_status,
                "fail_mode": fail_mode,
                "trusted_cli_action": trusted_cli_action,
                "untrusted_payload_action": untrusted_payload_action,
                "untrusted_payload_action_disposition": untrusted_payload_action_disposition,
                "untrusted_payload_action_reason": untrusted_payload_action_reason,
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
    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        harness,
        artifact_id,
        artifact_hash=artifact_hash,
        workspace=workspace,
        publisher=publisher,
        memory_command=_coalesce_string(payload.get("command"), payload.get("tool_name")),
        memory_artifact_type=_coalesce_string(payload.get("artifact_type"), payload.get("tool_type")),
        memory_artifact_name=artifact_name,
        consume_one_shot=False,
    )
    selected_decision = lookup["decision"]
    ignored_integrity = lookup.get("ignored_local_integrity")
    if legacy_artifact_hash is not None and legacy_artifact_hash != artifact_hash:
        legacy_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
            harness,
            artifact_id,
            artifact_hash=legacy_artifact_hash,
            workspace=workspace,
            publisher=publisher,
            memory_command=_coalesce_string(payload.get("command"), payload.get("tool_name")),
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
        validation_reason = cast(
            ApprovalReuseValidationFailure | None,
            approval_context_tokens_validation_reason(decision.get("artifact_hash"), artifact_hash),
        )
    if not saved_present:
        diagnosed_reason = store.approval_reuse_validation_reason(
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
    reuse = evaluate_approval_reuse(
        current_action,
        saved_action,
        saved_decision_present=saved_present,
        validation_reason=validation_reason,
    )
    return reuse, saved_present


def _should_relax_configured_default(
    *,
    configured_action: GuardAction,
    has_narrow_override: bool,
    home_dir: Path | None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
) -> bool:
    if has_narrow_override or configured_action not in {"review", "require-reapproval"}:
        return False
    event_name = _hook_event_name(dict(payload))
    if event_name == "UserPromptSubmit":
        prompt_text = payload.get("prompt")
        if not isinstance(prompt_text, str) or not prompt_text.strip():
            return False
        if extract_prompt_requests(prompt_text):
            return False
        return (
            _codex_prompt_credential_file_artifact(
                prompt_text=prompt_text,
                cwd=runtime_workspace,
                config_path="<runtime>",
            )
            is None
        )
    return event_name == "PreToolUse" and is_explicitly_benign_tool_action_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=runtime_workspace,
        home_dir=home_dir,
    )


def _run_hook_generic_payload(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    home_dir: Path | None = None,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    post_claim_revalidator: Callable[[str], int | None] | None = None,
    _claimed_saved_allow_hash: str | None = None,
    _claim_saved_approval: bool = True,
    _post_claim_refresh_failed: bool = False,
) -> int:
    payload_map = dict(payload)
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
    configured_override = config.resolve_action_override(
        args.harness,
        artifact_id,
        publisher,
    )
    configured_narrow_override = config.resolve_artifact_or_publisher_action_override(
        artifact_id,
        publisher,
    )
    configured_policy_normalization = normalize_guard_action_result(
        configured_override if configured_override is not None else config.default_action,
        unknown_action="require-reapproval",
    )
    hook_event_name = _hook_event_name(payload_map)
    verified_benign_default = _should_relax_configured_default(
        configured_action=configured_policy_normalization.action,
        has_narrow_override=configured_narrow_override is not None,
        home_dir=home_dir,
        payload=payload_map,
        runtime_workspace=runtime_workspace,
    )
    current_config_normalization = (
        normalize_guard_action_result("warn", unknown_action="require-reapproval")
        if verified_benign_default
        else configured_policy_normalization
    )
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
    ignored_payload_action_reason = _generic_hook_ignored_payload_action_reason(
        args=args,
        home_dir=home_dir,
        payload=payload_map,
        payload_action_recognized=(
            payload_action_normalization.recognized if payload_action_normalization is not None else False
        ),
        runtime_workspace=runtime_workspace,
    )
    payload_action_disposition = (
        "ignored"
        if ignored_payload_action_reason is not None
        else "applied"
        if payload_action_normalization is not None
        else None
    )
    current_action_inputs: list[GuardAction] = [current_config_normalization.action]
    if cli_action_normalization is not None:
        current_action_inputs.append(cli_action_normalization.action)
    if payload_action_normalization is not None and ignored_payload_action_reason is None:
        # Hook payloads are untrusted hints. They may make local policy stricter
        # but can never lower the current configured action.
        current_action_inputs.append(payload_action_normalization.action)
    policy_action = most_restrictive_guard_action(*current_action_inputs)
    daemon_status = _optional_string(payload_map.get("daemon_status"))
    fail_mode = _optional_string(payload_map.get("fail_mode"))
    daemon_failure_reason: str | None = None
    daemon_hint_disposition: str | None = None
    daemon_hint_reason_code: str | None = None
    if daemon_status in _HOOK_DAEMON_FAILURE_STATUSES and fail_mode in _HOOK_DAEMON_FAIL_MODES:
        if fail_mode == "strict":
            previous_action = policy_action
            policy_action = most_restrictive_guard_action(policy_action, "block")
            daemon_hint_disposition = "preserved_current_block" if previous_action == "block" else "tightened_to_block"
            daemon_hint_reason_code = _UNTRUSTED_DAEMON_STRICT_REASON_CODE
            daemon_failure_reason = _HOOK_DAEMON_STRICT_REASON
            payload_map["permission_decision_reason"] = daemon_failure_reason
        else:
            daemon_hint_disposition = "preserved_current_action"
            daemon_hint_reason_code = _UNTRUSTED_DAEMON_PERMISSIVE_REASON_CODE
            if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
                daemon_failure_reason = _coalesce_string(
                    payload_map.get("permission_decision_reason"),
                    _HOOK_DAEMON_PRESERVED_DENY_REASON,
                )
                payload_map["permission_decision_reason"] = daemon_failure_reason
            else:
                daemon_failure_reason = _UNTRUSTED_DAEMON_PERMISSIVE_REASON
                payload_map["permission_decision_reason"] = daemon_failure_reason
    current_policy_action = policy_action
    runtime_artifact_hash = _generic_hook_approval_context_token(
        action_envelope=action_envelope,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        config=config,
        current_action=current_policy_action,
        current_config_action=current_config_normalization.action,
        daemon_hint_disposition=daemon_hint_disposition,
        daemon_hint_reason_code=daemon_hint_reason_code,
        daemon_status=daemon_status,
        fail_mode=fail_mode,
        harness=args.harness,
        payload=payload_map,
        publisher=publisher,
        runtime_workspace=runtime_workspace,
        trusted_cli_action=(cli_action_normalization.action if cli_action_normalization is not None else None),
        untrusted_payload_action=(
            payload_action_normalization.action if payload_action_normalization is not None else None
        ),
        untrusted_payload_action_disposition=payload_action_disposition,
        untrusted_payload_action_reason=ignored_payload_action_reason,
    )
    legacy_artifact_hash = _optional_string(payload_map.get("artifact_hash"))
    stored_policy_decision, ignored_integrity = _generic_hook_saved_decision(
        artifact_hash=runtime_artifact_hash,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        harness=args.harness,
        legacy_artifact_hash=legacy_artifact_hash,
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
            approval_reuse = evaluate_approval_reuse(
                current_policy_action,
                stored_policy_decision.get("action"),
                saved_decision_present=True,
                validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
            )
        else:
            # A successful one-shot claim is not itself the launch authority.
            # Rebuild the complete current context after the atomic write so a
            # policy/configuration mutation performed by the claiming store (or
            # racing with it) cannot inherit the stale pre-claim allow.
            if post_claim_revalidator is not None:
                try:
                    refreshed_result = post_claim_revalidator(runtime_artifact_hash)
                except Exception:
                    refreshed_result = None
                if refreshed_result is not None:
                    return refreshed_result
                _post_claim_refresh_failed = True
            return _run_hook_generic_payload(
                args,
                action_envelope=action_envelope,
                config=config,
                home_dir=home_dir,
                output_stream=output_stream,
                payload=payload,
                runtime_workspace=runtime_workspace,
                store=store,
                post_claim_revalidator=None,
                _claimed_saved_allow_hash=runtime_artifact_hash,
                _claim_saved_approval=False,
                _post_claim_refresh_failed=_post_claim_refresh_failed,
            )
    policy_action = approval_reuse.action
    stored_policy_action = (
        _optional_string(stored_policy_decision.get("action")) if stored_policy_decision is not None else None
    )
    approval_reuse_source = (
        "saved_policy_decision"
        if stored_policy_decision is not None
        else "saved_policy_integrity"
        if ignored_integrity is not None
        else "invalidated_saved_policy"
        if saved_decision_present
        else None
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
        if ignored_integrity is not None:
            claimed_validation_reason = "approval_reuse_integrity_failure"

        # An unclaimed allow found by the fresh lookup is evidence only. The
        # already-claimed exact row may satisfy a freshly recomputed review;
        # fresh blocks and terminal current actions remain authoritative.
        post_claim_current_action = policy_action
        if approval_reuse.saved_action == "allow" and approval_reuse.action == "allow":
            post_claim_current_action = current_policy_action
        if claimed_validation_reason is not None:
            post_claim_current_action = most_restrictive_guard_action(
                post_claim_current_action,
                "require-reapproval",
            )
        approval_reuse = evaluate_approval_reuse(
            post_claim_current_action,
            "allow",
            saved_decision_present=True,
            validation_reason=claimed_validation_reason,
        )
        policy_action = approval_reuse.action
        approval_reuse_source = "claimed_saved_policy_decision"
    policy_composition = {
        "current_config_action": current_config_normalization.action,
        "configured_policy_action": configured_policy_normalization.action,
        "configured_default_disposition": ("relaxed_verified_benign" if verified_benign_default else "applied"),
        "configured_default_disposition_reason_code": (
            _VERIFIED_BENIGN_DEFAULT_DISPOSITION_REASON if verified_benign_default else None
        ),
        "trusted_cli_override": cli_action_normalization.action if cli_action_normalization is not None else None,
        "untrusted_hook_payload_hint": (
            payload_action_normalization.action if payload_action_normalization is not None else None
        ),
        "untrusted_hook_payload_hint_disposition": payload_action_disposition,
        "untrusted_hook_payload_hint_reason_code": ignored_payload_action_reason,
        "daemon_hint_disposition": daemon_hint_disposition,
        "daemon_hint_reason_code": daemon_hint_reason_code,
        "daemon_hint_trust": ("untrusted_hook_payload" if daemon_hint_disposition is not None else None),
        "daemon_status": daemon_status,
        "fail_mode": fail_mode,
        "current_composed_action": current_policy_action,
        "saved_policy_action": stored_policy_action,
        "approval_reuse_source": approval_reuse_source,
        "authoritative_action": policy_action,
    }
    scanner_evidence: list[dict[str, object]] = [
        {
            "source": "approval_reuse",
            "input_source": approval_reuse_source,
            **approval_reuse.to_evidence(),
        },
        {
            "source": "policy_composition",
            **policy_composition,
        },
    ]
    if ignored_payload_action_reason is not None:
        scanner_evidence.append(
            {
                "source": "hook_payload_trust",
                "input_source": "untrusted_hook_payload_hint",
                "status": "ignored",
                "reason_code": ignored_payload_action_reason,
                "classifier": "is_explicitly_benign_tool_action_request",
            }
        )
    if verified_benign_default:
        scanner_evidence.append(
            {
                "source": "configured_default",
                "input_source": "local_config",
                "status": "relaxed_verified_benign",
                "reason_code": _VERIFIED_BENIGN_DEFAULT_DISPOSITION_REASON,
                "classifier": "is_explicitly_benign_tool_action_request",
            }
        )
    if daemon_hint_disposition is not None:
        scanner_evidence.append(
            {
                "source": "daemon_hint_trust",
                "input_source": "untrusted_hook_payload",
                "status": "monotonic-only",
                "disposition": daemon_hint_disposition,
                "reason_code": daemon_hint_reason_code,
            }
        )
    for input_source, normalization in (
        ("current_config_action", current_config_normalization),
        ("trusted_cli_override", cli_action_normalization),
        ("untrusted_hook_payload_hint", payload_action_normalization),
    ):
        if normalization is not None and not normalization.recognized:
            scanner_evidence.append(
                {
                    "source": "guard_action_normalizer",
                    "input_source": input_source,
                    "reason_code": normalization.reason_code,
                    "original_action": normalization.original_action,
                    "original_type": normalization.original_type,
                    "normalized_action": normalization.action,
                }
            )
    hook_event_name = hook_event_name or "PreToolUse"
    changed_capabilities = _string_list(payload_map.get("changed_capabilities"))
    if not changed_capabilities and isinstance(payload_map.get("event"), str):
        changed_capabilities = [str(payload_map["event"])]
    should_record_generic_hook_receipt = not (
        args.harness == "codex"
        and hook_event_name == "PreToolUse"
        and policy_action not in {"review", "require-reapproval", "sandbox-required", "block"}
    )
    effective_action_envelope = (
        action_envelope.with_pre_execution_result(policy_action) if action_envelope is not None else None
    )
    command_activity_receipt_id: str | None = None
    if should_record_generic_hook_receipt:
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
    if hook_is_post_event(hook_event_name):
        record_post_hook_command_activity_best_effort(
            store=store,
            guard_home=store.guard_home,
            harness=_canonical_harness_name(args.harness),
            event=hook_event_name,
            payload=payload_map,
            succeeded=hook_post_succeeded(hook_event_name, payload_map),
        )
    elif hook_is_pre_event(hook_event_name):
        command_activity_reuse_status = (
            ActivityApprovalReuseStatus(approval_reuse.status)
            if approval_reuse.status in {item.value for item in ActivityApprovalReuseStatus}
            else ActivityApprovalReuseStatus.NOT_APPLICABLE
        )
        record_pre_hook_command_activity_best_effort(
            store=store,
            guard_home=store.guard_home,
            harness=_canonical_harness_name(args.harness),
            event=hook_event_name,
            payload=payload_map,
            policy_action=cast(GuardAction, policy_action),
            receipt_id=command_activity_receipt_id,
            prompted=command_activity_was_prompted(
                cast(GuardAction, current_policy_action),
                command_activity_reuse_status,
            ),
            approval_reuse_status=command_activity_reuse_status,
            cwd=runtime_workspace,
            home_dir=home_dir,
        )
    if _should_emit_copilot_hook_response(args):
        _emit_copilot_hook_response(
            policy_action=policy_action,
            reason=_copilot_hook_reason(payload_map.get("permission_decision_reason")),
            output_stream=output_stream,
        )
        return 0
    _localize_pending_approval_copy(payload_map, harness=args.harness)
    incoming_reason = (
        daemon_failure_reason
        or _decision_v2_harness_message(payload_map)
        or payload_map.get("permission_decision_reason")
    )
    approval_context = _native_approval_center_context(payload_map, harness=args.harness)
    if _should_emit_native_hook_exit_block(args, event_name=hook_event_name, policy_action=policy_action):
        block_reason = _native_hook_reason_for_harness(
            args.harness,
            incoming_reason,
            approval_context,
        )
        if _canonical_harness_name(args.harness) == "kimi":
            _emit_native_hook_response(
                harness=args.harness,
                policy_action=policy_action,
                event_name=hook_event_name,
                reason=block_reason,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "grok":
            from ..adapters.grok_hooks import emit_grok_hook_response

            emit_grok_hook_response(
                policy_action=policy_action,
                reason=block_reason,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "pi":
            from ..adapters.pi_hooks import emit_pi_hook_response

            emit_pi_hook_response(
                policy_action=policy_action,
                reason=block_reason,
                approval_payload=payload_map,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "adal":
            from ..adapters.adal_hooks import emit_adal_hook_response

            emit_adal_hook_response(
                policy_action=policy_action,
                reason=block_reason,
                event_name=hook_event_name,
                payload=payload_map,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "zcode":
            from ..adapters.zcode_hooks import emit_zcode_hook_response

            emit_zcode_hook_response(
                policy_action=policy_action,
                reason=block_reason,
                event_name=hook_event_name,
                payload=payload_map,
                output_stream=output_stream,
            )
        # Kimi surfaces stderr to the user as the blocking explanation.
        _emit_native_hook_block_stderr(block_reason)
        return 2
    if _canonical_harness_name(args.harness) == "codex" and (
        hook_event_name == "UserPromptSubmit" or approval_context is not None
    ):
        reason = _native_hook_reason(
            incoming_reason,
            approval_context,
        )
    else:
        reason = _native_hook_reason_for_harness(
            args.harness,
            incoming_reason,
            approval_context,
        )
    if _should_emit_claude_native_pretooluse_notice(
        args,
        event_name=hook_event_name,
        policy_action=policy_action,
    ):
        _emit_native_hook_notification_stderr(
            _claude_native_pretooluse_terminal_notice(payload=payload_map, reason=reason)
        )
    if _should_emit_native_hook_response(args) or _should_emit_native_hook_json_response(
        args,
        event_name=hook_event_name,
        output_stream=output_stream,
    ):
        if _canonical_harness_name(args.harness) == "grok":
            from ..adapters.grok_hooks import emit_grok_hook_response

            emit_grok_hook_response(
                policy_action=policy_action,
                reason=reason,
                output_stream=output_stream,
            )
            return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2
        if _canonical_harness_name(args.harness) == "pi":
            from ..adapters.pi_hooks import emit_pi_hook_response

            emit_pi_hook_response(
                policy_action=policy_action,
                reason=reason,
                approval_payload=payload_map,
                output_stream=output_stream,
            )
            return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2
        if _canonical_harness_name(args.harness) == "adal":
            from ..adapters.adal_hooks import adal_hook_should_block, emit_adal_hook_response

            emit_adal_hook_response(
                policy_action=policy_action,
                reason=reason,
                event_name=hook_event_name,
                payload=payload_map,
                output_stream=output_stream,
            )
            return (
                2
                if adal_hook_should_block(
                    policy_action=policy_action,
                    event_name=hook_event_name,
                )
                else 0
            )
        if _canonical_harness_name(args.harness) == "zcode":
            from ..adapters.zcode_hooks import emit_zcode_hook_response

            emit_zcode_hook_response(
                policy_action=policy_action,
                reason=reason,
                event_name=hook_event_name,
                payload=payload_map,
                output_stream=output_stream,
            )
            return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2
        system_message = None
        canonical_harness = _canonical_harness_name(args.harness)
        if (
            canonical_harness == "claude-code"
            and hook_event_name in {"UserPromptSubmit", "PreToolUse"}
            and policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
        ):
            system_message = _ensure_terminal_punctuation(reason)
        elif canonical_harness == "codex" and hook_event_name == "UserPromptSubmit":
            system_message = _codex_prompt_block_system_message(
                policy_action=policy_action,
                native_reason=reason,
            )
        _emit_native_hook_response(
            harness=args.harness,
            policy_action=policy_action,
            event_name=hook_event_name,
            reason=reason,
            system_message=system_message,
            output_stream=output_stream,
        )
        return 0
    _emit(
        "hook",
        {
            "recorded": True,
            "artifact_id": artifact_id,
            "artifact_name": artifact_name,
            "policy_action": policy_action,
            "approval_reuse": approval_reuse.to_evidence(),
            "policy_composition": policy_composition,
            "scanner_evidence": scanner_evidence,
        },
        getattr(args, "json", False),
    )
    return 1 if policy_action in {"review", "require-reapproval", "sandbox-required", "block"} else 0


__all__ = [
    "_run_hook_generic_payload",
]
