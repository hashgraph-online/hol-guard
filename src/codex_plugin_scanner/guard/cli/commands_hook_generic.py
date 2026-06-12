"""Guard CLI generic hook fallback flow."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *
from .commands_parser_helpers import *

def _run_hook_generic_payload(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int:
    runtime_artifact = None
    artifact_id = _coalesce_string(
        getattr(args, "artifact_id", None),
        payload.get("artifact_id"),
        _artifact_id_from_event(args.harness, payload),
    )
    artifact_name = _coalesce_string(
        getattr(args, "artifact_name", None),
        payload.get("artifact_name"),
        payload.get("tool_name"),
        artifact_id,
    )
    stored_policy_action = store.resolve_policy(
        args.harness,
        artifact_id,
        str(payload.get("artifact_hash")) if isinstance(payload.get("artifact_hash"), str) else None,
        str(runtime_workspace) if runtime_workspace else None,
    )
    incoming_policy_action = _optional_string(payload.get("policy_action"))
    policy_action = _coalesce_string(
        getattr(args, "policy_action", None),
        stored_policy_action,
        incoming_policy_action,
        config.default_action,
    )
    if (
        _canonical_harness_name(args.harness) == "copilot"
        and _copilot_hook_stage(payload) == "pretooluse"
        and runtime_artifact is None
        and stored_policy_action is None
        and not isinstance(getattr(args, "policy_action", None), str)
        and incoming_policy_action in VALID_GUARD_ACTIONS
        and is_explicitly_benign_tool_action_request(
            payload.get("tool_name"),
            payload.get("tool_input", payload.get("arguments")),
        )
    ):
        policy_action = "allow"
    if (
        stored_policy_action is None
        and not isinstance(getattr(args, "policy_action", None), str)
        and not isinstance(payload.get("policy_action"), str)
        and runtime_artifact is not None
        and runtime_artifact.artifact_type == "tool_action_request"
    ):
        policy_action = SAFE_CHANGED_HASH_ACTION
    if policy_action not in VALID_GUARD_ACTIONS:
        policy_action = SAFE_CHANGED_HASH_ACTION
    daemon_status = _optional_string(payload.get("daemon_status"))
    fail_mode = _optional_string(payload.get("fail_mode"))
    daemon_failure_reason: str | None = None
    if daemon_status in _HOOK_DAEMON_FAILURE_STATUSES and fail_mode in _HOOK_DAEMON_FAIL_MODES:
        if fail_mode == "strict":
            policy_action = "block"
            daemon_failure_reason = _HOOK_DAEMON_STRICT_REASON
            payload["permission_decision_reason"] = daemon_failure_reason
        else:
            if policy_action in {"block", "sandbox-required", "require-reapproval"}:
                daemon_failure_reason = _coalesce_string(
                    payload.get("permission_decision_reason"),
                    _HOOK_DAEMON_PRESERVED_DENY_REASON,
                )
                payload["permission_decision_reason"] = daemon_failure_reason
            else:
                policy_action = "allow"
                daemon_failure_reason = _HOOK_DAEMON_PERMISSIVE_REASON
                payload["permission_decision_reason"] = daemon_failure_reason
    hook_event_name = _hook_event_name(payload) or "PreToolUse"
    changed_capabilities = _string_list(payload.get("changed_capabilities"))
    if not changed_capabilities and isinstance(payload.get("event"), str):
        changed_capabilities = [str(payload["event"])]
    should_record_generic_hook_receipt = not (
        args.harness == "codex"
        and hook_event_name == "PreToolUse"
        and policy_action not in {"block", "sandbox-required", "require-reapproval"}
    )
    if should_record_generic_hook_receipt:
        receipt = build_receipt(
            harness=args.harness,
            artifact_id=artifact_id,
            artifact_hash=str(payload.get("artifact_hash", f"hook:{artifact_id}")),
            policy_decision=policy_action,
            capabilities_summary=_coalesce_string(
                payload.get("capabilities_summary"),
                f"hook artifact • {args.harness}",
            ),
            changed_capabilities=changed_capabilities or ["hook"],
            provenance_summary=_coalesce_string(
                payload.get("provenance_summary"),
                f"hook event for {artifact_name}",
            ),
            artifact_name=artifact_name,
            source_scope=_coalesce_string(payload.get("source_scope"), "project"),
            user_override=_optional_string(payload.get("user_override")),
            approval_source=("inline" if _optional_string(payload.get("user_override")) is not None else "policy"),
        )
        store.add_receipt(receipt, action_envelope=action_envelope)
    _record_harness_usage_for_hook(
        store=store,
        action_envelope=action_envelope,
        payload=payload,
        policy_action=policy_action,
    )
    if _should_emit_copilot_hook_response(args):
        _emit_copilot_hook_response(
            policy_action=policy_action,
            reason=_copilot_hook_reason(payload.get("permission_decision_reason")),
            output_stream=output_stream,
        )
        return 0
    _localize_pending_approval_copy(payload, harness=args.harness)
    incoming_reason = (
        daemon_failure_reason
        or _decision_v2_harness_message(payload)
        or payload.get("permission_decision_reason")
    )
    approval_context = _native_approval_center_context(payload, harness=args.harness)
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
            # Kimi surfaces stderr to the user as the blocking explanation.
            _emit_native_hook_block_stderr(block_reason)
        else:
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
            _claude_native_pretooluse_terminal_notice(payload=payload, reason=reason)
        )
    if _should_emit_native_hook_response(args) or _should_emit_native_hook_json_response(
        args,
        event_name=hook_event_name,
        output_stream=output_stream,
    ):
        system_message = None
        canonical_harness = _canonical_harness_name(args.harness)
        if (
            canonical_harness == "claude-code"
            and hook_event_name in {"UserPromptSubmit", "PreToolUse"}
            and policy_action in {"block", "sandbox-required", "require-reapproval"}
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
        },
        getattr(args, "json", False),
    )
    return 1 if policy_action in {"block", "require-reapproval"} else 0

__all__ = [
    "_run_hook_generic_payload",
]
