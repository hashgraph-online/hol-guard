"""Guard CLI generic hook fallback flow."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import (
        _HOOK_DAEMON_FAIL_MODES,
        _HOOK_DAEMON_FAILURE_STATUSES,
        _HOOK_DAEMON_PERMISSIVE_REASON,
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


from ._commands_shared import *
from .commands_parser_helpers import *


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
) -> int:
    payload_map = dict(payload)
    runtime_artifact = None
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
    stored_policy_action = store.resolve_policy(
        args.harness,
        artifact_id,
        str(payload_map.get("artifact_hash")) if isinstance(payload_map.get("artifact_hash"), str) else None,
        str(runtime_workspace) if runtime_workspace else None,
        memory_command=_coalesce_string(
            payload_map.get("command"),
            payload_map.get("tool_name"),
        ),
        memory_artifact_type=_coalesce_string(
            payload_map.get("artifact_type"),
            payload_map.get("tool_type"),
        ),
        memory_artifact_name=artifact_name,
    )
    incoming_policy_action = _optional_string(payload_map.get("policy_action"))
    policy_action = _coalesce_string(
        getattr(args, "policy_action", None),
        stored_policy_action,
        incoming_policy_action,
        config.default_action,
    )
    if (
        _canonical_harness_name(args.harness) == "copilot"
        and _copilot_hook_stage(payload_map) == "pretooluse"
        and runtime_artifact is None
        and stored_policy_action is None
        and not isinstance(getattr(args, "policy_action", None), str)
        and incoming_policy_action in VALID_GUARD_ACTIONS
        and is_explicitly_benign_tool_action_request(
            payload_map.get("tool_name"),
            payload_map.get("tool_input", payload_map.get("arguments")),
            cwd=runtime_workspace,
            home_dir=home_dir,
        )
    ):
        policy_action = "allow"
    if (
        stored_policy_action is None
        and not isinstance(getattr(args, "policy_action", None), str)
        and not isinstance(payload_map.get("policy_action"), str)
        and runtime_artifact is not None
        and runtime_artifact.artifact_type == "tool_action_request"
    ):
        policy_action = SAFE_CHANGED_HASH_ACTION
    if policy_action not in VALID_GUARD_ACTIONS:
        policy_action = SAFE_CHANGED_HASH_ACTION
    daemon_status = _optional_string(payload_map.get("daemon_status"))
    fail_mode = _optional_string(payload_map.get("fail_mode"))
    daemon_failure_reason: str | None = None
    if daemon_status in _HOOK_DAEMON_FAILURE_STATUSES and fail_mode in _HOOK_DAEMON_FAIL_MODES:
        if fail_mode == "strict":
            policy_action = "block"
            daemon_failure_reason = _HOOK_DAEMON_STRICT_REASON
            payload_map["permission_decision_reason"] = daemon_failure_reason
        else:
            if policy_action in {"block", "sandbox-required", "require-reapproval"}:
                daemon_failure_reason = _coalesce_string(
                    payload_map.get("permission_decision_reason"),
                    _HOOK_DAEMON_PRESERVED_DENY_REASON,
                )
                payload_map["permission_decision_reason"] = daemon_failure_reason
            else:
                policy_action = "allow"
                daemon_failure_reason = _HOOK_DAEMON_PERMISSIVE_REASON
                payload_map["permission_decision_reason"] = daemon_failure_reason
    hook_event_name = _hook_event_name(payload_map) or "PreToolUse"
    changed_capabilities = _string_list(payload_map.get("changed_capabilities"))
    if not changed_capabilities and isinstance(payload_map.get("event"), str):
        changed_capabilities = [str(payload_map["event"])]
    should_record_generic_hook_receipt = not (
        args.harness == "codex"
        and hook_event_name == "PreToolUse"
        and policy_action not in {"block", "sandbox-required", "require-reapproval"}
    )
    if should_record_generic_hook_receipt:
        receipt = build_receipt(
            harness=args.harness,
            artifact_id=artifact_id,
            artifact_hash=str(payload_map.get("artifact_hash", f"hook:{artifact_id}")),
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
            approval_source=("inline" if _optional_string(payload_map.get("user_override")) is not None else "policy"),
        )
        store.add_receipt(receipt, action_envelope=action_envelope)
    _record_harness_usage_for_hook(
        store=store,
        action_envelope=action_envelope,
        payload=payload_map,
        policy_action=policy_action,
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
            return 0 if policy_action not in {"block", "sandbox-required", "require-reapproval"} else 2
        if _canonical_harness_name(args.harness) == "pi":
            from ..adapters.pi_hooks import emit_pi_hook_response

            emit_pi_hook_response(
                policy_action=policy_action,
                reason=reason,
                approval_payload=payload_map,
                output_stream=output_stream,
            )
            return 0 if policy_action not in {"block", "sandbox-required", "require-reapproval"} else 2
        if _canonical_harness_name(args.harness) == "zcode":
            from ..adapters.zcode_hooks import emit_zcode_hook_response

            emit_zcode_hook_response(
                policy_action=policy_action,
                reason=reason,
                event_name=hook_event_name,
                payload=payload_map,
                output_stream=output_stream,
            )
            return 0 if policy_action not in {"block", "sandbox-required", "require-reapproval"} else 2
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
