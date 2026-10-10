"""Render the generic hook response the resident directive selected.

Every routing choice (route, emitter, exit code, reason policy, system
message) is in the directive; this module only executes it.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from typing import TextIO

from .commands_support_claude_approval import _claude_native_pretooluse_terminal_notice
from .commands_support_hook_payload import (
    _apply_native_edge_envelope_fields,
    _emit_native_hook_block_stderr,
    _emit_native_hook_json_document,
    _emit_native_hook_notification_stderr,
    _emit_native_hook_response,
    _emit_native_post_tool_envelope,
    _native_hook_json_document,
)
from .commands_support_interaction import _emit
from .commands_support_prompts import _codex_prompt_block_system_message
from .commands_support_runtime_policy import (
    _ensure_terminal_punctuation,
    _native_hook_reason,
    _native_hook_reason_for_harness,
)


def directive_exit_code(directive: Mapping[str, object], policy_action: str) -> int:
    """The directive's exit code; grok's depends on its adapter's emit state."""

    code = directive["exit_code"]
    if isinstance(code, int):
        return code
    from ..adapters.grok_hooks import grok_hook_process_exit

    return grok_hook_process_exit(policy_action)


def _emit_adapter(
    directive: Mapping[str, object],
    *,
    harness: str,
    policy_action: str,
    reason: str,
    event_name: str,
    payload: dict[str, object],
    output_stream: TextIO | None,
    system_message: str | None = None,
) -> None:
    emitter = directive["emitter"]
    if emitter == "grok":
        from ..adapters.grok_hooks import emit_grok_hook_response

        emit_grok_hook_response(
            policy_action=policy_action, reason=reason, event_name=event_name, output_stream=output_stream
        )
    elif emitter == "pi":
        from ..adapters.pi_hooks import emit_pi_hook_response

        emit_pi_hook_response(
            policy_action=policy_action, reason=reason, approval_payload=payload, output_stream=output_stream
        )
    elif emitter == "zcode":
        from ..adapters.zcode_hooks import emit_zcode_hook_response

        emit_zcode_hook_response(
            policy_action=policy_action,
            reason=reason,
            event_name=event_name,
            payload=payload,
            output_stream=output_stream,
        )
    elif emitter == "devin":
        from ..adapters.devin_hooks import emit_devin_hook_response

        emit_devin_hook_response(
            policy_action=policy_action,
            reason=reason,
            event_name=event_name,
            payload=payload,
            output_stream=output_stream,
        )
    else:
        _emit_native_hook_response(
            harness=harness,
            policy_action=policy_action,
            event_name=event_name,
            reason=reason,
            system_message=system_message,
            output_stream=output_stream,
        )


def _reason(
    directive: Mapping[str, object],
    *,
    approval_context: object,
    harness: str,
    incoming_reason: object,
    remediation: Callable[[], str | None],
) -> str:
    guidance = remediation() if directive["include_remediation"] else None
    mode = directive["codex_native_reason"]
    if mode == "always" or (mode == "with_approval_context" and approval_context is not None):
        return _native_hook_reason(incoming_reason, approval_context, guidance)
    return _native_hook_reason_for_harness(harness, incoming_reason, approval_context, guidance)


def render_generic_hook(
    args: argparse.Namespace,
    *,
    action_envelope: object,
    approval_context: object,
    canonical_harness: str,
    content_flagged: bool,
    directive: Mapping[str, object],
    envelope: dict[str, object],
    event_name: str,
    incoming_reason: object,
    native_edge_result: Mapping[str, object] | None,
    output_stream: TextIO | None,
    payload: dict[str, object],
    policy_action: str,
    remediation: Callable[[], str | None],
    verified_benign: Callable[[], bool],
    coalesce: Callable[..., str],
) -> int:
    """Execute the directive's exit-block / native / envelope branch."""

    harness = str(args.harness)
    as_json = bool(getattr(args, "json", False))

    def exit_code() -> int:
        return directive_exit_code(directive, policy_action)

    reason = _reason(
        directive,
        approval_context=approval_context,
        harness=harness,
        incoming_reason=incoming_reason,
        remediation=remediation,
    )
    if directive["route"] == "exit_block":
        _emit_adapter(
            directive,
            harness=harness,
            policy_action=policy_action,
            reason=reason,
            event_name=event_name,
            payload=payload,
            output_stream=output_stream,
        )
        code = exit_code()
        if code != 0 or not directive["stderr_only_on_nonzero_exit"]:
            # Kimi surfaces stderr to the user as the blocking explanation.
            _emit_native_hook_block_stderr(reason)
        return code
    if directive["terminal_notice"]:
        _emit_native_hook_notification_stderr(_claude_native_pretooluse_terminal_notice(payload=payload, reason=reason))
    if directive["try_json_document"]:
        json_result = _native_hook_json_document(
            args,
            event_name=event_name,
            policy_action=policy_action,
            reason=reason,
            envelope=envelope,
            generic_path=True,
            native_protocol_payload="hook_event_name" in payload or "event" not in payload,
            content_flagged=content_flagged,
            command_surface=getattr(action_envelope, "action_type", None) == "shell_command",
            verified_benign=verified_benign(),
        )
        if json_result is not None:
            json_doc, json_rc = json_result
            if json_doc:
                _emit_native_hook_json_document(
                    json_doc,
                    compact=canonical_harness == "copilot",
                    output_stream=output_stream,
                )
            return json_rc
    after = directive["after_json"]
    if after == "native_response":
        message = directive["system_message"]
        system_message: str | None
        if message == "claude_punctuated":
            system_message = _ensure_terminal_punctuation(reason)
        elif message == "codex_prompt":
            system_message = _codex_prompt_block_system_message(policy_action=policy_action, native_reason=reason)
        else:
            system_message = None
        _emit_adapter(
            directive,
            harness=harness,
            policy_action=policy_action,
            reason=reason,
            event_name=event_name,
            payload=payload,
            output_stream=output_stream,
            system_message=system_message,
        )
        return exit_code()
    if after == "post_tool_envelope":
        _apply_native_edge_envelope_fields(envelope, native_edge_result)
        _emit_native_post_tool_envelope(
            harness,
            policy_action=policy_action,
            reason=coalesce(incoming_reason, reason) or reason,
            response_payload=envelope,
            output_stream=output_stream,
            as_json=as_json,
        )
        return exit_code()
    envelope["continue"] = True
    envelope["decision"] = directive["envelope_decision"]
    _emit("hook", envelope, as_json)
    return exit_code()


__all__ = ["directive_exit_code", "render_generic_hook"]
