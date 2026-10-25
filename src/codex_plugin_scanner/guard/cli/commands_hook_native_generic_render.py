"""Render the hook response the resident directive selected.

Every routing choice (route, emitter, exit code, reason policy, system
message) is in the directive; this module only executes it. The generic hook
and the artifact hook share it: the artifact hook passes ``artifact_reason``,
its reason composed on first use, and its response payload as the envelope.
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
from .commands_support_prompts import (
    _claude_prompt_intercept_message,
    _codex_prompt_block_system_message,
    _copilot_hook_reason,
)
from .commands_support_runtime_policy import (
    _ensure_terminal_punctuation,
    _native_hook_reason,
    _native_hook_reason_for_harness,
)


def directive_exit_code(directive: Mapping[str, object], policy_action: str, *, key: str = "exit_code") -> int:
    """The directive's exit code; grok's depends on its adapter's emit state.

    ``key`` picks the status the branch owns: the JSON document answers before
    the fallback envelope, so a replayed decision relaxes ``exit_code`` to 0
    without touching ``json_exit_code``.
    """

    code = directive[key]
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
    approval_payload: dict[str, object] | None,
    system_message: str | None = None,
) -> None:
    emitter = directive["emitter"]
    if emitter == "grok":
        from ..adapters.grok_hooks import emit_grok_hook_response

        emit_grok_hook_response(
            policy_action=policy_action,
            reason=reason,
            event_name=event_name,
            approval_payload=approval_payload,
            output_stream=output_stream,
        )
    elif emitter == "pi":
        from ..adapters._modules.pi.pi_hooks import emit_pi_hook_response

        emit_pi_hook_response(
            policy_action=policy_action,
            reason=reason,
            approval_payload=payload if approval_payload is None else approval_payload,
            output_stream=output_stream,
        )
    elif emitter == "zcode":
        from ..adapters._modules.zcode.zcode_hooks import emit_zcode_hook_response

        emit_zcode_hook_response(
            policy_action=policy_action,
            reason=reason,
            event_name=event_name,
            payload=payload,
            output_stream=output_stream,
        )
    elif emitter == "devin":
        from ..adapters._modules.devin.devin_hooks import emit_devin_hook_response

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
    envelope: Mapping[str, object],
    harness: str,
    incoming_reason: object,
    remediation: Callable[[], str | None],
) -> str:
    guidance = remediation() if directive["include_remediation"] else None
    mode = directive["codex_native_reason"]
    if mode == "artifact_codex":
        return _native_hook_reason(incoming_reason, approval_context or envelope.get("review_hint"), guidance)
    if mode == "always" or (mode == "with_approval_context" and approval_context is not None):
        return _native_hook_reason(incoming_reason, approval_context, guidance)
    return _native_hook_reason_for_harness(harness, incoming_reason, approval_context, guidance)


def directive_system_message(
    directive: Mapping[str, object],
    *,
    policy_action: str,
    reason: Callable[[], str],
) -> str | None:
    """The system message a directive or review route names, or ``None``."""

    message = directive["system_message"]
    if message == "claude_punctuated":
        return _ensure_terminal_punctuation(reason())
    if message == "codex_prompt":
        return _codex_prompt_block_system_message(policy_action=policy_action, native_reason=reason)
    if message in {"claude_prompt_secret", "claude_prompt_sensitive"}:
        return _claude_prompt_intercept_message(secret=message == "claude_prompt_secret")
    return None


def _exit_block_stderr(directive: Mapping[str, object], code: int) -> bool:
    explicit = directive.get("exit_block_stderr")
    if isinstance(explicit, bool):
        return explicit
    return code != 0 or not directive["stderr_only_on_nonzero_exit"]


def render_generic_hook(
    args: argparse.Namespace,
    *,
    action_envelope: object,
    approval_context: object,
    canonical_harness: str,
    command_text: str | None,
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
    artifact_reason: Callable[[], str] | None = None,
) -> int:
    """Execute the directive's exit-block / native / envelope branch.

    The reason is composed on first use: a branch that shows none never pays
    for it. ``artifact_reason`` marks the artifact hook, whose incoming reason
    is the resident's and whose grok and pi responses read their approval
    links from the response payload (``envelope``).
    """

    harness = str(args.harness)
    as_json = bool(getattr(args, "json", False))
    artifact = artifact_reason is not None
    approval_payload = envelope if artifact else None
    composed: dict[str, str] = {}

    def exit_code() -> int:
        return directive_exit_code(directive, policy_action)

    def json_exit_code() -> int:
        return directive_exit_code(directive, policy_action, key="json_exit_code")

    def reason() -> str:
        if "reason" not in composed:
            composed["reason"] = _reason(
                directive,
                approval_context=approval_context,
                envelope=envelope,
                harness=harness,
                incoming_reason=artifact_reason() if artifact_reason is not None else incoming_reason,
                remediation=remediation,
            )
        return composed["reason"]

    if directive["route"] == "exit_block":
        _emit_adapter(
            directive,
            harness=harness,
            policy_action=policy_action,
            reason=reason(),
            event_name=event_name,
            payload=payload,
            output_stream=output_stream,
            approval_payload=approval_payload,
        )
        code = exit_code()
        if _exit_block_stderr(directive, code):
            # Kimi surfaces stderr to the user as the blocking explanation.
            _emit_native_hook_block_stderr(reason())
        return code
    if directive["terminal_notice"]:
        _emit_native_hook_notification_stderr(
            _claude_native_pretooluse_terminal_notice(payload=dict(payload), reason=reason())
        )
    if directive["try_json_document"]:
        if directive.get("json_reason") == "copilot":
            json_reason = _copilot_hook_reason(
                envelope.get("why_now"), envelope.get("review_hint"), envelope.get("risk_headline")
            )
        else:
            json_reason = reason()
        json_result = _native_hook_json_document(
            args,
            event_name=event_name,
            policy_action=policy_action,
            exit_code=json_exit_code,
            reason=json_reason,
            envelope=envelope,
            system_message=(
                directive_system_message(directive, policy_action=policy_action, reason=reason) if artifact else None
            ),
            generic_path=not artifact,
            native_protocol_payload="hook_event_name" in payload or "event" not in payload,
            command_text=command_text,
            command_surface=getattr(action_envelope, "action_type", None) == "shell_command",
            verified_benign=False if artifact else verified_benign(),
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
        _emit_adapter(
            directive,
            harness=harness,
            policy_action=policy_action,
            reason=reason(),
            event_name=event_name,
            payload=payload,
            output_stream=output_stream,
            approval_payload=approval_payload,
            system_message=(
                directive_system_message(directive, policy_action=policy_action, reason=reason)
                if directive["emitter"] == "default"
                else None
            ),
        )
        return exit_code()
    if after == "post_tool_envelope":
        if not artifact:
            _apply_native_edge_envelope_fields(envelope, native_edge_result)
        _emit_native_post_tool_envelope(
            harness,
            # The directive settled this verdict natively. Reading it back stops
            # the envelope from disagreeing with the exit code and the receipt
            # that came out of that same decision.
            blocking=directive["envelope_decision"] == "block",
            reason=reason() if artifact else coalesce(incoming_reason, reason()) or reason(),
            response_payload=envelope,
            output_stream=output_stream,
            as_json=as_json,
        )
        return exit_code()
    envelope["continue"] = True
    envelope["decision"] = directive["envelope_decision"]
    _emit("hook", envelope, as_json)
    return exit_code()


__all__ = ["directive_exit_code", "directive_system_message", "render_generic_hook"]
