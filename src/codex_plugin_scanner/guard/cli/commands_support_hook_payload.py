"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# fmt: off
# ruff: noqa: E402, F403, F405, I001

from __future__ import annotations

import re
import sys
from collections.abc import Mapping
from typing import TYPE_CHECKING


def _coalesce_string(*values: object | None) -> str:
    """Return the first non-empty display value during circular CLI imports."""

    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown-artifact"


def _canonical_harness_name(value: str) -> str:
    """Resolve harness aliases lazily to avoid the CLI support import cycle."""

    from .commands_support_runtime_resolution import (
        _canonical_harness_name as resolve_canonical_harness_name,
    )

    return resolve_canonical_harness_name(value)


def _managed_install_for(store: GuardStore, harness: str) -> dict[str, object] | None:
    """Resolve managed-install state lazily to avoid the CLI support import cycle."""

    from .commands_support_runtime_resolution import _managed_install_for as resolve_managed_install_for

    return resolve_managed_install_for(store, harness)


def _hook_event_name(payload: dict[str, object]) -> str | None:
    """Read hook event names lazily to avoid the CLI support import cycle."""

    from .commands_support_runtime_artifacts import _hook_event_name as resolve_hook_event_name

    return resolve_hook_event_name(payload)


_ENCODED_CONTENT_MARKER_PATTERN = re.compile(
    r"\b(?:base64|b64decode|frombase64string|encodedcommand|openssl|gpg|xxd)\b"
    r"|\bencoded\b"
    r"|\b(?:ba|da|z|a)?sh\s+-\w*s\b",
    re.IGNORECASE,
)


def _hook_command_has_encoded_markers(command_text: str | None) -> bool:
    """Whether a command text carries encoded-execution-looking markers.

    Presentation-only signal: encoded-adjacent content is worth surfacing in the
    structured decision document even when the action is verified inert and
    allowed. It is deliberately lighter than the policy detector, which is
    tuned to avoid false positives on quoted literals and stdin-mode scripts.
    """
    return isinstance(command_text, str) and bool(_ENCODED_CONTENT_MARKER_PATTERN.search(command_text))


def _write_json_line(payload: dict[str, object], *, output_stream: TextIO | None = None) -> None:
    """Resolve hook output lazily without reintroducing the prompt import cycle."""

    from .commands_support_prompts import _write_json_line as resolve_write_json_line

    resolve_write_json_line(payload, output_stream=output_stream)

if TYPE_CHECKING:
    from ..store import GuardStore
    from ._commands_shared import _GUARD_CLIENT_VERSION, _HOOK_DAEMON_UNREACHABLE_REASON_MARKER, _now
    from .commands_support_interaction import _attach_primary_approval_link, _preferred_approval_review_url
    from .commands_support_runtime_policy import _approval_delivery_payload, _localize_pending_approval_copy


from ._commands_shared import *
from .commands_parser_helpers import *
from ..browser_opener import open_browser_url
from .commands_support_hook_payload_loader import (
    _first_hook_tool_call,
    _load_hook_payload as _load_hook_payload_impl,
    _normalize_hook_argument_value,
    _normalize_hook_arguments,
    _normalize_hook_payload,
)


def _load_hook_payload(
    event_file: str | None,
    *,
    input_text: str | None = None,
    harness: str | None = None,
    normalize: bool = True,
) -> dict[str, object]:
    """Keep the legacy CLI facade while the loader owns raw input handling."""

    payload = _load_hook_payload_impl(
        event_file,
        input_text=input_text,
        harness=harness,
        normalize=False,
    )
    return payload

def _emit_native_hook_response(
    *,
    harness: str,
    policy_action: str,
    reason: str,
    event_name: str = "PreToolUse",
    additional_context: str | None = None,
    system_message: str | None = None,
    output_stream: TextIO | None = None,
) -> None:
    payload: dict[str, object] = {}
    if isinstance(system_message, str) and system_message.strip():
        payload["systemMessage"] = system_message.strip()
    if event_name == "UserPromptSubmit":
        if policy_action in {"review", "require-reapproval", "sandbox-required", "block"} and not additional_context:
            payload["decision"] = "block"
            payload["reason"] = reason
            if _canonical_harness_name(harness) == "codex":
                payload["continue"] = False
                payload["stopReason"] = reason
                payload["hookSpecificOutput"] = {
                    "hookEventName": event_name,
                    "additionalContext": reason,
                }
        elif additional_context:
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "additionalContext": additional_context,
            }
        elif _canonical_harness_name(harness) in {"claude-code", "codex"}:
            payload["hookSpecificOutput"] = {"hookEventName": event_name}
        if payload:
            _write_json_line(payload, output_stream=output_stream)
        return
    if event_name in {"Notification", "PermissionRequest"}:
        if event_name == "PermissionRequest" and policy_action in {"block", "sandbox-required"}:
            decision: dict[str, object] = {
                "behavior": "deny",
                "message": additional_context or reason,
            }
            if _canonical_harness_name(harness) != "codex":
                decision["interrupt"] = False
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "decision": decision,
            }
            _write_json_line(payload, output_stream=output_stream)
            return
        if event_name == "PermissionRequest" and _canonical_harness_name(harness) == "codex":
            if policy_action in {"review", "require-reapproval"}:
                payload["systemMessage"] = (
                    "HOL Guard is reviewing this Codex approval request. Codex will show its normal approval prompt; "
                    "choose allow only if you trust the exact tool action."
                )
            if payload:
                _write_json_line(payload, output_stream=output_stream)
            return
        if event_name == "PermissionRequest" and _canonical_harness_name(harness) == "claude-code":
            message = system_message or reason
            if message:
                payload["systemMessage"] = message
            if additional_context:
                payload["hookSpecificOutput"] = {
                    "hookEventName": event_name,
                    "additionalContext": additional_context,
                }
            elif message:
                payload["hookSpecificOutput"] = {"hookEventName": event_name}
            if payload:
                _write_json_line(payload, output_stream=output_stream)
            return
        if additional_context:
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "additionalContext": additional_context,
            }
        if payload:
            _write_json_line(payload, output_stream=output_stream)
        return
    if event_name == "PostToolUse":
        if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
            payload.update({"decision": "block", "reason": reason, "continue": True, "stopReason": reason})
        else:
            payload["continue"] = True
            payload["policy_action"] = policy_action
            permission_decision = _native_hook_permission_decision(policy_action, harness=harness)
            if permission_decision is not None:
                hook_output: dict[str, object] = {
                    "hookEventName": event_name,
                    "permissionDecision": permission_decision,
                }
                if permission_decision != "allow" or _HOOK_DAEMON_UNREACHABLE_REASON_MARKER in reason.lower():
                    hook_output["permissionDecisionReason"] = reason
                payload["hookSpecificOutput"] = hook_output
        _write_json_line(payload, output_stream=output_stream)
        return
    permission_decision = _native_hook_permission_decision(policy_action, harness=harness)
    if harness == "codex" and event_name == "PreToolUse" and permission_decision is None:
        return
    hook_specific_output: dict[str, object] = {"hookEventName": event_name}
    if permission_decision is not None:
        hook_specific_output["permissionDecision"] = permission_decision
        if permission_decision != "allow" or _HOOK_DAEMON_UNREACHABLE_REASON_MARKER in reason.lower():
            hook_specific_output["permissionDecisionReason"] = reason
    payload["hookSpecificOutput"] = hook_specific_output
    _write_json_line(
        _hermes_native_or_payload(harness, policy_action, reason, payload),
        output_stream=output_stream,
    )

def _hermes_native_or_payload(
    harness: str,
    policy_action: str,
    reason: str,
    payload: dict[str, object],
) -> dict[str, object]:
    if _canonical_harness_name(harness) != "hermes":
        return payload
    from ..adapters.hermes_runtime_hooks import hermes_native_decision
    return hermes_native_decision(policy_action=policy_action, reason=reason)


def _apply_native_edge_envelope_fields(
    response_payload: dict[str, object],
    native_edge_result: Mapping[str, object] | None,
    *,
    project_decision: bool = True,
) -> None:
    """Project the raw native edge decision onto the emitted envelope.

    The edge stays the authority for the output mask; these fields are
    provenance for harness bridges (cline's managed plugin replaces the
    model-visible result from ``model_output_action`` and the digest proof).
    """
    if not isinstance(native_edge_result, Mapping):
        return
    edge_decision = native_edge_result.get("decision")
    if isinstance(edge_decision, str) and edge_decision.strip():
        response_payload["native_edge_decision"] = edge_decision
        if project_decision:
            response_payload["decision"] = "block" if edge_decision == "deny" else "allow"
    for source_key, target_key in (
        ("reason", "native_edge_reason"),
        ("reason_code", "native_edge_reason_code"),
        ("reason_code", "reason_code"),
        ("model_output_action", "model_output_action"),
        ("reviewed_output_sha256", "reviewed_output_sha256"),
        ("reviewed_excerpt", "reviewed_excerpt"),
        ("notice", "notice"),
    ):
        value = native_edge_result.get(source_key)
        if isinstance(value, str) and value.strip():
            response_payload[target_key] = value


_GUARD_TOKEN_URL_VALUE = re.compile(r"guard-token=([A-Za-z0-9._~%+-]+)")
_GUARD_TOKEN_SENTINEL = re.compile(r"hgdfrag=efgh(\d+)")


def _protect_ephemeral_approval_tokens(value: object, tokens: list[str]) -> object:
    """Swap signed dashboard-session fragments for a redaction-safe sentinel."""
    if isinstance(value, str):
        def _replace(match: re.Match[str]) -> str:
            tokens.append(match.group(1))
            return f"hgdfrag=efgh{len(tokens) - 1}"

        return _GUARD_TOKEN_URL_VALUE.sub(_replace, value)
    if isinstance(value, dict):
        return {key: _protect_ephemeral_approval_tokens(item, tokens) for key, item in value.items()}
    if isinstance(value, list):
        return [_protect_ephemeral_approval_tokens(item, tokens) for item in value]
    return value


def _restore_ephemeral_approval_tokens(value: object, tokens: list[str]) -> object:
    """Restore the deliberately user-facing signed approval link after redaction."""
    if isinstance(value, str):
        if "hgdfrag=efgh" in value:
            def _replace(match: re.Match[str]) -> str:
                index = int(match.group(1))
                return f"guard-token={tokens[index]}" if index < len(tokens) else match.group(0)

            return _GUARD_TOKEN_SENTINEL.sub(_replace, value)
        return value
    if isinstance(value, dict):
        return {key: _restore_ephemeral_approval_tokens(item, tokens) for key, item in value.items()}
    if isinstance(value, list):
        return [_restore_ephemeral_approval_tokens(item, tokens) for item in value]
    return value


def _emit_native_post_tool_envelope(
    harness: str,
    *,
    policy_action: str,
    reason: str,
    response_payload: dict[str, object],
    output_stream: TextIO | None = None,
    as_json: bool = False,
) -> None:
    """Emit a PostToolUse outcome; the action already ran so it never pauses."""
    blocking = policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    edge_masked = (
        response_payload.get("native_edge_decision") == "deny"
        or response_payload.get("model_output_action") == "block"
    )
    response_payload["continue"] = True
    # ``decision`` mirrors the composed policy outcome for the bridge surface;
    # ``native_edge_decision`` keeps the raw edge mask verdict as provenance.
    response_payload["decision"] = "block" if (blocking or edge_masked) else "allow"
    if blocking or edge_masked:
        # PostToolUse never stops the session, but a flagged outcome still
        # carries the native block surface so harness bridges mask the output
        # and surface the approval link alongside the queued requests.
        stop_reason = reason if blocking else _coalesce_string(
            response_payload.get("native_edge_reason"), reason
        )
        response_payload.setdefault("reason", stop_reason)
        response_payload["stopReason"] = stop_reason
    if as_json:
        # The protocol surface is written by harnesses, so it carries the
        # ephemeral signed approval link verbatim; everything else still goes
        # through the shared redactor.
        from .render import _redact_payload, _render_redacted_json_payload

        tokens: list[str] = []
        protected = _protect_ephemeral_approval_tokens(response_payload, tokens)
        masked = _redact_payload(protected, command="hook")
        restored = _restore_ephemeral_approval_tokens(masked, tokens)
        # stdout is the harness delivery channel; the ephemeral approval
        # link must reach the operator intact. An explicit output stream (used
        # by in-process callers such as _run_guard_hook_command) takes
        # precedence over process stdout.
        stream = output_stream if output_stream is not None else sys.stdout
        stream.write(_render_redacted_json_payload(restored))  # codeql[py/clear-text-logging-sensitive-data]
        stream.write("\n")
        return
    from .render import emit_guard_payload

    emit_guard_payload("hook", response_payload, as_json)


def _native_hook_json_document(
    args: argparse.Namespace,
    *,
    event_name: str,
    policy_action: str,
    reason: str,
    envelope: Mapping[str, object] | None,
    system_message: str | None = None,
    generic_path: bool = False,
    native_protocol_payload: bool = False,
    content_flagged: bool = False,
    command_surface: bool = False,
    verified_benign: bool = False,
    replayed_decision: bool = False,
    envelope_keyed: bool = False,
    fail_closed_native_floor: bool = False,
) -> tuple[dict[str, object] | None, int] | None:
    """Build the --json protocol document for native harnesses.

    Returns ``(document, rc)`` when this call owns the response, ``(None, 0)``
    when the harness contract is silence, and ``None`` when the caller should
    fall back to the generic envelope or adapter emit paths. The envelope is
    merged into the protocol document so callers keep policy/evidence fields
    alongside the harness-facing decision keys.
    """
    if not getattr(args, "json", False) or event_name == "PostToolUse":
        return None
    canonical = _canonical_harness_name(args.harness)
    blocking = policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    terminal = policy_action in {"block", "sandbox-required"}
    base = dict(envelope) if isinstance(envelope, Mapping) else {}
    scanner_evidence = base.get("scanner_evidence")
    # The generic path always records the baseline pair (approval reuse +
    # policy composition); only additional *decisional* scanner evidence
    # warrants the merged evidence-bearing document on the wire. Benign-verified
    # payloads may still carry audit entries: ignored untrusted hints, relaxed
    # configured defaults, and embedded-script audit indexes are not flags.
    def _decisional_evidence(entry: object) -> bool:
        if not isinstance(entry, Mapping):
            return True
        source = entry.get("source")
        if source in {"approval_reuse", "policy_composition", "embedded_script"}:
            return False
        if source == "hook_payload_trust" and entry.get("status") == "ignored":
            return False
        if source == "configured_default" and entry.get("status") == "relaxed_verified_benign":
            return False
        return not (source == "trusted_local_tool" and entry.get("eligible") is True)

    has_extra_evidence = isinstance(scanner_evidence, list) and any(
        _decisional_evidence(entry) for entry in scanner_evidence
    )
    # Verified-benign relaxations mark the composed warn as a safe fast path:
    # the configured default was relaxed or a trusted local tool qualified.
    has_benign_evidence = isinstance(scanner_evidence, list) and any(
        isinstance(entry, Mapping)
        and (
            (entry.get("source") == "configured_default" and entry.get("status") == "relaxed_verified_benign")
            or (entry.get("source") == "trusted_local_tool" and entry.get("eligible") is True)
        )
        for entry in scanner_evidence
    )

    if canonical == "copilot":
        if event_name != "PreToolUse":
            return None
        if not blocking:
            if (
                generic_path
                and not content_flagged
                and (policy_action == "allow" or not has_extra_evidence)
            ):
                return {"permissionDecision": "allow"}, 0
            base["continue"] = True
            base["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "permissionDecision": "allow",
            }
            return base, 0
        base["continue"] = True
        base["hookSpecificOutput"] = {
            "hookEventName": event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
        return base, 1

    if canonical not in {"claude-code", "codex"}:
        return None

    if event_name == "UserPromptSubmit":
        if not blocking:
            base["hookSpecificOutput"] = {"hookEventName": event_name}
            return base, 0
        if canonical == "codex":
            # Codex prompt payloads must never echo the submitted prompt back;
            # emit the protocol document only, carrying the composed action and
            # the edge reason code as provenance.
            doc: dict[str, object] = {
                "decision": "block",
                "reason": reason,
                "policy_action": policy_action,
                "continue": False,
                "stopReason": reason,
                "hookSpecificOutput": {
                    "hookEventName": event_name,
                    "additionalContext": reason,
                },
            }
            edge_reason_code = base.get("reason_code") or base.get("native_edge_reason_code")
            if isinstance(edge_reason_code, str) and edge_reason_code.strip():
                doc["reason_code"] = edge_reason_code
            if isinstance(system_message, str) and system_message.strip():
                doc["systemMessage"] = system_message.strip()
            return doc, 0
        base["decision"] = "block"
        base["reason"] = reason
        base["continue"] = True
        if terminal and not generic_path:
            if isinstance(system_message, str) and system_message.strip():
                base["systemMessage"] = system_message.strip()
            return base, 0
        return base, 1

    if (
        canonical == "codex"
        and event_name == "PreToolUse"
        and native_protocol_payload
        and generic_path
        and command_surface
        and not blocking
        and (policy_action == "allow" or has_benign_evidence or verified_benign)
        and _native_hook_permission_decision(policy_action, harness=args.harness) is None
    ):
        return None, 0

    base["continue"] = True
    if isinstance(system_message, str) and system_message.strip():
        base["systemMessage"] = system_message.strip()
    hook_specific_output: dict[str, object] = {"hookEventName": event_name}
    if event_name == "PermissionRequest":
        if terminal:
            hook_specific_output["decision"] = {"behavior": "deny", "message": reason}
        elif canonical == "claude-code":
            if isinstance(system_message, str) and system_message.strip():
                base["systemMessage"] = system_message.strip()
        elif policy_action in {"review", "require-reapproval"}:
            base["systemMessage"] = (
                "HOL Guard is reviewing this Codex approval request. Codex will show its normal approval prompt; "
                "choose allow only if you trust the exact tool action."
            )
        else:
            return None, 0
        base["hookSpecificOutput"] = hook_specific_output
        return base, 0
    if blocking:
        base["decision"] = "block"
        base["reason"] = reason
    permission_decision = _native_hook_permission_decision(policy_action, harness=args.harness)
    if (
        permission_decision is None
        and canonical == "codex"
        and event_name == "PreToolUse"
        and not blocking
    ):
        permission_decision = "allow"
    if permission_decision is not None:
        hook_specific_output["permissionDecision"] = permission_decision
        if (
            permission_decision != "allow"
            or policy_action == "warn"
            or _HOOK_DAEMON_UNREACHABLE_REASON_MARKER in reason.lower()
        ):
            hook_specific_output["permissionDecisionReason"] = reason
    base["hookSpecificOutput"] = hook_specific_output
    # Codex reads its decision from the hookSpecificOutput document, so
    # reviews and denials exit cleanly; nonzero is reserved for cases where
    # the decision must travel the machine envelope instead: sandbox
    # escalations, fail-closed native floors where the command evaluator
    # could not prove the request, legacy `event`-keyed payloads that never
    # normalized to the native protocol, and blocking decisions a package
    # evaluation contributed to (queued approvals and advisory context live
    # in the envelope, not the protocol decision). Claude Code keeps the
    # envelope contract for every blocking action: the merged document
    # carries the approval and evaluation fields its --json callers read.
    if canonical == "codex":
        policy_composition = base.get("policy_composition")
        package_evaluated = (
            isinstance(policy_composition, Mapping)
            and policy_composition.get("package_action") is not None
        )
        envelope_rc = (
            policy_action == "sandbox-required"
            or fail_closed_native_floor
            or (envelope_keyed and not native_protocol_payload)
            or package_evaluated
        )
    else:
        envelope_rc = True
    return base, 1 if blocking and envelope_rc and not replayed_decision else 0


def _emit_native_hook_json_document(
    payload: dict[str, object],
    *,
    compact: bool = False,
    output_stream: TextIO | None = None,
) -> None:
    """Write a native protocol document, redacting everything except the
    ephemeral signed approval link that the operator is meant to click."""
    from .render import _redact_payload, _render_redacted_json_payload

    tokens: list[str] = []
    protected = _protect_ephemeral_approval_tokens(payload, tokens)
    masked = _redact_payload(protected, command="hook")
    restored = _restore_ephemeral_approval_tokens(masked, tokens)
    rendered = (
        json.dumps(restored, separators=(",", ":"))
        if compact
        else _render_redacted_json_payload(restored)
    )
    if output_stream is None:
        # stdout is the harness delivery channel; the ephemeral approval
        # link must reach the operator intact.
        sys.stdout.write(rendered)  # codeql[py/clear-text-logging-sensitive-data]
        sys.stdout.write("\n")
    else:
        output_stream.write(rendered)  # codeql[py/clear-text-logging-sensitive-data]
        output_stream.write("\n")


def _emit_native_hook_block_stderr(reason: str) -> None:
    # stderr is the harness notice channel; the reason may carry the
    # ephemeral approval link the operator needs.
    print(reason, file=sys.stderr)  # codeql[py/clear-text-logging-sensitive-data]

def _emit_native_hook_notification_stderr(reason: str) -> None:
    # stderr is the harness notice channel; the reason may carry the
    # ephemeral approval link the operator needs.
    print(reason, file=sys.stderr)  # codeql[py/clear-text-logging-sensitive-data]

def _native_hook_permission_decision(policy_action: str, *, harness: str) -> str | None:
    canonical = _canonical_harness_name(harness)
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action in {"review", "require-reapproval"}:
        # zcode routes ask to its native permission prompt instead of denying.
        if canonical in {"codex", "kimi", "grok", "devin"}:
            return "deny"
        return "ask"
    if canonical == "codex":
        return None
    return "allow"

def _copilot_hook_permission_decision(policy_action: str) -> str:
    if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
        return "deny"
    return "allow"


def _object_list(value: object | None) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def _mapping_list(value: object | None) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]

def _headless_approval_resolver(
    *,
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config,
):
    should_wait_for_approvals = not bool(getattr(args, "json", False))

    def resolve(detection, payload):
        if evaluation_has_terminal_policy_action(payload):
            return payload
        managed_install = _managed_install_for(store, args.harness)
        approval_flow = approval_prompt_flow(args.harness, managed_install=managed_install)
        approval_center_url = schedule_guard_daemon_ensure(
            context.guard_home,
            home_dir=context.home_dir,
        )

        def apply_delivery_and_wait(payload, queued):
            """Attach delivery copy and either record the pending wait or block on approvals.

            Returns the wait result, or None when no wait was performed.
            """
            payload["approval_delivery"] = _approval_delivery_payload(args.harness, managed_install=managed_install)
            _localize_pending_approval_copy(payload, harness=args.harness)
            if str(approval_flow["tier"]) != "native-or-center" or not should_wait_for_approvals:
                payload["approval_wait"] = {
                    "resolved": False,
                    "pending_request_ids": [str(item["request_id"]) for item in queued if "request_id" in item],
                    "items": [],
                }
                return None
            wait_result = wait_for_approval_requests(
                store=store,
                request_ids=[str(item["request_id"]) for item in queued if "request_id" in item],
                timeout_seconds=config.approval_wait_timeout_seconds,
            )
            payload["approval_wait"] = wait_result
            return wait_result

        def resolve_from_local_queue():
            queued = queue_blocked_approvals(
                redaction_level=config.receipt_redaction_level,
                detection=detection,
                evaluation=payload,
                store=store,
                approval_center_url=approval_center_url,
                now=_now(),
            )
            payload["approval_requests"] = queued
            _attach_primary_approval_link(
                payload,
                harness=args.harness,
                approval_center_url=approval_center_url,
            )
            payload["approval_center_url"] = approval_center_url
            payload["review_hint"] = approval_center_hint(
                context=context,
                harness=args.harness,
                approval_center_url=approval_center_url,
                queued=queued,
                review_url=_preferred_approval_review_url(payload, harness=args.harness),
            )
            wait_result = apply_delivery_and_wait(payload, queued)
            if wait_result is None:
                return payload
            if bool(wait_result.get("resolved")):
                resolved_items = _mapping_list(wait_result.get("items"))
                payload["blocked"] = any(str(item.get("resolution_action")) == "block" for item in resolved_items)
                if not payload["blocked"]:
                    payload["blocked"] = False
                    payload["review_hint"] = "Approval received. Guard is resuming the harness launch."
            else:
                pending_request_ids = _object_list(wait_result.get("pending_request_ids"))
                payload["review_hint"] = (
                    f"Approval is still pending in the Guard approval center at {approval_center_url}. Resolve request "
                    f"{', '.join(str(item) for item in pending_request_ids)}."
                )
            return payload

        try:
            daemon_client = load_guard_surface_daemon_client(context.guard_home)
        except RuntimeError:
            return resolve_from_local_queue()
        try:
            session = daemon_client.start_session(
                harness=args.harness,
                surface="cli",
                workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
                client_name="hol-guard",
                client_title="HOL Guard CLI",
                client_version=_GUARD_CLIENT_VERSION,
                capabilities=["approval-resolution", "receipt-view"],
            )
            blocked_operation = daemon_client.queue_blocked_operation(
                session_id=str(session["session_id"]),
                operation_type="run",
                harness=args.harness,
                metadata={"command": f"hol-guard run {args.harness}"},
                detection=detection.to_dict(),
                evaluation=payload,
                approval_center_url=approval_center_url,
                approval_surface_policy=_approval_surface_policy_for_flow(
                    config.approval_surface_policy,
                    approval_flow,
                ),
                open_key=None,
                redaction_level=config.receipt_redaction_level,
            )
        except RuntimeError:
            return resolve_from_local_queue()
        operation = blocked_operation["operation"] if isinstance(blocked_operation.get("operation"), dict) else {}
        queued = (
            blocked_operation["approval_requests"]
            if isinstance(blocked_operation.get("approval_requests"), list)
            else []
        )
        payload["session_id"] = str(session["session_id"])
        payload["operation_id"] = str(operation["operation_id"])
        payload["approval_requests"] = queued
        _attach_primary_approval_link(
            payload,
            harness=args.harness,
            approval_center_url=approval_center_url,
        )
        payload["approval_center_url"] = approval_center_url
        payload["review_hint"] = approval_center_hint(
            context=context,
            harness=args.harness,
            approval_center_url=approval_center_url,
            queued=queued,
            managed_install=managed_install,
            review_url=_preferred_approval_review_url(payload, harness=args.harness),
        )
        wait_result = apply_delivery_and_wait(payload, queued)
        if wait_result is None:
            return payload
        if bool(wait_result.get("resolved")):
            resolved_items = _mapping_list(wait_result.get("items"))
            payload["blocked"] = any(str(item.get("resolution_action")) == "block" for item in resolved_items)
            if not payload["blocked"]:
                payload["blocked"] = False
                with suppress(RuntimeError):
                    daemon_client.update_operation_status(
                        operation_id=str(operation["operation_id"]),
                        status="completed",
                    )
                payload["review_hint"] = "Approval received. Guard is resuming the harness launch."
            else:
                with suppress(RuntimeError):
                    daemon_client.update_operation_status(
                        operation_id=str(operation["operation_id"]),
                        status="blocked",
                    )
        else:
            pending_request_ids = _object_list(wait_result.get("pending_request_ids"))
            with suppress(RuntimeError):
                daemon_client.update_operation_status(
                    operation_id=str(operation["operation_id"]),
                    status="waiting_on_approval",
                    approval_request_ids=[str(item["request_id"]) for item in queued if "request_id" in item],
                )
            payload["review_hint"] = (
                f"Approval is still pending in the Guard approval center at {approval_center_url}. Resolve request "
                f"{', '.join(str(item) for item in pending_request_ids)}."
            )
        return payload

    return resolve

def _open_approval_center(
    approval_center_url: str,
    *,
    store: GuardStore,
    config: GuardConfig,
    open_key: str | None = None,
    force_open: bool = False,
) -> dict[str, object]:
    surface_runtime = GuardSurfaceRuntime(store)
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    browser_url = _approval_center_browser_url(approval_center_url, auth_token)
    open_result = surface_runtime.ensure_surface(
        surface="approval-center",
        approval_center_url=approval_center_url,
        browser_url=browser_url,
        approval_surface_policy=config.approval_surface_policy,
        open_key=open_key or approval_center_url,
        force_open=force_open,
        opener=open_browser_url,
    )
    open_result["browser_url"] = _public_approval_center_url(browser_url) or approval_center_url
    return open_result

def _approval_center_browser_url(approval_center_url: str, auth_token: str | None) -> str | None:
    if auth_token is None:
        return None
    return _browser_url_with_guard_params(approval_center_url, auth_token=auth_token, surface="approval-center")

def _browser_url_with_guard_params(
    url: str,
    *,
    auth_token: str,
    surface: str,
    daemon_url: str | None = None,
) -> str:
    parsed = urllib.parse.urlparse(url)
    fragment_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key not in {"guard-token", "guardDaemon"}
    ]
    if daemon_url:
        fragment_pairs.append(("guardDaemon", daemon_url))
    fragment_pairs.append(
        (
            "guard-token",
            build_local_dashboard_session_token(auth_token=auth_token, surface=surface),
        )
    )
    return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.urlencode(fragment_pairs)))

def _public_approval_center_url(browser_url: str | None) -> str | None:
    if browser_url is None:
        return None
    parsed = urllib.parse.urlparse(browser_url)
    fragment_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key != "guard-token"
    ]
    return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.urlencode(fragment_pairs)))

def _approval_surface_policy_for_flow(config_policy: str, approval_flow: dict[str, object]) -> str:
    if approval_flow.get("tier") != "approval-center":
        return "notify-only"
    if approval_flow.get("auto_open_browser") is False:
        return "never-auto-open"
    return config_policy

_ACTION_ENVELOPE_HARNESSES = frozenset(
    {
        "codex", "cline", "claude-code", "opencode", "copilot", "gemini", "hermes",
        "openclaw", "cursor", "grok", "kimi", "pi", "omp", "zcode", "devin",
    }
)

def _hook_action_envelope(
    *,
    harness: str,
    payload: dict[str, object],
    home_dir: Path,
    workspace: Path | None,
) -> GuardActionEnvelope | None:
    canonical_harness = _canonical_harness_name(harness)
    if canonical_harness not in _ACTION_ENVELOPE_HARNESSES:
        return None
    return normalize_harness_payload(
        canonical_harness,
        _hook_event_name(payload) or "PreToolUse",
        payload,
        workspace=workspace,
        home_dir=home_dir,
    )

def _action_envelope_json(envelope: GuardActionEnvelope | None) -> dict[str, object] | None:
    return envelope.to_dict() if envelope is not None else None

__all__ = [
    "_ACTION_ENVELOPE_HARNESSES", "_action_envelope_json", "_apply_native_edge_envelope_fields",
    "_approval_center_browser_url",
    "_approval_surface_policy_for_flow", "_browser_url_with_guard_params", "_coalesce_string",
    "_copilot_hook_permission_decision", "_emit_native_hook_block_stderr",
    "_emit_native_hook_json_document", "_emit_native_hook_notification_stderr",
    "_emit_native_hook_response", "_emit_native_post_tool_envelope", "_first_hook_tool_call",
    "_headless_approval_resolver", "_hook_action_envelope", "_hook_command_has_encoded_markers",
    "_load_hook_payload",
    "_native_hook_json_document", "_native_hook_permission_decision", "_normalize_hook_argument_value",
    "_normalize_hook_arguments",
    "_normalize_hook_payload", "_open_approval_center", "_public_approval_center_url",
]
