"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# fmt: off
# ruff: noqa: E402, F403, F405, I001

from __future__ import annotations

import logging
import re
import sqlite3
import sys
from collections.abc import Mapping
from typing import TYPE_CHECKING

from .native_hook_exit_code import native_hook_verdict_exit_code


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
    from ._commands_shared import _GUARD_CLIENT_VERSION, _now
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

_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_NON_VERDICT_EVENTS = frozenset({"UserPromptSubmit", "Notification", "PermissionRequest", "PostToolUse"})


def _render_cli(kind: str, harness: str, params: dict[str, object]) -> tuple[str, dict[str, object] | None] | None:
    from ..native_hook_render import native_render_cli

    return native_render_cli(kind, harness, params)


def _fixed_deny(
    harness: str,
    event_name: str,
    policy_action: str,
    reason: str,
    *,
    additional_context: str | None = None,
    system_message: str | None = None,
) -> dict[str, object] | None:
    """The constant document for an outcome the resident could not render.

    A blocking verdict always renders as an explicit block, on every event
    type. A nonblocking outcome carries no verdict and only forwards its own
    notice fields, so nothing here ever authorizes an action.
    """

    if policy_action not in _BLOCKING_ACTIONS:
        notice: dict[str, object] = {}
        if system_message:
            notice["systemMessage"] = system_message
        if additional_context:
            notice["hookSpecificOutput"] = {"hookEventName": event_name, "additionalContext": additional_context}
        return notice or None
    from ..daemon.hook_fail_closed import fail_closed_response

    text = reason or "HOL Guard blocked this action."
    document = fail_closed_response(harness, event_name, reason=text, prompt_reason=reason or None)
    if document and document.get("policy_action") != "allow" and document.get("decision") != "allow":
        return document
    reason_code = str((document or {}).get("reason_code") or "native_hook_render_unavailable")
    return {
        "continue": True,
        "decision": "block",
        "reason": text,
        "policy_action": "block",
        "reason_code": reason_code,
    }


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
    canonical = _canonical_harness_name(harness)
    if canonical == "hermes" and event_name not in _NON_VERDICT_EVENTS:
        from ..adapters.hermes_runtime_hooks import hermes_native_decision

        decision = hermes_native_decision(policy_action=policy_action, reason=reason)
        _write_json_line(decision, output_stream=output_stream)
        return
    params: dict[str, object] = {
        "canonical_harness": canonical,
        "event_name": event_name,
        "policy_action": policy_action,
        "reason": reason,
        "additional_context": additional_context,
        "system_message": system_message,
    }
    rendered = _render_cli("cli_response", harness, params)
    document = (
        rendered[1]
        if rendered is not None
        else _fixed_deny(
            harness,
            event_name,
            policy_action,
            reason,
            additional_context=additional_context,
            system_message=system_message,
        )
    )
    if document:
        _write_json_line(document, output_stream=output_stream)


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
    structured_content_mediation = native_edge_result.get("structured_content_mediation")
    if isinstance(structured_content_mediation, Mapping):
        # The worker already produced the validated mediation contract. Keep
        # it as an opaque adapter projection so the receiver can validate its
        # exact schema, action, and fail-closed fields without inventing
        # native authority here.
        response_payload["structured_content_mediation"] = dict(structured_content_mediation)
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
) -> tuple[dict[str, object] | None, int] | None:
    """Build the --json protocol document for native harnesses.

    Returns ``(document, rc)`` when this call owns the response, ``(None, 0)``
    when the harness contract is silence, and ``None`` when the caller should
    fall back to the generic envelope or adapter emit paths.
    """
    if not getattr(args, "json", False) or event_name == "PostToolUse":
        return None
    canonical = _canonical_harness_name(args.harness)
    if canonical not in {"copilot", "claude-code", "codex"}:
        return None
    params: dict[str, object] = {
        "canonical_harness": canonical,
        "event_name": event_name,
        "policy_action": policy_action,
        "reason": reason,
        "system_message": system_message,
        "envelope": dict(envelope) if isinstance(envelope, Mapping) else None,
        "generic_path": generic_path,
        "native_protocol_payload": native_protocol_payload,
        "content_flagged": content_flagged,
        "command_surface": command_surface,
        "verified_benign": verified_benign,
    }
    rendered = _render_cli("cli_document", args.harness, params)
    exit_code = native_hook_verdict_exit_code(canonical, policy_action, event_name)
    if rendered is None:
        denied = _fixed_deny(args.harness, event_name, policy_action, reason)
        return (denied, exit_code) if denied is not None else None
    outcome, document = rendered
    if outcome == "fallback":
        return None
    return (document if outcome == "document" else None), exit_code


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


def _daemon_failure_reason(error: RuntimeError) -> str:
    """Preserve the daemon-failure category and, when present, its message."""
    message = str(error)
    if message:
        return f"{type(error).__name__}: {message}"
    return type(error).__name__

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

        def apply_delivery_and_wait(payload, queued, *, complete=True):
            """Attach delivery copy and either record the pending wait or block on approvals.

            Returns the wait result, or None when no wait was performed. An
            incomplete queue never waits: approving the requests that were
            written must not resume a launch whose other findings have none.
            """
            payload["approval_delivery"] = _approval_delivery_payload(args.harness, managed_install=managed_install)
            _localize_pending_approval_copy(payload, harness=args.harness)
            if str(approval_flow["tier"]) != "native-or-center" or not should_wait_for_approvals or not complete:
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
            try:
                queued = queue_blocked_approvals(
                    redaction_level=config.receipt_redaction_level,
                    detection=detection,
                    evaluation=payload,
                    store=store,
                    approval_center_url=approval_center_url,
                    now=_now(),
                )
            except (sqlite3.Error, OSError) as queue_error:
                # A fatal store/IO error (e.g. a quarantined SQLite store) must
                # not abort the deny path: still emit an explicit, empty approval
                # queue so callers always find the key and the action stays
                # blocked pending manual resolution. Programming errors
                # (TypeError/ValueError/AttributeError) still propagate.
                logging.getLogger(__name__).warning(
                    "Guard approval queue unavailable: %s", queue_error, exc_info=True
                )
                queued = approvals_queued_before(queue_error)
                payload["approval_queue_unavailable"] = type(queue_error).__name__
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
            wait_result = apply_delivery_and_wait(
                payload, queued, complete="approval_queue_unavailable" not in payload
            )
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
        except RuntimeError as daemon_load_error:
            # Preserve the daemon-failure category and message through the
            # local-queue fallback so the unresolved launch-validation reason
            # is evidence, not a silently absorbed error.
            payload["daemon_queue_unavailable"] = _daemon_failure_reason(daemon_load_error)
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
        except RuntimeError as daemon_operation_error:
            payload["daemon_queue_unavailable"] = _daemon_failure_reason(daemon_operation_error)
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
    guard_home: Path | None = None,
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
        guard_home=guard_home,
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
    "_native_hook_json_document", "_normalize_hook_argument_value",
    "_normalize_hook_arguments",
    "_normalize_hook_payload", "_open_approval_center", "_public_approval_center_url",
]
