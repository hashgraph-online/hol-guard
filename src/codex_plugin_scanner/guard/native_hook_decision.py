"""Generic-hook decisions answered by the native runtime.

The hook transport gathers facts (payload fields, store lookups, classifier
verdicts) and renders host output. The resident decides everything between:
event and action normalization, composition of the current action, which
grant lookups are permitted, the final action after approval reuse and Watch
mode, receipt and activity dispositions, and the response directive. It also
settles Copilot tool calls and names the effects the transport runs, picks how
the artifact hook renders its settled verdict, and routes its review-tier
verdicts. There is
no Python evaluator: a reply that is not a bound, strictly decoded ``ok``
raises ``NativeHookDecisionError`` and callers fail closed.
"""

from __future__ import annotations

import dataclasses
import functools
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .native_execution import _resident_request
from .native_resident_decision import ResidentOperation, resident_decide, shape_fields
from .runtime.approval_reuse import ApprovalReuseMalformedResultError, _decision_from_native_payload

HOOK_DECISION_FEATURE = "hook-decision-v1"
# The composed post-claim request names the claimed approval's context token
# and expects the reuse decision back.  A resident that predates it rejects
# those fields as unknown, and the claim it would have re-evaluated is already
# consumed by then, so the capability is demanded before the request is sent.
HOOK_DECISION_POST_CLAIM_COMPOSE_FEATURE = "hook-decision-post-claim-compose-v1"
# The artifact hook's response directive; a resident that predates it rejects
# the query, so the capability is demanded first.
HOOK_DECISION_ARTIFACT_DIRECTIVE_FEATURE = "hook-decision-artifact-directive-v1"
# What a Claude-native approval saves; a resident that predates it rejects the
# query, so the capability is demanded first and nothing is saved without it.
HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE = "hook-decision-native-permission-persist-plan-v1"
# The route a reviewed artifact verdict takes; demanded first for the same reason.
HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE = "hook-decision-artifact-review-route-v1"
# A directive names the status the JSON document itself exits with. A resident
# that predates the field omits it, and a directive is decoded by its exact key
# set, so an older resident still answering after an upgrade would have every
# reply rejected and every hook decision would fail closed until it is retired.
# Demanding the capability replaces that resident instead.
HOOK_DECISION_JSON_EXIT_CODE_FEATURE = "hook-decision-json-exit-code-v1"
# A composed, settled or finalized edge names the reason the edge result reached
# its action. The edge denies unknown fields, so a resident that predates the
# field rejects every request that carries one and the hook fails closed as
# unavailable until that resident retires. Demanding the capability replaces it.
# It ships with the exit code above, so demanding it demands both.
HOOK_DECISION_NATIVE_EDGE_REASON_FEATURE = "hook-decision-native-edge-reason-v1"
_UNAVAILABLE = "native_hook_decision_unavailable"
_INVALID = "native_hook_decision_payload_invalid"
_TIMEOUT_SECONDS = 5.0
_MAX_FACT_ROUNDS = 12
_MAX_REQUEST_BYTES = 6 * 1024 * 1024

_ACTION_NAMES = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_OPT_STR = (str, type(None))
_COMPOSITION_FIELDS: dict[str, Any] = {
    "event_name": _OPT_STR,
    "effective_event_name": str,
    "composed_action": str,
    "grant_lookups_allowed": bool,
    "tool_eligibility_needed": bool,
    "action_with_tool_grant": str,
    "action_without_tool_grant": str,
    "permission_decision_reason": _OPT_STR,
    "daemon_failure_reason": _OPT_STR,
    "token": dict,
    "verified_benign": bool,
}
_TOKEN_FIELDS: dict[str, Any] = {
    "current_config_action": str,
    "daemon_hint_disposition": _OPT_STR,
    "daemon_hint_reason_code": _OPT_STR,
    "trusted_cli_action": _OPT_STR,
    "untrusted_payload_action": _OPT_STR,
    "untrusted_payload_action_disposition": _OPT_STR,
    "untrusted_payload_action_reason": _OPT_STR,
}
_FINAL_FIELDS: dict[str, Any] = {
    "policy_action": str,
    "observed_policy_action": _OPT_STR,
    "effective_event_name": str,
    "approval_reuse_source": _OPT_STR,
    "policy_composition": dict,
    "evidence_tail": list,
    "silent_review": (dict, type(None)),
    "record_receipt": bool,
    "activity": dict,
    "directive": dict,
}
_ACTIVITY_FIELDS: dict[str, Any] = {"phase": str, "reuse_status": str, "prompted": bool}
_DIRECTIVE_FIELDS: dict[str, Any] = {
    "route": str,
    "queue_observe_request": bool,
    "queue_approval_request": bool,
    "emitter": str,
    "exit_code": (int, type(None)),
    "json_exit_code": (int, type(None)),
    "stderr_only_on_nonzero_exit": bool,
    "codex_native_reason": str,
    "include_remediation": bool,
    "terminal_notice": bool,
    "system_message": str,
    "try_json_document": bool,
    "after_json": str,
    "envelope_decision": str,
}
_ARTIFACT_DIRECTIVE_FIELDS: dict[str, Any] = {
    **_DIRECTIVE_FIELDS,
    "exit_block_stderr": bool,
    "json_reason": str,
}
# Values the artifact renderer dispatches on; anything else is malformed.
_ARTIFACT_DIRECTIVE_VALUES: dict[str, frozenset[str]] = {
    "route": frozenset({"exit_block", "render"}),
    "emitter": frozenset({"default", "grok", "pi", "zcode", "devin"}),
    "codex_native_reason": frozenset({"artifact_codex", "never"}),
    "system_message": frozenset(
        {"none", "claude_punctuated", "claude_prompt_secret", "claude_prompt_sensitive", "codex_prompt"}
    ),
    "after_json": frozenset({"native_response", "post_tool_envelope", "fallback_envelope"}),
    "envelope_decision": frozenset({"allow", "block"}),
    "json_reason": frozenset({"copilot", "harness"}),
}
_ARTIFACT_INPUT_FIELDS = frozenset(
    {
        "harness",
        "canonical_harness",
        "event",
        "policy_action",
        "json",
        "output_stream_present",
        "replayed",
        "approval_context_present",
        "prompt_hard_block",
        "prompt_secret_read",
    }
)
_PERSIST_INPUT_FIELDS = frozenset(
    {
        "artifact_id",
        "artifact_hash",
        "artifact_type",
        "config_path",
        "source_scope",
        "raw_command_text",
        "wrapper_chain",
        "action",
        "reason",
        "source",
        "authoritative_action",
    }
)
_PERSIST_PLAN_FIELDS: dict[str, Any] = {
    "stored_artifact_hash": _OPT_STR,
    "policy_action": _OPT_STR,
    "events": list,
    "inventory_approved": bool,
}
_PERSIST_EVENT_FIELDS: dict[str, Any] = {"name": str, "payload": dict, "before_policy": bool}
# Whether each event the plan may carry is written before the policy row.
_PERSIST_EVENT_PHASE: dict[str, bool] = {
    "claude/native_permission_exact_key_missing": True,
    "claude/native_permission_saved": False,
    "claude/native_permission_current_policy_retained": False,
}
# The event sequences a plan may carry: with a policy row to write, and without.
_PERSIST_EVENT_SEQUENCES: dict[bool, frozenset[tuple[str, ...]]] = {
    True: frozenset(
        {
            ("claude/native_permission_saved",),
            ("claude/native_permission_exact_key_missing", "claude/native_permission_saved"),
        }
    ),
    False: frozenset({("claude/native_permission_current_policy_retained",)}),
}
_REVIEW_ROUTE_FIELDS: dict[str, Any] = {
    "route": str,
    "terminalize": str,
    "record_claude_notice": bool,
    "attach_cursor_request_ids": bool,
    "system_message": str,
    "additional_context": str,
    "silent_review": (dict, type(None)),
}
_REVIEW_ROUTE_SILENT = frozenset({"silent_review", "silent_block"})
# Values the review executor dispatches on; anything else is malformed.
_REVIEW_ROUTE_VALUES: dict[str, frozenset[str]] = {
    "route": frozenset(
        {"continue", "observe", "copilot_response", "native_response", "queue_approval", *_REVIEW_ROUTE_SILENT}
    ),
    "terminalize": frozenset({"none", "enforce", "observe"}),
    "system_message": frozenset({"none", "claude_punctuated", "claude_prompt_secret", "claude_prompt_sensitive"}),
    "additional_context": frozenset({"none", "claude_prompt_secret", "claude_prompt_sensitive"}),
}
_REVIEW_ROUTE_INPUT_FIELDS = frozenset(
    {
        "harness",
        "canonical_harness",
        "event",
        "policy_action",
        "artifact_type",
        "observe_mode",
        "asks_for_approval",
        "json",
        "output_stream_present",
        "prompt_hard_block",
        "prompt_secret_read",
    }
)
_PLAN_FIELDS: dict[str, Any] = {
    "policy_action": str,
    "approval_reuse": (dict, type(None)),
    "scanner_evidence": list,
    "effects": list,
    "exit_code": (int, type(None)),
}
_EFFECT_FIELDS: dict[str, dict[str, Any]] = {
    "silent_review": {"artifact": dict},
    "observe_queue": {"executable_action": str, "observed_policy_action": str, "changed_fields": list},
    "receipt": {"verdict": str, "decision_source": str, "policy_action": str},
    "activity": {"event": str, "policy_action": str, "prompted": bool, "reuse_status": str},
    "usage": {"policy_action": str},
    "pretool_response": {"permission_decision": str, "reason": str},
    "permission_response": {"behavior": str, "message": _OPT_STR, "interrupt": (bool, type(None))},
    "queue_approval": {"evaluation_artifact": dict, "response_payload": dict, "deny_reason": str},
}
# Effect values the transport dispatches on; anything else is malformed.
_EFFECT_VALUES: dict[str, frozenset[str]] = {
    "verdict": frozenset({"allow", "block"}),
    "reuse_status": frozenset({"accepted", "rejected", "not-applicable"}),
    "permission_decision": frozenset({"allow", "deny"}),
    "behavior": frozenset({"allow", "deny"}),
    "event": frozenset({"preToolUse", "copilotPermissionRequest"}),
}
_ACKED_FACT = "acked_recording_only"
_EDGE_KEYS = ("policy_action", "minimum_action", "decision", "reason_code")


class NativeHookDecisionError(RuntimeError):
    """No authoritative decision; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _shape(value: object, fields: Mapping[str, Any]) -> dict[str, Any]:
    return shape_fields(value, fields, lambda: NativeHookDecisionError(_INVALID))


def _action(value: object) -> str:
    if not isinstance(value, str) or value not in _ACTION_NAMES:
        raise NativeHookDecisionError(_INVALID)
    return value


_OPERATION = ResidentOperation(
    operation="hook_decide",
    feature=HOOK_DECISION_FEATURE,
    prefix="native_hook_decision",
    request_schema="guard-hook-decision-request.v1",
    result_schema="guard-hook-decision-result.v1",
    request_id_prefix="hook-decision",
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeHookDecisionError,
)


def _decide(
    query: Mapping[str, object],
    guard_home: Path | None,
    validate: Callable[[dict[str, Any]], None],
    feature: str = HOOK_DECISION_FEATURE,
) -> dict[str, Any]:
    # Copilot settlement carries the serialized tool arguments, so the request
    # gets the same budget as the hook edge that already accepted them.
    return resident_decide(
        _OPERATION if feature == _OPERATION.feature else dataclasses.replace(_OPERATION, feature=feature),
        functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
        query,
        guard_home,
        validate,
    )


def native_compose_current(
    inputs: Mapping[str, object],
    classifiers: Mapping[str, Callable[[str | None], bool]],
    *,
    guard_home: Path | None = None,
) -> tuple[dict[str, Any], dict[str, bool]]:
    """Compose the current action; classifiers run only when the resident asks.

    Each classifier is called with the resident-normalized event name.

    Returns the composition and the classifier verdicts gathered along the way
    (the caller hands them back to ``native_finalize``).
    """

    facts: dict[str, bool] = {}

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", "event_name", "needs_facts", "composition"}:
            raise NativeHookDecisionError(_INVALID)
        needs, composition, event_name = payload["needs_facts"], payload["composition"], payload["event_name"]
        if not isinstance(needs, list) or not isinstance(event_name, (str, type(None))):
            raise NativeHookDecisionError(_INVALID)
        if not needs:
            composition = _shape(composition, _COMPOSITION_FIELDS)
            _shape(composition["token"], _TOKEN_FIELDS)
            for key in ("composed_action", "action_with_tool_grant", "action_without_tool_grant"):
                _action(composition[key])
            return
        for name in needs:
            if not isinstance(name, str) or name not in classifiers or name in facts:
                raise NativeHookDecisionError(_INVALID)

    for _ in range(_MAX_FACT_ROUNDS):
        payload = _decide(
            {"kind": "compose_current", "inputs": {**inputs, "facts": dict(facts)}},
            guard_home,
            validate,
            HOOK_DECISION_NATIVE_EDGE_REASON_FEATURE,
        )
        needs, composition, event_name = payload["needs_facts"], payload["composition"], payload["event_name"]
        if not needs:
            return composition, facts
        for name in needs:
            facts[name] = bool(classifiers[name](event_name))
    raise NativeHookDecisionError(_INVALID)


def native_post_claim_decision(
    inputs: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> tuple[str, str | None, dict[str, Any] | None]:
    """Re-evaluate a claimed saved approval, with its reuse decision when composed.

    A request that names the claimed approval's context token asks the resident
    to compare the tokens and to say what the re-evaluated claim means for
    reuse, so the caller makes one request rather than three and never names a
    saved action itself.  A request that settles the context on its own gets
    the original two fields back and ``None`` here.
    """

    composed = "claimed_context_token" in inputs

    def validate(payload: dict[str, Any]) -> None:
        expected = {"kind", "current_action", "validation_reason"}
        if set(payload) != (expected | {"reuse"} if composed else expected):
            raise NativeHookDecisionError(_INVALID)
        reason = payload["validation_reason"]
        if reason is not None and not isinstance(reason, str):
            raise NativeHookDecisionError(_INVALID)
        if composed:
            try:
                _decision_from_native_payload(payload["reuse"])
            except ApprovalReuseMalformedResultError:
                raise NativeHookDecisionError(_INVALID) from None
        _action(payload["current_action"])

    payload = _decide(
        {"kind": "post_claim_reuse", "inputs": dict(inputs)},
        guard_home,
        validate,
        HOOK_DECISION_POST_CLAIM_COMPOSE_FEATURE if composed else HOOK_DECISION_FEATURE,
    )
    return (
        _action(payload["current_action"]),
        payload["validation_reason"],
        payload["reuse"] if composed else None,
    )


def native_finalize(
    inputs: Mapping[str, object],
    settled: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """Settle the final action, dispositions and response directive."""

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", *_FINAL_FIELDS}:
            raise NativeHookDecisionError(_INVALID)
        final = _shape({key: payload[key] for key in _FINAL_FIELDS}, _FINAL_FIELDS)
        _action(final["policy_action"])
        _shape(final["activity"], _ACTIVITY_FIELDS)
        _shape(final["directive"], _DIRECTIVE_FIELDS)
        if not all(isinstance(entry, dict) for entry in final["evidence_tail"]):
            raise NativeHookDecisionError(_INVALID)
        review = final["silent_review"]
        if review is not None:
            _shape(review, {"action": str, "reason": str})

    payload = _decide(
        {"kind": "finalize", "inputs": dict(inputs), "settled": dict(settled)},
        guard_home,
        validate,
        HOOK_DECISION_NATIVE_EDGE_REASON_FEATURE,
    )
    return {key: payload[key] for key in _FINAL_FIELDS}


def native_artifact_review_route(inputs: Mapping[str, object], *, guard_home: Path | None = None) -> dict[str, Any]:
    """The branch a reviewed artifact verdict takes, and what that branch is told."""

    if set(inputs) != _REVIEW_ROUTE_INPUT_FIELDS:
        raise NativeHookDecisionError(_INVALID)

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", *_REVIEW_ROUTE_FIELDS}:
            raise NativeHookDecisionError(_INVALID)
        chosen = _shape({key: payload[key] for key in _REVIEW_ROUTE_FIELDS}, _REVIEW_ROUTE_FIELDS)
        for key, allowed in _REVIEW_ROUTE_VALUES.items():
            if chosen[key] not in allowed:
                raise NativeHookDecisionError(_INVALID)
        silent = chosen["silent_review"]
        if (silent is not None) != (chosen["route"] in _REVIEW_ROUTE_SILENT):
            raise NativeHookDecisionError(_INVALID)
        if silent is not None and _shape(silent, {"action": str, "reason": str})["action"] != inputs["policy_action"]:
            raise NativeHookDecisionError(_INVALID)

    payload = _decide(
        {"kind": "artifact_review_route", "inputs": dict(inputs)},
        guard_home,
        validate,
        HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE,
    )
    return {key: payload[key] for key in _REVIEW_ROUTE_FIELDS}


def native_artifact_directive(inputs: Mapping[str, object], *, guard_home: Path | None = None) -> dict[str, Any]:
    """The artifact hook's response directive: how its settled verdict renders."""

    if set(inputs) != _ARTIFACT_INPUT_FIELDS:
        raise NativeHookDecisionError(_INVALID)

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", *_ARTIFACT_DIRECTIVE_FIELDS}:
            raise NativeHookDecisionError(_INVALID)
        directive = _shape({key: payload[key] for key in _ARTIFACT_DIRECTIVE_FIELDS}, _ARTIFACT_DIRECTIVE_FIELDS)
        for key, allowed in _ARTIFACT_DIRECTIVE_VALUES.items():
            if directive[key] not in allowed:
                raise NativeHookDecisionError(_INVALID)
        if directive["queue_observe_request"] or directive["queue_approval_request"]:
            raise NativeHookDecisionError(_INVALID)

    # The newer capability stands for both: a runtime that names the JSON
    # document's exit status is built from a tree that answers this query.
    payload = _decide(
        {"kind": "artifact_directive", "inputs": dict(inputs)},
        guard_home,
        validate,
        HOOK_DECISION_JSON_EXIT_CODE_FEATURE,
    )
    return {key: payload[key] for key in _ARTIFACT_DIRECTIVE_FIELDS}


def _tilde_home() -> str | None:
    """``os.path.expanduser("~")``, or ``None`` when the host cannot resolve it."""

    home = os.path.expanduser("~")
    return None if home.startswith("~") else home


def native_permission_persist_plan(
    inputs: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """What a Claude-native approval saves: the stored hash, the events, the inventory disposition.

    The stored hash is what a later lookup matches a saved approval by, so only
    the resident decides it. The caller performs the writes the plan names, in
    order, and writes nothing when this raises.
    """

    if set(inputs) != _PERSIST_INPUT_FIELDS:
        raise NativeHookDecisionError(_INVALID)

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", *_PERSIST_PLAN_FIELDS}:
            raise NativeHookDecisionError(_INVALID)
        plan = _shape({key: payload[key] for key in _PERSIST_PLAN_FIELDS}, _PERSIST_PLAN_FIELDS)
        stored, policy_action = plan["stored_artifact_hash"], plan["policy_action"]
        if (stored is None) != (policy_action is None) or policy_action not in {None, "allow", "block"}:
            raise NativeHookDecisionError(_INVALID)
        names: list[str] = []
        for event in plan["events"]:
            fields = _shape(event, _PERSIST_EVENT_FIELDS)
            if _PERSIST_EVENT_PHASE.get(fields["name"]) != fields["before_policy"]:
                raise NativeHookDecisionError(_INVALID)
            names.append(fields["name"])
        if tuple(names) not in _PERSIST_EVENT_SEQUENCES[stored is not None]:
            raise NativeHookDecisionError(_INVALID)

    payload = _decide(
        {
            "kind": "native_permission_persist_plan",
            "inputs": {**inputs, "tilde_home": _tilde_home()},
        },
        guard_home,
        validate,
        HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE,
    )
    return {key: payload[key] for key in _PERSIST_PLAN_FIELDS}


def native_copilot_settle(
    inputs: Mapping[str, object],
    acked_recording_only: Callable[[], bool],
    *,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """Settle a Copilot tool call: the final action and the effects to run, in order.

    ``acked_recording_only`` runs only when the resident asks for it.
    """

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", "needs_facts", "plan"}:
            raise NativeHookDecisionError(_INVALID)
        needs = payload["needs_facts"]
        if not isinstance(needs, list):
            raise NativeHookDecisionError(_INVALID)
        if needs:
            if needs != [_ACKED_FACT] or inputs[_ACKED_FACT] is not None or payload["plan"] is not None:
                raise NativeHookDecisionError(_INVALID)
            return
        plan = _shape(payload["plan"], _PLAN_FIELDS)
        _action(plan["policy_action"])
        if not all(isinstance(entry, dict) for entry in plan["scanner_evidence"]):
            raise NativeHookDecisionError(_INVALID)
        for effect in plan["effects"]:
            kind = effect.get("effect") if isinstance(effect, dict) else None
            if kind not in _EFFECT_FIELDS:
                raise NativeHookDecisionError(_INVALID)
            fields = _shape({key: value for key, value in effect.items() if key != "effect"}, _EFFECT_FIELDS[kind])
            for key, allowed in _EFFECT_VALUES.items():
                if key in fields and fields[key] not in allowed:
                    raise NativeHookDecisionError(_INVALID)
            for key in ("policy_action", "executable_action", "observed_policy_action"):
                if key in fields:
                    _action(fields[key])

    # The resident binds the reply to its typed request, so every optional
    # field travels explicitly.
    edge = inputs.get("native_edge")
    inputs = {
        **inputs,
        _ACKED_FACT: inputs.get(_ACKED_FACT),
        "native_edge": {key: edge.get(key) for key in _EDGE_KEYS} if isinstance(edge, Mapping) else None,
    }
    settle = functools.partial(
        _decide,
        guard_home=guard_home,
        validate=validate,
        feature=HOOK_DECISION_NATIVE_EDGE_REASON_FEATURE,
    )
    payload = settle({"kind": "copilot_settle", "inputs": dict(inputs)})
    if payload["needs_facts"]:
        inputs = {**inputs, _ACKED_FACT: bool(acked_recording_only())}
        payload = settle({"kind": "copilot_settle", "inputs": dict(inputs)})
    return payload["plan"]


__all__ = [
    "HOOK_DECISION_ARTIFACT_DIRECTIVE_FEATURE",
    "HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE",
    "HOOK_DECISION_FEATURE",
    "HOOK_DECISION_JSON_EXIT_CODE_FEATURE",
    "HOOK_DECISION_NATIVE_EDGE_REASON_FEATURE",
    "HOOK_DECISION_NATIVE_PERMISSION_PERSIST_FEATURE",
    "HOOK_DECISION_POST_CLAIM_COMPOSE_FEATURE",
    "NativeHookDecisionError",
    "native_artifact_directive",
    "native_artifact_review_route",
    "native_compose_current",
    "native_copilot_settle",
    "native_finalize",
    "native_permission_persist_plan",
    "native_post_claim_decision",
]
