"""The artifact hook's final-action settle, answered by the native runtime.

A verdict can still change after review: Watch mode executes the policy it
observed, a silent denial closes a review, and a browser approval resolves it.
The resident says whether a browser outcome settles the hook
(``artifact_browser_outcome``) and what the final action, the decision record,
the evidence and the persisted receipt become (``artifact_finalize``). The
transport gathers the facts and applies the answer. There is no Python
evaluator: a reply that is not a bound, strictly decoded ``ok`` raises
``NativeHookDecisionError``, and the hook answers with its outage response
rather than persisting a receipt for a verdict the harness never received.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_hook_decision import (
    _ACTION_NAMES,
    _INVALID,
    _OPT_STR,
    NativeHookDecisionError,
    _action,
    _decide,
    _shape,
)

HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE = "hook-decision-artifact-finalize-v1"

_FINALIZE_INPUT_FIELDS = frozenset(
    {
        "previous_action",
        "policy_action",
        "observed_policy_action",
        "approval_source",
        "approval_request_id",
        "queued_request_id",
        "initial_policy_action",
        "receipt_approval_source",
        "receipt_approval_request_id",
        "receipt_user_override",
        "package_review_cloud_reason_code",
        "supply_chain_present",
        "supply_chain_action",
    }
)
_FINALIZE_FIELDS: dict[str, Any] = {
    "action": str,
    "observed_action": _OPT_STR,
    "decision_reason": str,
    "cloud_reason_code": _OPT_STR,
    "refresh_copy": bool,
    "observed_supply_chain_action": _OPT_STR,
    "drop_terminal_action": bool,
    "evidence_patch": dict,
    "receipt": dict,
}
_PATCH_FIELDS: dict[str, Any] = {"source": str, "fields": dict}
_RECEIPT_FIELDS: dict[str, Any] = {
    "policy_decision": str,
    "approval_source": _OPT_STR,
    "approval_request_id": _OPT_STR,
    "user_override": _OPT_STR,
    "appended_evidence": list,
}
_RESOLUTION_FIELDS: dict[str, Any] = {
    "source": str,
    "initial_action": str,
    "authoritative_action": str,
    "approval_request_id": _OPT_STR,
}
_OUTCOME_INPUT_FIELDS = frozenset({"decision", "event"})
_OUTCOME_FIELDS: dict[str, Any] = {
    "settle": bool,
    "action": _OPT_STR,
    "approval_source": _OPT_STR,
    "emit_native_allow": bool,
    "finish_without_render": bool,
}
# The only outcomes that settle a browser resolution: the user's approval and
# the two terminal verdicts. Anything else leaves the review where it was.
_OUTCOME_ACTIONS = frozenset({"allow", "block", "sandbox-required"})


def _validate_finalize(inputs: Mapping[str, object], payload: dict[str, Any]) -> None:
    if set(payload) != {"kind", *_FINALIZE_FIELDS}:
        raise NativeHookDecisionError(_INVALID)
    chosen = _shape({key: payload[key] for key in _FINALIZE_FIELDS}, _FINALIZE_FIELDS)
    action = _action(chosen["action"])
    # An action the transport named in the lattice is settled as it is named.
    named = inputs["policy_action"]
    if isinstance(named, str) and named in _ACTION_NAMES and action != named:
        raise NativeHookDecisionError(_INVALID)
    observed = chosen["observed_action"]
    if observed is not None:
        _action(observed)
    if (observed is None) != (inputs["observed_policy_action"] is None) or chosen["drop_terminal_action"] != (
        observed is not None
    ):
        raise NativeHookDecisionError(_INVALID)
    if chosen["observed_supply_chain_action"] is not None:
        _action(chosen["observed_supply_chain_action"])
    patch = _shape(chosen["evidence_patch"], _PATCH_FIELDS)
    fields = patch["fields"]
    if set(fields) != ({"authoritative_action"} | ({"observed_policy_action"} if observed is not None else set())):
        raise NativeHookDecisionError(_INVALID)
    if fields["authoritative_action"] != action or fields.get("observed_policy_action") != observed:
        raise NativeHookDecisionError(_INVALID)
    receipt = _shape(chosen["receipt"], _RECEIPT_FIELDS)
    if receipt["policy_decision"] != action:
        raise NativeHookDecisionError(_INVALID)
    appended = receipt["appended_evidence"]
    if not all(isinstance(entry, dict) for entry in appended):
        raise NativeHookDecisionError(_INVALID)
    for entry in appended:
        _shape(entry, _RESOLUTION_FIELDS)
        if entry["authoritative_action"] != action:
            raise NativeHookDecisionError(_INVALID)


def native_artifact_finalize(inputs: Mapping[str, object], *, guard_home: Path | None = None) -> dict[str, Any]:
    """What the final action, decision record, evidence and receipt become."""

    if set(inputs) != _FINALIZE_INPUT_FIELDS:
        raise NativeHookDecisionError(_INVALID)
    payload = _decide(
        {"kind": "artifact_finalize", "inputs": dict(inputs)},
        guard_home,
        lambda reply: _validate_finalize(inputs, reply),
        HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE,
    )
    return {key: payload[key] for key in _FINALIZE_FIELDS}


def _validate_outcome(inputs: Mapping[str, object], payload: dict[str, Any]) -> None:
    if set(payload) != {"kind", *_OUTCOME_FIELDS}:
        raise NativeHookDecisionError(_INVALID)
    outcome = _shape({key: payload[key] for key in _OUTCOME_FIELDS}, _OUTCOME_FIELDS)
    decision = inputs["decision"]
    if not outcome["settle"]:
        # The user's approval and the two terminal verdicts always settle: an
        # answer that leaves one unsettled would render the review again.
        if decision in _OUTCOME_ACTIONS:
            raise NativeHookDecisionError(_INVALID)
        if outcome["action"] is not None or outcome["approval_source"] is not None:
            raise NativeHookDecisionError(_INVALID)
        if outcome["emit_native_allow"] or outcome["finish_without_render"]:
            raise NativeHookDecisionError(_INVALID)
        return
    # A browser outcome settles only as the verdict the user's browser gave.
    if outcome["action"] not in _OUTCOME_ACTIONS or outcome["action"] != decision:
        raise NativeHookDecisionError(_INVALID)
    if outcome["approval_source"] != "browser":
        raise NativeHookDecisionError(_INVALID)
    # An approval ends the hook once its receipt is recorded, answered natively
    # unless a tool call is, and a terminal verdict is rendered like any other.
    approved = decision == "allow"
    if outcome["finish_without_render"] != approved:
        raise NativeHookDecisionError(_INVALID)
    if outcome["emit_native_allow"] != (approved and inputs["event"] != "PreToolUse"):
        raise NativeHookDecisionError(_INVALID)


def native_artifact_browser_outcome(inputs: Mapping[str, object], *, guard_home: Path | None = None) -> dict[str, Any]:
    """Whether a browser outcome settles the hook, and how the hook ends."""

    if set(inputs) != _OUTCOME_INPUT_FIELDS:
        raise NativeHookDecisionError(_INVALID)
    payload = _decide(
        {"kind": "artifact_browser_outcome", "inputs": dict(inputs)},
        guard_home,
        lambda reply: _validate_outcome(inputs, reply),
        HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE,
    )
    return {key: payload[key] for key in _OUTCOME_FIELDS}


__all__ = [
    "HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE",
    "native_artifact_browser_outcome",
    "native_artifact_finalize",
]
