"""The wrapper decodes the resident's settle and outcome strictly.

A reply that is not a bound, strictly shaped ``ok`` raises
``NativeHookDecisionError`` and the hook answers with its outage response.
"""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_finalize as finalize
from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_resident_decision as shared
from tests.artifact_finalize_support import FEATURE

_FACTS = {
    "previous_action": "review",
    "policy_action": "allow",
    "observed_policy_action": None,
    "approval_source": "browser",
    "approval_request_id": "req-1",
    "queued_request_id": None,
    "initial_policy_action": "review",
    "receipt_approval_source": None,
    "receipt_approval_request_id": None,
    "receipt_user_override": None,
    "package_review_cloud_reason_code": None,
    "supply_chain_present": False,
    "supply_chain_action": None,
}
_FINALIZE = {
    "kind": "artifact_finalize",
    "action": "allow",
    "observed_action": None,
    "decision_reason": "browser-approval",
    "cloud_reason_code": None,
    "refresh_copy": True,
    "observed_supply_chain_action": None,
    "drop_terminal_action": False,
    "evidence_patch": {"source": "policy_composition", "fields": {"authoritative_action": "allow"}},
    "receipt": {
        "policy_decision": "allow",
        "approval_source": "browser",
        "approval_request_id": "req-1",
        "user_override": "browser-approval",
        "appended_evidence": [
            {
                "source": "browser_approval_resolution",
                "initial_action": "review",
                "authoritative_action": "allow",
                "approval_request_id": "req-1",
            }
        ],
    },
}
_OUTCOME_FACTS = {"decision": "allow", "event": "PostToolUse"}
_OUTCOME = {
    "kind": "artifact_browser_outcome",
    "settle": True,
    "action": "allow",
    "approval_source": "browser",
    "emit_native_allow": True,
    "finish_without_render": True,
}
_UNSETTLED = {
    "kind": "artifact_browser_outcome",
    "settle": False,
    "action": None,
    "approval_source": None,
    "emit_native_allow": False,
    "finish_without_render": False,
}


def _resident_answering(monkeypatch: pytest.MonkeyPatch, query: dict[str, Any], payload: dict[str, Any]) -> list[str]:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", FEATURE}),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)
    asked: list[str] = []

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append(required_feature)
        assert request["query"] == query
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(decision, "_resident_request", transport)
    return asked


def test_a_bound_settle_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _resident_answering(monkeypatch, {"kind": "artifact_finalize", "inputs": _FACTS}, _FINALIZE)
    answer = finalize.native_artifact_finalize(_FACTS)
    assert answer == {key: value for key, value in _FINALIZE.items() if key != "kind"}
    assert asked == [FEATURE]


def test_a_bound_outcome_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": _OUTCOME_FACTS}, _OUTCOME)
    answer = finalize.native_artifact_browser_outcome(_OUTCOME_FACTS)
    assert answer == {key: value for key, value in _OUTCOME.items() if key != "kind"}
    assert asked == [FEATURE]


def _with(base: dict[str, Any], dotted: str, value: object) -> dict[str, Any]:
    changed = copy.deepcopy(base)
    target = changed
    *path, last = dotted.split(".")
    for part in path:
        target = target[int(part)] if isinstance(target, list) else target[part]
    if isinstance(target, list):
        target[int(last)] = value
    else:
        target[last] = value
    return changed


@pytest.mark.parametrize(
    "payload",
    [
        _with(_FINALIZE, "action", "permit"),
        _with(_FINALIZE, "action", "block"),
        _with(_FINALIZE, "action", 5),
        _with(_FINALIZE, "observed_action", "review"),
        _with(_FINALIZE, "drop_terminal_action", True),
        _with(_FINALIZE, "refresh_copy", "yes"),
        _with(_FINALIZE, "cloud_reason_code", 5),
        _with(_FINALIZE, "observed_supply_chain_action", "maybe"),
        _with(_FINALIZE, "evidence_patch.source", None),
        _with(_FINALIZE, "evidence_patch.fields", {}),
        _with(_FINALIZE, "evidence_patch.fields", {"authoritative_action": "block"}),
        _with(_FINALIZE, "evidence_patch.fields", {"authoritative_action": "allow", "observed_policy_action": "x"}),
        _with(_FINALIZE, "receipt.policy_decision", "block"),
        _with(_FINALIZE, "receipt.user_override", 1),
        _with(_FINALIZE, "receipt.appended_evidence", ["browser"]),
        _with(_FINALIZE, "receipt.appended_evidence", [{"source": "browser_approval_resolution"}]),
        _with(_FINALIZE, "receipt.appended_evidence.0.authoritative_action", "block"),
        {**_FINALIZE, "extra": True},
        {key: value for key, value in _FINALIZE.items() if key != "receipt"},
    ],
)
def test_a_malformed_settle_fails_closed(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    _resident_answering(monkeypatch, {"kind": "artifact_finalize", "inputs": _FACTS}, payload)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_finalize(_FACTS)


@pytest.mark.parametrize(
    "payload",
    [
        {**_OUTCOME, "action": "block"},
        {**_OUTCOME, "action": "review"},
        {**_OUTCOME, "approval_source": "daemon"},
        {**_OUTCOME, "approval_source": None},
        {**_OUTCOME, "settle": False},
        {**_OUTCOME, "emit_native_allow": "yes"},
        {**_OUTCOME, "finish_without_render": False},
        {**_OUTCOME, "emit_native_allow": False},
        {**_OUTCOME, "extra": 1},
        # An approval the user gave is never left unsettled.
        {**_UNSETTLED},
        {
            "kind": "artifact_browser_outcome",
            "settle": False,
            "action": "allow",
            "approval_source": None,
            "emit_native_allow": False,
            "finish_without_render": False,
        },
        {
            "kind": "artifact_browser_outcome",
            "settle": False,
            "action": None,
            "approval_source": None,
            "emit_native_allow": True,
            "finish_without_render": False,
        },
    ],
)
def test_a_malformed_outcome_fails_closed(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": _OUTCOME_FACTS}, payload)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_browser_outcome(_OUTCOME_FACTS)


def test_a_terminal_outcome_may_not_end_the_hook_unrendered(monkeypatch: pytest.MonkeyPatch) -> None:
    facts = {"decision": "block", "event": "PreToolUse"}
    terminal = {**_OUTCOME, "action": "block", "emit_native_allow": False, "finish_without_render": False}
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": facts}, terminal)
    assert finalize.native_artifact_browser_outcome(facts)["action"] == "block"
    unrendered = {**terminal, "finish_without_render": True}
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": facts}, unrendered)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_browser_outcome(facts)


def test_incomplete_inputs_are_refused_before_the_resident_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _resident_answering(monkeypatch, {"kind": "artifact_finalize", "inputs": _FACTS}, _FINALIZE)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_finalize({key: value for key, value in _FACTS.items() if key != "supply_chain_action"})
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_finalize({**_FACTS, "extra": 1})
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_browser_outcome({"decision": "allow"})
    assert asked == []


@pytest.mark.parametrize(
    ("facts", "payload"),
    [
        # A tool call's approval is answered by the harness, not natively.
        ({"decision": "allow", "event": "PreToolUse"}, {**_OUTCOME}),
        # An approval or a terminal verdict is never left unsettled.
        ({"decision": "allow", "event": "PreToolUse"}, {**_UNSETTLED}),
        ({"decision": "block", "event": "PreToolUse"}, {**_UNSETTLED}),
        ({"decision": "sandbox-required", "event": "PostToolUse"}, {**_UNSETTLED}),
    ],
)
def test_an_outcome_that_contradicts_the_browsers_verdict_fails_closed(
    monkeypatch: pytest.MonkeyPatch, facts: dict[str, str], payload: dict[str, Any]
) -> None:
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": facts}, payload)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_browser_outcome(facts)


@pytest.mark.parametrize("decision_text", ["review", "require-reapproval", "timeout", "", "ALLOW"])
def test_a_browser_outcome_that_is_no_verdict_settles_nothing(
    monkeypatch: pytest.MonkeyPatch, decision_text: str
) -> None:
    facts = {"decision": decision_text, "event": "PostToolUse"}
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": facts}, _UNSETTLED)
    assert finalize.native_artifact_browser_outcome(facts)["settle"] is False
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": facts}, _OUTCOME)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_browser_outcome(facts)


def test_a_tool_call_approval_is_settled_without_a_native_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    facts = {"decision": "allow", "event": "PreToolUse"}
    answer = {**_OUTCOME, "emit_native_allow": False}
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": facts}, answer)
    outcome = finalize.native_artifact_browser_outcome(facts)
    assert (outcome["settle"], outcome["emit_native_allow"], outcome["finish_without_render"]) == (True, False, True)
