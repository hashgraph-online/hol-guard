"""The artifact hook applies the resident's final-action settle as Python decided it.

``scripts/ci/record_artifact_finalize_vectors.py`` recorded the retired Python
``set_native_artifact_hook_final_action`` with its two rendering collaborators
stubbed. The Rust suite replays the facts to the answers; this suite hands each
recorded answer to the new executor and checks that it sends the same facts and
leaves the same state and the same persisted receipt bytes. It also pins the
approval invariant on the recorded answers.
"""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_finalize as finalize
from codex_plugin_scanner.guard.cli import commands_hook_native_state as state_module
from tests.artifact_finalize_support import (
    load_recorder,
    load_vectors,
    resident_stub,
    settle_reply,
    stub_renderers,
    vector_key,
)


def test_executor_reproduces_the_recorded_python_settle(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = load_recorder()
    data = load_vectors()
    vectors = {vector_key(vector["facts"]): vector for vector in data["settle"]}
    assert len(vectors) > 2_500
    stub_renderers(monkeypatch, recorder)
    asked = resident_stub(monkeypatch, lambda query: settle_reply(vectors[vector_key(query["inputs"])]))

    def run(case: Any) -> SimpleNamespace:
        state = case.state()
        state_module.set_native_artifact_hook_final_action(
            state,  # type: ignore[arg-type]
            case.policy_action,
            approval_request_id=case.approval_request_id,
            approval_source=case.approval_source,
            observed_policy_action=case.observed_policy_action,
            queued_request_id=case.queued_request_id,
        )
        return state

    failures: list[str] = []
    replayed = 0
    for case in recorder.settle_cases():
        replayed += 1
        expected = vectors[vector_key(case.facts())]
        asked.clear()
        actual = recorder.record_settle(case, run=run)
        if [query["inputs"] for query in asked] != [case.facts()]:
            failures.append(f"{case.facts()}: asked {asked}")
        for key in ("facts", "answer", "receipt", "wire"):
            if actual[key] != expected[key]:
                failures.append(f"{case.facts()}: {key} {actual[key]!r} != {expected[key]!r}")
        observed = json.dumps(actual["outcome"], sort_keys=True, separators=(",", ":"))
        if observed != data["outcomes"][expected["outcome"]]:
            failures.append(f"{case.facts()}: outcome {observed} != {data['outcomes'][expected['outcome']]}")
        if len(failures) > 10:
            break
    assert failures == []
    assert replayed == len(data["settle"])


def test_the_persisted_receipt_is_pinned_byte_for_byte(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = load_recorder()
    data = load_vectors()
    vectors = {vector_key(vector["facts"]): vector for vector in data["settle"]}
    stub_renderers(monkeypatch, recorder)
    resident_stub(monkeypatch, lambda query: settle_reply(vectors[vector_key(query["inputs"])]))
    browser = 0
    for case in recorder.settle_cases():
        state = case.state()
        state_module.set_native_artifact_hook_final_action(
            state,  # type: ignore[arg-type]
            case.policy_action,
            approval_request_id=case.approval_request_id,
            approval_source=case.approval_source,
            observed_policy_action=case.observed_policy_action,
            queued_request_id=case.queued_request_id,
        )
        pinned = vectors[vector_key(case.facts())]["receipt"]
        receipt = state.receipt
        assert receipt.policy_decision == pinned["policy_decision"]
        assert receipt.approval_source == pinned["approval_source"]
        assert receipt.approval_request_id == pinned["approval_request_id"]
        assert receipt.user_override == pinned["user_override"]
        assert json.dumps(list(receipt.scanner_evidence), separators=(",", ":")) == pinned["scanner_evidence"]
        if case.approval_source == "browser":
            browser += 1
            assert receipt.user_override == "browser-approval"
            assert json.loads(pinned["scanner_evidence"])[-1]["source"] == "browser_approval_resolution"
    assert browser > 700


def test_the_settle_leaves_the_approval_choice_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = load_recorder()
    data = load_vectors()
    vectors = {vector_key(vector["facts"]): vector for vector in data["settle"]}
    stub_renderers(monkeypatch, recorder)
    resident_stub(monkeypatch, lambda query: settle_reply(vectors[vector_key(query["inputs"])]))
    kept = {
        "approval_requests": [{"request_id": "queued-1"}],
        "approval_url": "http://127.0.0.1:4455/requests/queued-1",
        "approval_wait": {"timeout": 30},
        "review_hint": "Approve it.",
        "browser_resolution_request_id": "req-1",
    }
    for case in recorder.settle_cases():
        state = case.state()
        state.response_payload.update(copy.deepcopy(kept))
        state_module.set_native_artifact_hook_final_action(
            state,  # type: ignore[arg-type]
            case.policy_action,
            approval_request_id=case.approval_request_id,
            approval_source=case.approval_source,
            observed_policy_action=case.observed_policy_action,
            queued_request_id=case.queued_request_id,
        )
        for key, value in kept.items():
            assert state.response_payload[key] == value, case.facts()


class _StopError(Exception):
    """The resident was asked; nothing more is needed."""


def _stop(_query: object) -> dict[str, Any]:
    raise _StopError


def _supply_state(raw: object, cloud: object = None) -> SimpleNamespace:
    state = load_recorder().SettleCase(previous_action="review", policy_action="allow").state()
    state.response_payload.pop("supply_chain_evaluation", None)
    if raw is not _ABSENT:
        state.response_payload["supply_chain_evaluation"] = raw
    state.decision_v2_payload = {} if cloud is None else {"package_review_cloud_reason_code": cloud}
    return state


_ABSENT = object()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (_ABSENT, (False, None)),
        ("not a mapping", (False, None)),
        ({}, (True, None)),
        ({"decision": "block"}, (True, "block")),
        ({"policy_action": "review", "decision": "block"}, (True, "review")),
        ({"policy_action": None, "decision": "block"}, (True, None)),
        ({"policy_action": 5, "decision": "block"}, (True, None)),
        ({"decision": ["block"]}, (True, None)),
    ],
)
def test_package_evaluation_facts_are_read_as_the_old_settle_read_them(
    monkeypatch: pytest.MonkeyPatch, raw: object, expected: tuple[bool, str | None]
) -> None:
    asked = resident_stub(monkeypatch, _stop)
    state = _supply_state(raw)
    with pytest.raises(_StopError):
        state_module.plan_native_artifact_hook_final_action(state, "allow")  # type: ignore[arg-type]
    inputs = asked[0]["inputs"]
    assert (inputs["supply_chain_present"], inputs["supply_chain_action"]) == expected


@pytest.mark.parametrize(
    ("cloud", "expected"), [(None, None), ("cloud_timeout", "cloud_timeout"), (5, None), ([], None)]
)
def test_the_cloud_reason_code_is_sent_only_as_text(
    monkeypatch: pytest.MonkeyPatch, cloud: object, expected: str | None
) -> None:
    asked = resident_stub(monkeypatch, _stop)
    with pytest.raises(_StopError):
        state_module.plan_native_artifact_hook_final_action(_supply_state(_ABSENT, cloud), "allow")  # type: ignore[arg-type]
    assert asked[0]["inputs"]["package_review_cloud_reason_code"] == expected


def test_planning_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = load_recorder()
    case = recorder.SettleCase(previous_action="review", policy_action="block", approval_source="browser")
    data = load_vectors()
    vectors = {vector_key(vector["facts"]): vector for vector in data["settle"]}
    resident_stub(monkeypatch, lambda query: settle_reply(vectors[vector_key(query["inputs"])]))
    state, untouched = case.state(), case.state()
    state_module.plan_native_artifact_hook_final_action(
        state,  # type: ignore[arg-type]
        "block",
        approval_source="browser",
    )
    assert recorder.outcome_of(state) == recorder.outcome_of(untouched)


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_settles() -> None:
    failures: list[str] = []
    for vector in load_vectors()["settle"][::37]:
        answer = finalize.native_artifact_finalize(vector["facts"])
        expected = settle_reply(vector)
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {value!r}"
            for key, value in expected.items()
            if key != "kind" and answer[key] != value
        )
        # Key order is persisted: the objects the resident writes keep Python's.
        if json.dumps(answer["evidence_patch"]["fields"], separators=(",", ":")) != vector["wire"]["fields"]:
            failures.append(f"{vector['facts']}: evidence fields reordered")
    assert failures == []
