"""The policy-bundle candidate question travels to the resident as one query."""

from __future__ import annotations

from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
from codex_plugin_scanner.guard.native_policy_document import NativePolicyDocumentError
from codex_plugin_scanner.guard.runtime import runner_policy_shadow as candidate

_ROW: dict[str, Any] = {
    "harness": "codex",
    "scope": "artifact",
    "action": "allow",
    "artifact_id": "memory:exact-shell-command:x",
    "artifact_hash": None,
    "workspace": None,
    "publisher": None,
    "reason": None,
    "owner": "allow-x",
    "source": "policy-bundle-canonical",
    "expires_at": None,
}


def _ask(**overrides: Any) -> candidate.CandidateAnswer:
    fields: dict[str, Any] = {
        "is_v2": True,
        "device_id": "device-1",
        "device_name": "Workstation",
        "canonical_enforcement": True,
        "stored_legacy": None,
        "existing": None,
        **overrides,
    }
    return candidate.policy_bundle_candidate({"contractVersion": "guard-policy-bundle.v2"}, **fields)


def test_the_request_carries_the_candidate_and_both_shadows(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []
    mismatch: dict[str, object] = {
        "canonicalRows": 1,
        "legacyRows": 0,
        "reasonCodes": ["legacy_unavailable"],
        "status": "mismatch",
    }

    def _query(query: str, body: dict[str, object], **_kwargs: object) -> object:
        sent.append((query, body))
        return {"decisions": [_ROW], "rejection": None, "rule_id": None, "mismatch": mismatch, "total": 1, "next": None}

    monkeypatch.setattr(candidate, "policy_query", _query)
    answer = _ask(stored_legacy={"bundleVersion": 1}, existing="not-a-bundle")

    assert answer == candidate.CandidateAnswer([PolicyDecision(**_ROW)], None, None, mismatch)
    assert sent == [
        (
            "bundle_candidate",
            {
                "bundle": {"contractVersion": "guard-policy-bundle.v2"},
                "is_v2": True,
                "device_id": "device-1",
                "device_name": "Workstation",
                "canonical_enforcement": True,
                "stored_legacy": {"bundleVersion": 1},
                "existing": "not-a-bundle",
                "offset": 0,
            },
        )
    ]


def test_a_refusal_keeps_its_code_and_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        candidate,
        "policy_query",
        lambda *_args, **_kwargs: {
            "decisions": [],
            "rejection": "canonical_compile_unsupported_policy_effect",
            "rule_id": "warn-only",
            "mismatch": None,
            "total": 0,
            "next": None,
        },
    )

    assert _ask() == candidate.CandidateAnswer([], "canonical_compile_unsupported_policy_effect", "warn-only", None)


@pytest.mark.parametrize(
    "failure",
    [NativePolicyDocumentError("native_policy_document_unavailable"), ValueError("policy_document_query_invalid")],
)
def test_an_unanswered_query_refuses_the_candidate(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    def _down(*_args: object, **_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(candidate, "policy_query", _down)

    assert _ask() == candidate.CandidateAnswer([], NATIVE_UNAVAILABLE_REJECTION, None, None)


def _verdict(**fields: Any) -> dict[str, Any]:
    return {"decisions": [], "rejection": None, "rule_id": None, "mismatch": None, "total": 0, "next": None, **fields}


def test_the_decisions_are_collected_page_by_page(monkeypatch: pytest.MonkeyPatch) -> None:
    second: dict[str, Any] = {**_ROW, "artifact_id": "memory:exact-shell-command:y"}
    pages = {0: _verdict(decisions=[_ROW], total=2, next=1), 1: _verdict(decisions=[second], total=2)}
    offsets: list[object] = []

    def _query(_query: str, body: dict[str, object], **_kwargs: object) -> object:
        offsets.append(body["offset"])
        return pages[cast(int, body["offset"])]

    monkeypatch.setattr(candidate, "policy_query", _query)

    assert _ask().decisions == [PolicyDecision(**_ROW), PolicyDecision(**second)]
    assert offsets == [0, 1]


@pytest.mark.parametrize(
    "pages",
    [
        {0: _verdict(decisions=[_ROW], total=2, next=1), 1: _verdict(decisions=[_ROW], total=3)},
        {0: _verdict(decisions=[_ROW], total=2, next=1), 1: _verdict(decisions=[_ROW], total=2, rejection="x")},
        {0: _verdict(decisions=[_ROW], total=2, next=2)},
        {0: _verdict(decisions=[_ROW], total=2)},
    ],
)
def test_pages_that_disagree_refuse_the_candidate(
    monkeypatch: pytest.MonkeyPatch, pages: dict[int, dict[str, Any]]
) -> None:
    monkeypatch.setattr(candidate, "policy_query", lambda _query, body, **_kwargs: pages[cast(int, body["offset"])])

    assert _ask() == candidate.CandidateAnswer([], NATIVE_UNAVAILABLE_REJECTION, None, None)


@pytest.mark.parametrize(
    "answer",
    [
        [],
        {"decisions": [], "rejection": None, "rule_id": None, "mismatch": None},
        _verdict(decisions="rows"),
        _verdict(decisions=[{"harness": "codex", "unknown": 1}], total=1),
        _verdict(decisions=[{**_ROW, "action": "unexpected"}], total=1),
        _verdict(decisions=[{**_ROW, "scope": "everywhere"}], total=1),
        _verdict(decisions=[{**_ROW, "harness": None}], total=1),
        _verdict(decisions=[{**_ROW, "reason": 7}], total=1),
        _verdict(rejection=7),
        _verdict(total=-1),
        _verdict(total=True),
        _verdict(mismatch={"status": "mismatch"}),
        _verdict(mismatch={"canonicalRows": "1", "legacyRows": 0, "reasonCodes": [], "status": "mismatch"}),
        _verdict(mismatch={"canonicalRows": 1, "legacyRows": 0, "reasonCodes": [1], "status": "mismatch"}),
        _verdict(mismatch={"canonicalRows": 1, "legacyRows": 0, "reasonCodes": [], "status": "match"}),
    ],
)
def test_a_malformed_answer_refuses_the_candidate(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    monkeypatch.setattr(candidate, "policy_query", lambda *_args, **_kwargs: answer)

    assert _ask() == candidate.CandidateAnswer([], NATIVE_UNAVAILABLE_REJECTION, None, None)
