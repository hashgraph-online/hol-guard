"""The policy-bundle candidate question travels to the resident as one query."""

from __future__ import annotations

from typing import Any

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
        return {"decisions": [_ROW], "rejection": None, "rule_id": None, "mismatch": mismatch}

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


@pytest.mark.parametrize(
    "answer",
    [
        [],
        {"decisions": [], "rejection": None, "rule_id": None},
        {"decisions": "rows", "rejection": None, "rule_id": None, "mismatch": None},
        {"decisions": [{"harness": "codex", "unknown": 1}], "rejection": None, "rule_id": None, "mismatch": None},
        {"decisions": [], "rejection": 7, "rule_id": None, "mismatch": None},
        {"decisions": [], "rejection": None, "rule_id": None, "mismatch": {"status": "mismatch"}},
    ],
)
def test_a_malformed_answer_refuses_the_candidate(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    monkeypatch.setattr(candidate, "policy_query", lambda *_args, **_kwargs: answer)

    assert _ask() == candidate.CandidateAnswer([], NATIVE_UNAVAILABLE_REJECTION, None, None)
