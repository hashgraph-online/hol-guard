"""The stored rejection record when the resident cannot write it."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import policy_bundle_parser
from codex_plugin_scanner.guard.native_policy_bundle import (
    NATIVE_UNAVAILABLE_REJECTION,
    PolicyBundleNativeUnavailableError,
)


@pytest.fixture
def resident_down(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_kind: str, _request: dict[str, object]) -> dict[str, object]:
        raise PolicyBundleNativeUnavailableError("native_policy_bundle_authority_unavailable")

    monkeypatch.setattr(policy_bundle_parser, "native_policy_bundle", unavailable)


def test_an_outage_record_is_written_without_asking_the_resident_again(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    def answer(kind: str, _request: dict[str, object]) -> dict[str, object]:
        asked.append(kind)
        return {}

    monkeypatch.setattr(policy_bundle_parser, "native_policy_bundle", answer)
    record = policy_bundle_parser.policy_bundle_rejection_payload(NATIVE_UNAVAILABLE_REJECTION)

    assert asked == []

    assert record["reason"] == NATIVE_UNAVAILABLE_REJECTION
    assert isinstance(record["message"], str)
    assert "could not be reached" in record["message"]


@pytest.mark.usefixtures("resident_down")
def test_without_the_resident_another_record_keeps_only_its_reason() -> None:
    assert policy_bundle_parser.policy_bundle_rejection_payload("wrong_workspace", "rule-1") == {
        "reason": "wrong_workspace"
    }
    assert policy_bundle_parser.policy_bundle_rejection_payload(None) == {"reason": "invalid_policy_bundle"}
    assert policy_bundle_parser.policy_bundle_rejection_message("wrong_workspace") is None


def test_a_malformed_answer_is_not_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        policy_bundle_parser,
        "native_policy_bundle",
        lambda _kind, _request: {"reason": "wrong_workspace", "message": 7},
    )

    assert policy_bundle_parser.policy_bundle_rejection_payload("wrong_workspace") == {"reason": "wrong_workspace"}


def test_the_record_is_asked_for_with_the_reason_and_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[tuple[str, dict[str, object]]] = []

    def answer(kind: str, request: dict[str, object]) -> dict[str, object]:
        asked.append((kind, request))
        return {"reason": "canonical_compile_x", "message": "m", "ruleId": "rule-1"}

    monkeypatch.setattr(policy_bundle_parser, "native_policy_bundle", answer)

    record = policy_bundle_parser.policy_bundle_rejection_payload("canonical_compile_x", "rule-1")

    assert record == {"reason": "canonical_compile_x", "message": "m", "ruleId": "rule-1"}
    assert asked == [("rejection_payload", {"reason": "canonical_compile_x", "rule_id": "rule-1"})]
