"""A refused command and an absent runtime are reported as different failures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_command_policy_decision as transport
from codex_plugin_scanner.guard.cli.commands_dispatch_policy_dx import _undecided
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

RULES = [
    {
        "rule_id": "no-force",
        "action": "block",
        "expression": {
            "combinator": "all",
            "conditions": [{"operator": "contains", "value": "--force", "case_sensitive": False}],
        },
    }
]
COMMAND = "git push --force"
NOW = "2026-10-17T12:00:00Z"


def _home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(transport, "_resolve_digest_home", lambda home: tmp_path)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(transport, "_payload", lambda response, request, home: None)


def _reply(monkeypatch: pytest.MonkeyPatch, *, bound: bool, status: str, code: str) -> None:
    def answer(**kwargs: Any) -> dict[str, object]:
        request = kwargs["request"]
        digest = "sha256:" + _canonical_request_sha256(request)
        return {
            "schema": transport._RESULT_SCHEMA,
            "request_id": request["request_id"] if bound else "someone-elses-request",
            "request_sha256": digest,
            "status": status,
            "code": code,
        }

    monkeypatch.setattr(transport, "_resident_request", answer)


def _decide() -> transport.CommandPolicyDecisionUnavailableError:
    with pytest.raises(transport.CommandPolicyDecisionUnavailableError) as raised:
        transport.native_command_policy_decision(RULES, COMMAND, now=NOW)
    return raised.value


def test_a_pattern_outside_the_dialect_is_reported_as_the_refusal_it_is(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _home(monkeypatch, tmp_path)
    _reply(monkeypatch, bound=True, status="error", code="native_command_policy_decision_invalid_command_regex")
    error = _decide()
    assert error.code == "native_command_policy_decision_invalid_command_regex"
    assert error.refused


def test_a_reply_for_another_request_is_an_unavailable_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _home(monkeypatch, tmp_path)
    _reply(monkeypatch, bound=False, status="error", code="native_command_policy_decision_rule_invalid")
    error = _decide()
    assert error.code == transport.UNAVAILABLE
    assert not error.refused


def test_an_absent_runtime_never_matches_a_pattern_in_python(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _home(monkeypatch, tmp_path)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda home: False)

    def unreachable(**kwargs: Any) -> dict[str, object]:
        raise AssertionError("an unprovisioned home never reaches the resident")

    monkeypatch.setattr(transport, "_resident_request", unreachable)
    assert _decide().code == transport.UNAVAILABLE


def test_a_document_past_the_rule_ceiling_never_reaches_the_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _home(monkeypatch, tmp_path)

    def unreachable(**kwargs: Any) -> dict[str, object]:
        raise AssertionError("a document this size is refused before the request is sent")

    monkeypatch.setattr(transport, "_resident_request", unreachable)
    rules = [dict(RULES[0], rule_id=f"rule-{index}") for index in range(transport._MAX_RULES + 1)]
    with pytest.raises(transport.CommandPolicyDecisionUnavailableError) as raised:
        transport.native_command_policy_decision(rules, COMMAND, now=NOW)
    assert raised.value.code == transport.TOO_LARGE


def test_the_wire_rule_carries_only_the_fields_the_contract_names(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _home(monkeypatch, tmp_path)
    sent: dict[str, object] = {}

    def capture(**kwargs: Any) -> dict[str, object]:
        sent.update(kwargs["request"])
        return {}

    monkeypatch.setattr(transport, "_resident_request", capture)
    extra = dict(RULES[0], description="not part of the contract")
    with pytest.raises(transport.CommandPolicyDecisionUnavailableError):
        transport.native_command_policy_decision([extra], COMMAND, now=NOW)
    rules = sent["rules"]
    assert isinstance(rules, list)
    assert set(rules[0]) == {"rule_id", "action", "expression"}
    assert set(rules[0]["expression"]["conditions"][0]) == {"operator", "value", "case_sensitive"}


def test_the_command_tells_an_author_which_side_could_not_decide() -> None:
    absent = _undecided(transport.CommandPolicyDecisionUnavailableError())
    assert absent["error"] == transport.UNAVAILABLE
    assert "unavailable" in str(absent["message"])
    refused = _undecided(
        transport.CommandPolicyDecisionUnavailableError("native_command_policy_decision_rule_action_unknown")
    )
    assert "refused to decide this command" in str(refused["message"])
