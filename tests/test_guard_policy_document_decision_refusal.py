"""A refused document and an absent runtime are reported as different failures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_document_decision as transport
from codex_plugin_scanner.guard.cli.commands_dispatch_policy_dx import _undecided
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

EVENT = {"harness": "codex", "artifact": "tool:shell"}
ROWS = [{"rule_id": "allow-all", "harness": "codex", "scope": "global", "action": "allow"}]
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


def _decide() -> transport.PolicyDocumentDecisionUnavailableError:
    with pytest.raises(transport.PolicyDocumentDecisionUnavailableError) as raised:
        transport.native_policy_document_decision(ROWS, EVENT, now=NOW)
    return raised.value


def test_a_refused_row_is_reported_as_the_refusal_it_is(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _home(monkeypatch, tmp_path)
    _reply(monkeypatch, bound=True, status="error", code="native_policy_document_decision_row_scope_unknown")
    error = _decide()
    assert error.code == "native_policy_document_decision_row_scope_unknown"
    assert error.refused


def test_a_reply_for_another_request_is_an_unavailable_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _home(monkeypatch, tmp_path)
    _reply(monkeypatch, bound=False, status="error", code="native_policy_document_decision_row_invalid")
    error = _decide()
    assert error.code == transport.UNAVAILABLE
    assert not error.refused


def test_a_document_past_the_row_ceiling_never_reaches_the_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _home(monkeypatch, tmp_path)

    def unreachable(**kwargs: Any) -> dict[str, object]:
        raise AssertionError("a document this size is refused before the request is sent")

    monkeypatch.setattr(transport, "_resident_request", unreachable)
    rows = [dict(ROWS[0], rule_id=f"rule-{index}") for index in range(transport._MAX_ROWS + 1)]
    with pytest.raises(transport.PolicyDocumentDecisionUnavailableError) as raised:
        transport.native_policy_document_decision(rows, EVENT, now=NOW)
    assert raised.value.code == transport.TOO_LARGE


def test_the_command_tells_an_author_which_side_could_not_decide() -> None:
    absent = _undecided(transport.PolicyDocumentDecisionUnavailableError())
    assert absent["error"] == transport.UNAVAILABLE
    assert "unavailable" in str(absent["message"])
    oversized = _undecided(transport.PolicyDocumentDecisionUnavailableError(transport.TOO_LARGE))
    assert oversized["error"] == transport.TOO_LARGE
    assert "more rules" in str(oversized["message"])
    refused = _undecided(
        transport.PolicyDocumentDecisionUnavailableError("native_policy_document_decision_time_invalid")
    )
    assert "refused" in str(refused["message"])
    assert "unavailable" not in str(refused["message"])
