"""`policy init` asks the native `starters` and `starter` policy document queries for its starters."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from codex_plugin_scanner.guard import native_policy_document
from codex_plugin_scanner.guard.native_policy_document import NativePolicyDocumentError
from codex_plugin_scanner.guard.policy_starters import policy_starters, render_starter_yaml


def _fake(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[tuple[str, dict[str, object]]]:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_query(query: str, body: dict[str, object], **_: object) -> object:
        sent.append((query, body))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(native_policy_document, "policy_query", fake_query)
    return sent


def test_the_listing_comes_from_the_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    listing = [{"id": "blank", "name": "Blank", "summary": "No rules."}]
    sent = _fake(monkeypatch, listing)

    assert policy_starters() == listing
    assert sent == [("starters", {})]


def test_a_starter_is_rendered_with_a_utc_second_stamp(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, "text\n")
    now = datetime(2026, 1, 2, 5, 4, 5, 999, tzinfo=timezone(timedelta(hours=2)))

    assert render_starter_yaml("blank", now=now) == "text\n"
    assert sent == [("starter", {"id": "blank", "created_at": "2026-01-02T03:04:05Z"})]


def test_an_unknown_starter_renders_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, None)

    assert render_starter_yaml("nonsense") is None


@pytest.mark.parametrize(
    "answer",
    [
        {},
        [{"id": "blank", "name": "Blank"}],
        [{"id": "blank", "name": "Blank", "summary": 1}],
        [{"id": "blank", "name": "Blank", "summary": "", "extra": ""}],
        ["blank"],
    ],
)
def test_a_malformed_listing_is_refused(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(NativePolicyDocumentError, match="native_policy_starters_invalid"):
        policy_starters()


@pytest.mark.parametrize("answer", [1, [], {"text": ""}])
def test_a_malformed_starter_is_refused(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(NativePolicyDocumentError, match="native_policy_starters_invalid"):
        render_starter_yaml("blank")


def test_an_unavailable_runtime_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, NativePolicyDocumentError("native_policy_document_unavailable"))

    with pytest.raises(NativePolicyDocumentError, match="native_policy_document_unavailable"):
        policy_starters()
