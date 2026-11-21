from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.runtime.mcp_registry import search_mcp_registry


def _answer(monkeypatch, answer: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def native(kind, args, **_kwargs):
        calls.append((kind, args))
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", native)
    return calls


def test_the_native_search_answers_the_listing(monkeypatch):
    listing = {"results": [], "count": 0, "coverage": "search-page"}
    calls = _answer(monkeypatch, {"listing": listing})
    assert search_mcp_registry("Composio") == listing
    assert calls == [("mcp_registry_search", {"query": "Composio"})]


@pytest.mark.parametrize(
    "code",
    [
        "invalid_registry_search",
        "registry_unavailable",
        "registry_response_too_large",
        "registry_response_invalid",
    ],
)
def test_a_native_refusal_keeps_its_code(monkeypatch, code):
    _answer(monkeypatch, {"error": code})
    with pytest.raises(ValueError, match=code):
        search_mcp_registry("example")


def test_a_non_string_query_is_refused_before_the_runtime(monkeypatch):
    calls = _answer(monkeypatch, {"listing": {}})
    with pytest.raises(ValueError, match="invalid_registry_search"):
        search_mcp_registry(3)  # type: ignore[arg-type]
    assert calls == []


def test_a_native_outage_reports_the_registry_unavailable(monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise authority.NativeRunnerAuthorityError("native_runtime_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", unavailable)
    with pytest.raises(ValueError, match="registry_unavailable"):
        search_mcp_registry("example")
