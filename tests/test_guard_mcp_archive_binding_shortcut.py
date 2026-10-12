"""A package request with no external archive never reaches the resident for binding."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.proxy import runtime_mcp


def _patch(monkeypatch: pytest.MonkeyPatch, *, replacements: dict[str, str] | None, required: bool) -> list[dict]:
    calls: list[dict] = []
    monkeypatch.setattr(runtime_mcp, "_verified_external_archive_replacements", lambda _evaluation: replacements)
    monkeypatch.setattr(
        runtime_mcp, "_package_evaluation_requires_external_archive_binding", lambda _evaluation: required
    )

    def bind(params: object, reps: object, **kwargs: object) -> dict:
        calls.append({"params": params, "replacements": reps, **kwargs})
        return {"unused": True}

    monkeypatch.setattr(runtime_mcp, "native_external_archive_bind", bind)
    return calls


def test_no_replacements_and_no_requirement_skips_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, replacements={}, required=False)
    message = {"method": "tools/call", "params": {"big": "x" * (6 * 1024 * 1024)}}
    params = message["params"]
    result = runtime_mcp._bound_external_archive_mcp_request(
        message, params, evaluation=object(), guard_home=Path("/tmp/g")
    )
    assert result == (message, params)
    assert calls == []


def test_required_binding_without_replacements_sends_empty_params(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, replacements={}, required=True)
    result = runtime_mcp._bound_external_archive_mcp_request(
        {"params": {"a": 1}}, {"a": 1}, evaluation=object(), guard_home=Path("/tmp/g")
    )
    assert calls[0]["params"] == {}
    assert calls[0]["requires_binding"] is True
    assert result == ({"params": {"a": 1}}, {"a": 1})
