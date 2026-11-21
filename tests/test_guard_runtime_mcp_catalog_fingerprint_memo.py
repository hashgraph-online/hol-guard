"""The proxy reuses the native catalog fingerprint only for an unchanged catalog."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module


def _proxy(catalog: dict[str, dict[str, object]], state: str = "complete") -> SimpleNamespace:
    return SimpleNamespace(
        _tool_catalog=catalog,
        _tool_catalog_state=state,
        _tool_catalog_fingerprint_memo=None,
    )


def _fingerprint(proxy: SimpleNamespace) -> str:
    return runtime_mcp_module.RuntimeMcpGuardProxy._current_catalog_fingerprint(
        cast("runtime_mcp_module.RuntimeMcpGuardProxy", cast(object, proxy))
    )


@pytest.fixture
def native_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []

    def fake_fingerprint(catalog: dict[str, dict[str, object]], *, state: str = "complete") -> str:
        calls.append((repr(sorted(catalog.items())), state))
        return f"sha256:{len(calls)}"

    monkeypatch.setattr(runtime_mcp_module, "_tool_catalog_fingerprint", fake_fingerprint)
    return calls


def test_unchanged_catalog_asks_the_resident_once(native_calls: list[tuple[str, str]]) -> None:
    proxy = _proxy({"safe_echo": {"name": "safe_echo", "description": "Echo"}})

    assert _fingerprint(proxy) == _fingerprint(proxy) == "sha256:1"
    assert len(native_calls) == 1


def test_in_place_catalog_change_asks_again(native_calls: list[tuple[str, str]]) -> None:
    catalog: dict[str, dict[str, object]] = {"safe_echo": {"name": "safe_echo", "description": "Echo"}}
    proxy = _proxy(catalog)
    first = _fingerprint(proxy)

    catalog["safe_echo"]["description"] = "Echo with a changed advertised capability"

    assert _fingerprint(proxy) != first
    assert len(native_calls) == 2


def test_state_change_asks_again(native_calls: list[tuple[str, str]]) -> None:
    proxy = _proxy({"safe_echo": {"name": "safe_echo"}}, state="pending")
    first = _fingerprint(proxy)
    proxy._tool_catalog_state = "complete"

    assert _fingerprint(proxy) != first
    assert native_calls[-1][1] == "complete"


def test_json_types_that_compare_equal_are_not_conflated(native_calls: list[tuple[str, str]]) -> None:
    proxy = _proxy({"tool": {"name": "tool", "inputSchema": {"minimum": 1}}})
    first = _fingerprint(proxy)
    proxy._tool_catalog = {"tool": {"name": "tool", "inputSchema": {"minimum": True}}}

    assert _fingerprint(proxy) != first
    assert len(native_calls) == 2


def test_catalog_that_is_not_plain_json_is_never_memoized(native_calls: list[tuple[str, str]]) -> None:
    proxy = _proxy({"tool": {"name": "tool", "inputSchema": {"maximum": float("nan")}}})

    _ = _fingerprint(proxy)
    _ = _fingerprint(proxy)

    assert len(native_calls) == 2
    assert proxy._tool_catalog_fingerprint_memo is None
