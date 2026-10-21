from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.native_composio_role import NativeComposioRole
from codex_plugin_scanner.guard.runtime import composio_contract
from codex_plugin_scanner.guard.runtime.composio_contract import (
    composio_names_a_wrapper,
    composio_requires_action_review,
    composio_tool_role,
)


def _answer(monkeypatch: pytest.MonkeyPatch, native: NativeComposioRole | None) -> list[str]:
    asked: list[str] = []

    def fake(tool_name: str) -> NativeComposioRole | None:
        asked.append(tool_name)
        return native

    monkeypatch.setattr(composio_contract, "composio_role_native", fake)
    return asked


def test_the_resident_names_the_role_python_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _answer(monkeypatch, NativeComposioRole(role="discovery", requires_action_review=False))
    tool = "mcp__codex_apps__composio__composio_search_tools"
    assert composio_tool_role(tool) == "discovery"
    assert not composio_requires_action_review(tool)
    assert asked == [tool, tool]


def test_review_follows_the_resident_even_against_the_role_it_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Python reports what the runtime decided; it never re-derives review from
    # the role, so a change on the native side needs no second edit here.
    _answer(monkeypatch, NativeComposioRole(role="discovery", requires_action_review=True))
    assert composio_requires_action_review("mcp__a__composio_search_tools")
    _answer(monkeypatch, NativeComposioRole(role="batch", requires_action_review=False))
    assert not composio_requires_action_review("mcp__a__composio_multi_execute_tool")


def test_an_unreachable_resident_names_no_role_and_still_draws_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _answer(monkeypatch, None)
    # No role refuses every discovery-only path, which all gate on an exact
    # "discovery"; the provider review is drawn rather than skipped.
    assert composio_tool_role("mcp__codex_apps__composio__composio_search_tools") is None
    assert composio_requires_action_review("mcp__codex_apps__composio__composio_multi_execute_tool")


def test_an_outage_leaves_a_tool_that_is_not_composios_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reviewing every MCP tool as a provider action during an outage would move
    # the approval identity of tools the contract never placed and refuse to
    # remember their approvals, so the stricter answer stops at the name shape
    # every role shares.
    _answer(monkeypatch, None)
    assert not composio_requires_action_review("mcp__notes__read_note")
    assert not composio_names_a_wrapper("mcp__notes__read_note")
    assert composio_names_a_wrapper("mcp__a__COMPOSIO_Multi_Execute_Tool")
    assert composio_names_a_wrapper("composio_remote_bash_tool")


def test_python_keeps_no_role_table_of_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
    # A role the contract has never published still comes straight through, so
    # the answer cannot be coming from a table on this side.
    _answer(monkeypatch, NativeComposioRole(role="unknown", requires_action_review=True))
    assert composio_tool_role("mcp__codex_apps__composio__composio_search_tools") == "unknown"
