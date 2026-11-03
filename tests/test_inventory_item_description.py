from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.inventory_item_description import resolve_inventory_item_description
from codex_plugin_scanner.guard.native_inventory_url_redaction import NativeInventoryUrlRedactionError
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError


def test_resolve_inventory_item_description_prefers_metadata_description() -> None:
    result = resolve_inventory_item_description(
        harness="antigravity",
        item_kind="plugin",
        display_name="Pyrefly",
        metadata={"description": "Fast Python type checker and language server."},
        publisher="meta",
    )

    assert result == "Fast Python type checker and language server."


def test_resolve_inventory_item_description_uses_explicit_mcp_tool_description() -> None:
    result = resolve_inventory_item_description(
        harness="cursor",
        item_kind="mcp_tool",
        display_name="read_file",
        metadata={"toolName": "read_file"},
        explicit_description="Read a file from the workspace.",
    )

    assert result == "Read a file from the workspace."


def test_resolve_inventory_item_description_falls_back_for_plugins() -> None:
    result = resolve_inventory_item_description(
        harness="antigravity",
        item_kind="plugin",
        display_name="meta.pyrefly",
        metadata={},
        publisher="meta",
    )

    assert "meta.pyrefly" in result
    assert "extension" in result
    assert "meta" in result
    assert "antigravity" in result


def test_resolve_inventory_item_description_truncates_long_text() -> None:
    long_text = "a" * 600
    result = resolve_inventory_item_description(
        harness="codex",
        item_kind="skill",
        display_name="Long Skill",
        metadata={"description": long_text},
    )

    assert len(result) == 500
    assert result.endswith("…")


def test_resolve_inventory_item_description_falls_back_when_redacted() -> None:
    result = resolve_inventory_item_description(
        harness="cursor",
        item_kind="mcp_tool",
        display_name="read_file",
        metadata={},
        explicit_description="Reads files under /Users/agent/workspace",
    )

    assert "read_file" in result
    assert "MCP tool" in result
    assert "[REDACTED]" not in result


def test_the_native_kind_receives_the_item_and_answers_its_description(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object], **_: object) -> dict[str, object]:
        sent.append((kind, request))
        return {"description": "From native."}

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    monkeypatch.chdir("/")

    result = resolve_inventory_item_description(
        harness="cursor",
        item_kind="plugin",
        display_name="srv",
        metadata={"summary": " s ", "description": 3, "displayDescription": "d"},
        publisher="acme",
        explicit_description="",
        home_dir=Path("/h"),
        workspace_dir=Path("/h/w"),
    )

    assert result == "From native."
    assert sent == [
        (
            "inventory_export_redaction",
            {
                "op": "item_description",
                "harness": "cursor",
                "item_kind": "plugin",
                "display_name": "srv",
                "publisher": "acme",
                "explicit_description": "",
                "metadata_descriptions": [None, " s ", None, "d"],
                "home_dir": "/h",
                "workspace_dir": "/h/w",
                "cwd": "/",
            },
        )
    ]


@pytest.mark.parametrize(
    "answer",
    [{}, {"description": None}, NativeRunnerAuthorityError("native_runner_authority_unavailable")],
)
def test_an_unusable_answer_fails_the_export(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    def fake_native(_kind: str, _request: dict[str, object], **_: object) -> object:
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)

    with pytest.raises(NativeInventoryUrlRedactionError, match="native_inventory_url_redaction_unavailable"):
        _ = resolve_inventory_item_description(harness="codex", item_kind="skill", display_name="s", metadata={})
