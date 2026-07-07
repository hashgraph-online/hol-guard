"""Tests that MCP tool call receipts carry the actual command text.

Verifies that allow_tool_call / block_tool_call extract the command from
MCP tool call arguments and store it as raw_command_text in the receipt.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.mcp_tool_calls import (
    allow_tool_call,
    block_tool_call,
    extract_mcp_command_text,
)
from codex_plugin_scanner.guard.models import GuardArtifact, GuardReceipt
from codex_plugin_scanner.guard.store import GuardStore


def _make_store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


def _make_artifact(
    *,
    name: str = "lean-ctx:ctx_shell",
    harness: str = "codex",
    artifact_id: str = "codex:runtime:mcp:lean-ctx:ctx_shell",
) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name=name,
        harness=harness,
        artifact_type="tool_call",
        source_scope="mcp",
        config_path="/tmp/config.json",
        command="ctx_shell",
        transport="stdio",
        metadata={"server_name": "lean-ctx"},
    )


class TestExtractMcpCommandText:
    def test_extracts_command_from_ctx_shell_arguments(self):
        artifact = _make_artifact()
        arguments = {"command": "git status --short"}
        assert extract_mcp_command_text(artifact, arguments) == "git status --short"

    def test_extracts_cmd_key(self):
        artifact = _make_artifact()
        arguments = {"cmd": "npm install"}
        assert extract_mcp_command_text(artifact, arguments) == "npm install"

    def test_extracts_path_from_ctx_read_arguments(self):
        artifact = _make_artifact(name="lean-ctx:ctx_read")
        arguments = {"path": "/src/index.ts", "mode": "full"}
        result = extract_mcp_command_text(artifact, arguments)
        assert result is not None
        assert "/src/index.ts" in result
        assert "ctx_read" in result

    def test_returns_none_for_empty_command(self):
        artifact = _make_artifact()
        arguments = {"command": "  "}
        assert extract_mcp_command_text(artifact, arguments) is None

    def test_returns_none_for_non_mapping_arguments(self):
        artifact = _make_artifact()
        assert extract_mcp_command_text(artifact, None) is None
        assert extract_mcp_command_text(artifact, "string") is None
        assert extract_mcp_command_text(artifact, 42) is None

    def test_returns_none_for_empty_arguments(self):
        artifact = _make_artifact()
        assert extract_mcp_command_text(artifact, {}) is None

    def test_prefers_command_over_path(self):
        artifact = _make_artifact()
        arguments = {"command": "ls -la", "path": "/tmp"}
        assert extract_mcp_command_text(artifact, arguments) == "ls -la"


class TestAllowToolCallStoresRawCommandText:
    def test_allow_stores_raw_command_text(self, tmp_path: Path):
        store = _make_store(tmp_path)
        artifact = _make_artifact()
        arguments = {"command": "git status --short"}

        receipt = allow_tool_call(
            store=store,
            artifact=artifact,
            artifact_hash="sha256:abc",
            decision_source="policy-allow",
            now="2025-01-01T00:00:00Z",
            signals=(),
            remember=False,
            arguments=arguments,
        )

        assert receipt.raw_command_text == "git status --short"

        stored = store.list_receipts(limit=10)
        assert len(stored) == 1
        assert stored[0]["raw_command_text"] == "git status --short"

    def test_allow_without_arguments_has_no_raw_command_text(self, tmp_path: Path):
        store = _make_store(tmp_path)
        artifact = _make_artifact()

        receipt = allow_tool_call(
            store=store,
            artifact=artifact,
            artifact_hash="sha256:abc",
            decision_source="policy-allow",
            now="2025-01-01T00:00:00Z",
            signals=(),
            remember=False,
        )

        assert receipt.raw_command_text is None

        stored = store.list_receipts(limit=10)
        assert len(stored) == 1
        assert stored[0]["raw_command_text"] is None


class TestBlockToolCallStoresRawCommandText:
    def test_block_stores_raw_command_text(self, tmp_path: Path):
        store = _make_store(tmp_path)
        artifact = _make_artifact()
        arguments = {"command": "rm -rf /tmp/old"}

        receipt = block_tool_call(
            store=store,
            artifact=artifact,
            artifact_hash="sha256:abc",
            decision_source="inline-denied",
            now="2025-01-01T00:00:00Z",
            signals=(),
            arguments=arguments,
        )

        assert receipt.raw_command_text == "rm -rf /tmp/old"

        stored = store.list_receipts(limit=10)
        assert len(stored) == 1
        assert stored[0]["raw_command_text"] == "rm -rf /tmp/old"


class TestReceiptToDictIncludesRawCommandText:
    def test_to_dict_includes_raw_command_text(self):
        receipt = GuardReceipt(
            receipt_id="r-001",
            timestamp="2025-01-01T00:00:00Z",
            harness="codex",
            artifact_id="codex:runtime:mcp:lean-ctx:ctx_shell",
            artifact_hash="sha256:abc",
            policy_decision="allow",
            capabilities_summary="mcp tool call • lean-ctx:ctx_shell",
            changed_capabilities=("runtime_tool_call",),
            provenance_summary="runtime tool call allowed",
            raw_command_text="git status --short",
        )
        payload = receipt.to_dict()
        assert payload["raw_command_text"] == "git status --short"

    def test_to_dict_includes_none_raw_command_text(self):
        receipt = GuardReceipt(
            receipt_id="r-002",
            timestamp="2025-01-01T00:00:00Z",
            harness="codex",
            artifact_id="codex:runtime:mcp:lean-ctx:ctx_shell",
            artifact_hash="sha256:abc",
            policy_decision="allow",
            capabilities_summary="mcp tool call • lean-ctx:ctx_shell",
            changed_capabilities=("runtime_tool_call",),
            provenance_summary="runtime tool call allowed",
        )
        payload = receipt.to_dict()
        assert payload["raw_command_text"] is None
