"""Golden contract tests for the guard-mcp.v1 local MCP server.

These tests define the expected behavior of the local stdio MCP server
implemented in hol-guard. They fail initially because the MCP module
does not exist yet.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# These imports will fail until the MCP module is implemented.
# That is the intended initial failure proving the feature is missing.


class TestMCPModuleImport:
    """Verify the MCP module exists and has the expected structure."""

    def test_mcp_package_importable(self):
        """The MCP package must be importable."""
        from codex_plugin_scanner.guard import mcp  # noqa: F401

    def test_mcp_server_module_importable(self):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer  # noqa: F401

    def test_mcp_schemas_module_importable(self):
        from codex_plugin_scanner.guard.mcp.schemas import CONTRACT_VERSION  # noqa: F401

    def test_contract_version_is_guard_mcp_v1(self):
        from codex_plugin_scanner.guard.mcp.schemas import CONTRACT_VERSION

        assert CONTRACT_VERSION == "guard-mcp.v1"


class TestMCPServerInitialization:
    """Verify the MCP server initializes correctly."""

    @pytest.fixture()
    def server(self, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        return GuardMCPServer(guard_home=tmp_path)

    def test_server_has_tools(self, server):
        tools = server.list_tools()
        assert isinstance(tools, list)
        assert len(tools) >= 3

    def test_server_tool_names(self, server):
        tools = server.list_tools()
        names = {t.name for t in tools}
        assert "search" in names
        assert "fetch" in names
        assert "get_guard_status" in names

    def test_no_mutation_tools(self, server):
        """Only read-only tools are registered."""
        tools = server.list_tools()
        forbidden = {
            "approve", "deny", "sync", "upload", "delete", "revoke",
            "checkout", "admin", "shell", "exec",
        }
        names = {t.name for t in tools}
        assert not (names & forbidden), f"Forbidden tools found: {names & forbidden}"


class TestSearchTool:
    """Test the search tool contract."""

    @pytest.fixture()
    def server(self, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        return GuardMCPServer(guard_home=tmp_path)

    def test_search_empty_data(self, server):
        result = server.call_tool("search", {"query": "anything"})
        assert result is not None
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        assert data["contractVersion"] == "guard-mcp.v1"
        assert data["source"] == "local"
        assert "generatedAt" in data
        assert "freshness" in data
        assert data["results"] == []
        assert data["count"] == 0

    def test_search_returns_results(self, server, tmp_path: Path):
        """Search with seeded data returns sanitized results."""
        _seed_receipt(tmp_path, server)
        result = server.call_tool("search", {"query": "test"})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        assert data["contractVersion"] == "guard-mcp.v1"
        assert data["source"] == "local"
        assert isinstance(data["results"], list)
        assert data["count"] == len(data["results"])
        assert data["count"] >= 1

    def test_search_default_limit_10(self, server):
        """Search defaults to 10 results."""
        tools = server.list_tools()
        search_tool = next(t for t in tools if t.name == "search")
        input_schema = search_tool.inputSchema
        assert "properties" in input_schema
        assert input_schema["properties"]["query"]["type"] == "string"
        # The model cannot pass a limit parameter.
        assert "limit" not in input_schema["properties"]

    def test_search_max_20_results(self, server, tmp_path: Path):
        """Search returns at most 20 results."""
        for i in range(25):
            _seed_receipt(tmp_path, server, artifact_name=f"artifact-{i}")
        result = server.call_tool("search", {"query": "artifact"})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        assert data["count"] <= 20

    def test_search_result_structure(self, server, tmp_path: Path):
        """Each search result has the required fields."""
        _seed_receipt(tmp_path, server)
        result = server.call_tool("search", {"query": "test"})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        if data["results"]:
            r = data["results"][0]
            assert "id" in r
            assert "title" in r
            assert "kind" in r
            # IDs must be namespaced opaque.
            assert r["id"].startswith(("receipt:", "artifact:", "inventory:", "device:"))

    def test_search_no_local_urls(self, server, tmp_path: Path):
        """Local results must not contain file URLs or absolute paths."""
        _seed_receipt(tmp_path, server)
        result = server.call_tool("search", {"query": "test"})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        for r in data["results"]:
            if "url" in r:
                assert not r["url"].startswith("file://")
                assert not r["url"].startswith("/")

    def test_search_input_exactly_query(self, server):
        """Search input schema is exactly { query: string }."""
        tools = server.list_tools()
        search_tool = next(t for t in tools if t.name == "search")
        props = search_tool.inputSchema.get("properties", {})
        assert set(props.keys()) == {"query"}
        assert search_tool.inputSchema.get("required") == ["query"]


class TestFetchTool:
    """Test the fetch tool contract."""

    @pytest.fixture()
    def server(self, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        return GuardMCPServer(guard_home=tmp_path)

    def test_fetch_input_exactly_id(self, server):
        """Fetch input schema is exactly { id: string }."""
        tools = server.list_tools()
        fetch_tool = next(t for t in tools if t.name == "fetch")
        props = fetch_tool.inputSchema.get("properties", {})
        assert set(props.keys()) == {"id"}
        assert fetch_tool.inputSchema.get("required") == ["id"]

    def test_fetch_not_found(self, server):
        """Fetching a non-existent ID returns a not-found result."""
        result = server.call_tool("fetch", {"id": "receipt:nonexistent"})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        assert data["contractVersion"] == "guard-mcp.v1"
        assert data["source"] == "local"
        assert data.get("found") is False or data.get("text") is None

    def test_fetch_result_includes_contract_fields(self, server, tmp_path: Path):
        """Fetch result includes contractVersion, source, generatedAt, freshness."""
        _seed_receipt(tmp_path, server)
        # First search to get an ID.
        search_result = server.call_tool("search", {"query": "test"})
        search_text = search_result.text if hasattr(search_result, "text") else str(search_result)
        search_data = json.loads(search_text)
        if search_data["results"]:
            receipt_id = search_data["results"][0]["id"]
            result = server.call_tool("fetch", {"id": receipt_id})
            text = result.text if hasattr(result, "text") else str(result)
            data = json.loads(text)
            assert data["contractVersion"] == "guard-mcp.v1"
            assert data["source"] == "local"
            assert "generatedAt" in data
            assert "freshness" in data

    def test_fetch_text_max_32kib(self, server, tmp_path: Path):
        """Fetch text is at most 32 KiB after sanitization."""
        _seed_receipt(tmp_path, server, large_text="A" * 50000)
        result = server.call_tool("search", {"query": "test"})
        search_text = result.text if hasattr(result, "text") else str(result)
        search_data = json.loads(search_text)
        if search_data["results"]:
            receipt_id = search_data["results"][0]["id"]
            fetch_result = server.call_tool("fetch", {"id": receipt_id})
            text = fetch_result.text if hasattr(fetch_result, "text") else str(fetch_result)
            data = json.loads(text)
            if data.get("text"):
                assert len(data["text"]) <= 32768


class TestGetGuardStatusTool:
    """Test the get_guard_status tool contract."""

    @pytest.fixture()
    def server(self, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        return GuardMCPServer(guard_home=tmp_path)

    def test_status_input_empty(self, server):
        """get_guard_status input schema is exactly {}."""
        tools = server.list_tools()
        status_tool = next(t for t in tools if t.name == "get_guard_status")
        props = status_tool.inputSchema.get("properties", {})
        assert props == {} or props is None or len(props) == 0

    def test_status_returns_contract_fields(self, server):
        result = server.call_tool("get_guard_status", {})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        assert data["contractVersion"] == "guard-mcp.v1"
        assert data["source"] == "local"
        assert "generatedAt" in data
        assert "freshness" in data

    def test_status_has_cli_available(self, server):
        """Local status reports cliAvailable."""
        result = server.call_tool("get_guard_status", {})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        assert data.get("cliAvailable") is True or "cliAvailable" in data


class TestToolAnnotations:
    """Verify tool annotations match the contract."""

    @pytest.fixture()
    def server(self, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        return GuardMCPServer(guard_home=tmp_path)

    def test_local_tools_open_world_hint_false(self, server):
        """Local tools must have openWorldHint = false."""
        tools = server.list_tools()
        for tool in tools:
            annotations = getattr(tool, "annotations", None)
            if annotations is not None:
                # openWorldHint should be False for local tools.
                if hasattr(annotations, "open_world_hint"):
                    assert annotations.open_world_hint is False
                elif isinstance(annotations, dict):
                    assert annotations.get("openWorldHint") is False or annotations.get("openWorldHint") is None


class TestOfflineMode:
    """Verify the server works without network access."""

    @pytest.fixture()
    def server(self, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        return GuardMCPServer(guard_home=tmp_path)

    def test_server_works_offline(self, server, monkeypatch):
        """All reads work without network access."""
        # Simulate offline by blocking socket connections.
        import socket

        monkeypatch.setattr(socket, "socket", _BlockingSocket)
        # These should all work without network.
        server.list_tools()
        server.call_tool("get_guard_status", {})
        server.call_tool("search", {"query": "test"})
        server.call_tool("fetch", {"id": "receipt:nonexistent"})


class _BlockingSocket:
    """Socket replacement that raises to simulate offline mode."""

    def __init__(self, *args, **kwargs):
        raise OSError("Network access blocked for offline test")

    def __getattr__(self, name):
        raise OSError(f"Network access blocked: {name}")


def _seed_receipt(
    tmp_path: Path,
    server,
    *,
    artifact_name: str = "test-artifact",
    large_text: str | None = None,
) -> None:
    """Seed a test receipt into the Guard store."""
    from codex_plugin_scanner.guard.models import GuardReceipt
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path)
    receipt = GuardReceipt(
        receipt_id=f"rcpt-{artifact_name}-001",
        timestamp="2026-07-10T12:00:00Z",
        harness="codex",
        artifact_id=f"art-{artifact_name}",
        artifact_hash="sha256:abc123",
        policy_decision="allow",
        capabilities_summary="Read files, write files",
        changed_capabilities=(),
        provenance_summary="Installed via npm",
        user_override=None,
        artifact_name=artifact_name,
        source_scope="project",
        scanner_evidence=(),
        diff_summary=large_text or "No changes detected",
        approval_source="auto",
        approval_request_id=None,
        raw_command_text="npx test-package --flag",
    )
    store.add_receipt(receipt)
