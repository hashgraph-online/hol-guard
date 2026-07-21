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
        assert len(tools) == 6

    def test_server_tool_names(self, server):
        tools = server.list_tools()
        names = {t.name for t in tools}
        assert "search" in names
        assert "fetch" in names
        assert "get_guard_status" in names
        assert "validate_policy" in names
        assert "create_policy" in names
        assert "get_policy_creation" in names

    def test_no_mutation_tools(self, server):
        """Only read-only tools are registered."""
        tools = server.list_tools()
        forbidden = {
            "approve",
            "deny",
            "sync",
            "upload",
            "delete",
            "revoke",
            "checkout",
            "admin",
            "shell",
            "exec",
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


class TestReceiptPagination:
    """Verify search and fetch find receipts beyond the first page.

    Regression tests for Greptile P1 findings on PR #1404.
    """

    @pytest.fixture()
    def server(self, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        return GuardMCPServer(guard_home=tmp_path)

    def test_search_finds_older_receipt_beyond_page(self, server, tmp_path: Path):
        for i in range(250):
            _seed_receipt(tmp_path, server, artifact_name=f"noise-{i:04d}")
        _seed_receipt(tmp_path, server, artifact_name="unique-target")
        result = server.call_tool("search", {"query": "unique-target"})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        assert data["count"] >= 1
        assert any("unique-target" in r.get("title", "") for r in data["results"])

    def test_fetch_finds_older_receipt_beyond_scan_limit(self, server, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.schemas import make_opaque_id

        oldest_receipt_id = "rcpt-oldest-target-001"
        _seed_receipt(tmp_path, server, artifact_name="oldest-target")
        for i in range(250):
            _seed_receipt(tmp_path, server, artifact_name=f"newer-{i:04d}")
        opaque_id = make_opaque_id("receipt", oldest_receipt_id)
        result = server.call_tool("fetch", {"id": opaque_id})
        text = result.text if hasattr(result, "text") else str(result)
        data = json.loads(text)
        assert data["found"] is True
        assert "oldest-target" in data.get("title", "")


class TestCreatePolicyElicitationBinding:
    """The create_policy tool must tie its URL elicitation to the opaque request ID.

    VPC044: the MCP request URL ties to an opaque request_id via
    ``elicitation_id`` so the client can correlate the human-approval URL
    with the staged pending request.
    """

    @pytest.fixture()
    def server(self, tmp_path: Path):
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        return GuardMCPServer(guard_home=tmp_path)

    @pytest.fixture()
    def env_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
        monkeypatch.setenv("HOL_GUARD_MCP_POLICY_WRITE", "1")

    @staticmethod
    def _basic_policy_yaml() -> str:
        return (
            "apiVersion: guard.hashgraphonline.com/v1alpha1\n"
            "kind: GuardPolicy\n"
            "metadata:\n"
            "  id: policy.elicitation-binding-test\n"
            "  name: Elicitation binding test\n"
            "  revision: 1\n"
            "spec:\n"
            "  defaults:\n"
            "    mode: prompt\n"
            "    defaultAction: warn\n"
            "  rolloutState: draft\n"
            "  rules:\n"
            "    - id: rule.block-bad-package\n"
            "      description: Block bad package installs\n"
            "      enabled: true\n"
            "      effect: block\n"
            "      match:\n"
            "        artifacts:\n"
            "          - npm:bad-package\n"
            "        harnesses:\n"
            "          - claude-code\n"
            "      lifetime:\n"
            "        mode: permanent\n"
            "        expiresAt: null\n"
            "      provenance:\n"
            "        source: suggested-memory\n"
            "        createdAt: 2026-07-15T12:00:00Z\n"
            "        createdBy: user-001\n"
        )

    def test_elicit_url_receives_opaque_request_id_as_elicitation_id(
        self, server, tmp_path: Path, env_flags: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from codex_plugin_scanner.guard.policy_document import policy_document_digest
        from codex_plugin_scanner.guard.policy_document_yaml import (
            parse_policy_document_yaml,
        )

        captured: dict[str, object] = {}

        class _FakeContext:
            async def elicit_url(self, *, url: str, message: str, elicitation_id: str) -> object:
                captured["url"] = url
                captured["message"] = message
                captured["elicitation_id"] = elicitation_id
                return object()

        # Provide a trusted loopback origin so create_policy sets approvalUrl.
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.mcp.server.GuardMCPServer._build_approval_url_builder",
            lambda self: lambda request_id: f"http://127.0.0.1:5474/requests/{request_id}",
        )

        class _CapturingMCP:
            def tool(self, *, name: str, description: str, annotations: object):
                def decorator(fn):
                    captured[f"_fn_{name}"] = fn
                    return fn

                return decorator

        from codex_plugin_scanner.guard.mcp.registry import get_tool_definition
        from codex_plugin_scanner.guard.mcp.server import (
            _ORIGINAL_TOOL_DESCRIPTIONS,
            _create_annotations,
        )

        mcp = _CapturingMCP()
        td = get_tool_definition("create_policy")
        assert td is not None
        server._register_fastmcp_tool(
            mcp,
            td,
            _ORIGINAL_TOOL_DESCRIPTIONS.get(td.name, td.description),
            _create_annotations(read_only=td.annotations.read_only, destructive=td.annotations.destructive),
        )

        create_policy_fn = captured["_fn_create_policy"]
        yaml_text = self._basic_policy_yaml()
        document = parse_policy_document_yaml(yaml_text)
        candidate_digest = policy_document_digest(document)

        import asyncio

        result_text = asyncio.run(
            create_policy_fn(
                policyYaml=yaml_text,
                mode="merge",
                candidateDigest=candidate_digest,
                expectedCurrentDigest=None,
                idempotencyKey="elicit-binding-fixture",
                ctx=_FakeContext(),
            )
        )
        result = json.loads(result_text)

        assert result["status"] == "pending"
        request_id = result["requestId"]
        assert request_id  # opaque, non-empty
        assert "approvalUrl" in result
        assert captured.get("elicitation_id") == request_id
        assert captured.get("url") == result["approvalUrl"]

    def test_elicit_url_not_called_when_approval_url_absent(
        self, server, tmp_path: Path, env_flags: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the loopback origin is unavailable, no elicitation fires."""
        captured: dict[str, object] = {}

        class _FakeContext:
            async def elicit_url(self, *, url: str, message: str, elicitation_id: str) -> object:
                captured["called"] = True
                return object()

        class _CapturingMCP:
            def tool(self, *, name: str, description: str, annotations: object):
                def decorator(fn):
                    captured[f"_fn_{name}"] = fn
                    return fn

                return decorator

        from codex_plugin_scanner.guard.mcp.registry import get_tool_definition
        from codex_plugin_scanner.guard.mcp.server import (
            _ORIGINAL_TOOL_DESCRIPTIONS,
            _create_annotations,
        )
        from codex_plugin_scanner.guard.policy_document import policy_document_digest
        from codex_plugin_scanner.guard.policy_document_yaml import (
            parse_policy_document_yaml,
        )

        # Force resolve_loopback_origin to return None so no approvalUrl is set.
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.mcp.server.GuardMCPServer._build_approval_url_builder",
            lambda self: lambda request_id: None,
        )

        mcp = _CapturingMCP()
        td = get_tool_definition("create_policy")
        server._register_fastmcp_tool(
            mcp,
            td,
            _ORIGINAL_TOOL_DESCRIPTIONS.get(td.name, td.description),
            _create_annotations(read_only=td.annotations.read_only, destructive=td.annotations.destructive),
        )

        create_policy_fn = captured["_fn_create_policy"]
        yaml_text = self._basic_policy_yaml()
        document = parse_policy_document_yaml(yaml_text)
        candidate_digest = policy_document_digest(document)

        import asyncio

        result_text = asyncio.run(
            create_policy_fn(
                policyYaml=yaml_text,
                mode="merge",
                candidateDigest=candidate_digest,
                expectedCurrentDigest=None,
                idempotencyKey="no-url-fixture-request",
                ctx=_FakeContext(),
            )
        )
        result = json.loads(result_text)

        assert result["status"] == "pending"
        assert "approvalUrl" not in result
        assert "called" not in captured
