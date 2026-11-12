"""Opt-in real MCP stdio/resident/SDK flow, with explicit operator pairing."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_context_assistance import control, workspace


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("GUARD_CIGAR_TEST_SELECTION") or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the explicitly approved actual CIGAR 0.14.1 candidate",
)
def test_real_guard_mcp_pairing_context_explanation_and_cached_opt_out(native_hook_force: Path, tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    home = tmp_path / "guard"
    source = tmp_path / "workspace"
    source.mkdir()
    (source / "README.md").write_text("Paired MCP fixture uses a reviewed deployment procedure.\n")
    home.mkdir()
    assert control("status", guard_home=home)["effective_enabled"] is False

    def operator(command, request):
        result = subprocess.run(
            [str(native_hook_force), command, "--stdin"],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=45,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    enrolled = operator(
        "context-assistance-enroll-local",
        {
            "schema": "guard-cigar-enroll-local.v1",
            "guard_home": str(home),
            "runtime_id": "mcp-candidate",
            "local_candidate_approved": True,
            "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
            "selection": json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text()),
            "approval": json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text()),
        },
    )
    assert enrolled["ok"] is True
    updated = operator(
        "guard-config-update",
        {
            "schema": "guard-config-update.v1",
            "guard_home": str(home),
            "kind": "settings",
            "value_text": json.dumps(
                {
                    "context_assistance": {
                        "enabled": True,
                        "runtime_id": "mcp-candidate",
                        "features": {"agent_context": True},
                        "sources": {"workspace_documents": True, "source_set_id": "mcp-selected"},
                    }
                }
            ),
        },
    )
    assert updated["ok"] is True
    control("activate", guard_home=home)
    deadline = time.monotonic() + 30
    while not control("status", guard_home=home)["effective_enabled"]:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    granted = workspace(
        "workspace_grant",
        guard_home=home,
        payload={"action": "grant", "workspace": str(source), "app": "codex", "sources": ["README.md"]},
    )["result"]

    async def run():
        server = StdioServerParameters(
            command=sys.executable,
            args=[
                "-B",
                "-c",
                "import sys; from pathlib import Path; "
                "from codex_plugin_scanner.guard.mcp.server import GuardMCPServer; "
                "raise SystemExit(GuardMCPServer(Path(sys.argv[1])).run_stdio())",
                str(home),
            ],
            env=os.environ.copy(),
        )
        async with stdio_client(server) as (read, write), ClientSession(read, write) as client:
            initialized = await client.initialize()
            assert initialized.capabilities.tools and initialized.capabilities.tools.listChanged is True
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert "get_context_status" in names
            assert "get_guard_context" not in names

            async def call(name, arguments=None):
                reply = await client.call_tool(name, arguments or {})
                assert not reply.isError
                return json.loads(reply.content[0].text)

            pending = await call("get_context_status")
            assert pending["data"]["phase"] == "pending"
            assert "credential" not in json.dumps(pending)
            refused = await call("get_guard_context", {"query": "deployment procedure"})
            assert refused["ok"] is False
            workspace(
                "workspace_grant",
                guard_home=home,
                payload={
                    "action": "authorize_agent",
                    "session_id": pending["data"]["session_id"],
                    "scope_id": granted["scope_id"],
                },
            )
            assert (await call("get_context_status"))["data"]["phase"] == "authorized"
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert {"get_context_status", "get_guard_context", "explain_guard_context"} <= names
            result = await call("get_guard_context", {"query": "deployment procedure"})
            assert result["data_role"] is True
            brief = result["data"]["result"]["brief"]
            assert "Paired MCP fixture" in brief["rendered"]
            assert len(brief["citations"]) >= 2
            assert (await call("explain_guard_context", {"snapshot_id": brief["snapshot_id"]}))["ok"] is True
            forged = await call("get_guard_context", {"query": "x", "app": "claude-code", "scope_id": "foreign"})
            assert forged["ok"] is False
            control("stop", guard_home=home)
            assert not (
                {"get_context_status", "get_guard_context", "explain_guard_context"}
                & {tool.name for tool in (await client.list_tools()).tools}
            )
            cached = await call("get_guard_context", {"query": "deployment procedure"})
            assert cached["ok"] is False
            assert cached["error"]["code"] == "native_context_assistance_disabled"

    try:
        asyncio.run(run())
    finally:
        control("stop", guard_home=home)
