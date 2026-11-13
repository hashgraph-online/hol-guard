"""Telemio's externally contributed hosted MCP policy stays opt-in and tightening-only."""
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "contributions/mcp-servers/mcp.telemio.json"
SCHEMA = ROOT / "contracts/mcp-servers/contribution.v1.schema.json"
TRUST = ROOT / "contracts/extensions/trust/command.mcp-telemio.v1.json"


def test_telemio_mcp_profile_schema_and_policy():
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(profile)
    assert profile["id"] == "mcp.telemio"
    assert profile["launch"] == {
        "kind": "remote-http", "url": "https://mcp.telemio.sh/mcp", "serverNames": ["telemio"]
    }
    assert profile["trustClass"] == "external"
    assert profile["activation"] == "opt-in"
    tools = {tool["name"]: tool["state"] for tool in profile["tools"]}
    assert tools["create_dashboard"] == "review"
    assert tools["other"] == "review"
    for name in (
        "workspace_summary", "query_telemetry", "list_runtimes", "get_runtime",
        "list_dashboards", "list_integrations", "integration_setup", "console_link",
    ):
        assert tools[name] == "inherit"
    assert "allow" not in tools.values()
    assert TRUST.is_file(), "Committed external/opt-in trust binding is required"
