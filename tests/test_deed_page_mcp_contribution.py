"""deed.page's externally contributed hosted MCP policy stays opt-in and tightening-only."""
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "contributions/mcp-servers/mcp.deed-page.json"
SCHEMA = ROOT / "contracts/mcp-servers/contribution.v1.schema.json"
TRUST = ROOT / "contracts/extensions/trust/command.mcp-deed-page.v1.json"


def test_deed_page_mcp_profile_schema_and_policy():
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(profile)
    assert profile["id"] == "mcp.deed-page"
    assert profile["launch"] == {
        "kind": "remote-http",
        "url": "https://deed.page/mcp",
        "serverNames": ["deed-page", "deed-page-mcp"],
    }
    assert profile["trustClass"] == "external"
    assert profile["activation"] == "opt-in"
    tools = {tool["name"]: tool["state"] for tool in profile["tools"]}
    for name in (
        "publish_site",
        "update_site",
        "delete_site",
        "set_badge",
        "domain_status",
        "get_upgrade_link",
        "other",
    ):
        assert tools[name] == "review"
    for name in (
        "get_site",
        "list_sites",
        "whoami",
        "list_versions",
        "site_analytics",
        "plan_upload",
    ):
        assert tools[name] == "inherit"
    assert "allow" not in tools.values()
    assert "block" not in tools.values()
    assert TRUST.is_file(), "Committed external/opt-in trust binding is required"
