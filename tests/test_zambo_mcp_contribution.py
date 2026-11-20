"""Zambo's externally contributed hosted MCP policy stays opt-in and tightening-only."""
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "contributions/mcp-servers/mcp.zambo.json"
SCHEMA = ROOT / "contracts/mcp-servers/contribution.v1.schema.json"
TRUST = ROOT / "contracts/extensions/trust/command.mcp-zambo.v1.json"


def test_zambo_mcp_profile_schema_and_policy():
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(profile)
    assert profile["id"] == "mcp.zambo"
    assert profile["launch"] == {
        "kind": "remote-http", "url": "https://zambo.dev/mcp", "serverNames": ["zambo"]
    }
    assert profile["trustClass"] == "external"
    assert profile["activation"] == "opt-in"
    tools = {tool["name"]: tool["state"] for tool in profile["tools"]}
    for name in (
        "day_pass_activate", "day_pass_checkout_link", "day_pass_redeem",
        "handover", "handover_accept", "memory_remember", "workflow_close",
        "workflow_seal", "zambo_universal", "other",
    ):
        assert tools[name] == "review"
    for name in (
        "live_price", "scam_check", "prompt_shield", "handover_status",
        "activity_today", "capability_search", "memory_recall",
        "day_pass_status", "pass_status",
    ):
        assert tools[name] == "inherit"
    assert "allow" not in tools.values()
    assert "block" not in tools.values()
    assert TRUST.is_file(), "Committed external/opt-in trust binding is required"
