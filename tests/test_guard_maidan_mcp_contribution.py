"""Maidan's externally contributed MCP policy stays opt-in, endpoint-bound and tightening-only."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
CONTRIBUTIONS = ROOT / "contributions/mcp-servers"
SCHEMA = ROOT / "contracts/mcp-servers/contribution.v1.schema.json"
TRUST = ROOT / "contracts/extensions/trust"

ENDPOINTS = {
    "maidan": ("https://maidan.world/mcp/streamable", ["maidan"]),
    "maidan-worker": ("https://maidan.world/mcp/worker", ["maidan-worker"]),
    "maidan-reviewer": ("https://maidan.world/mcp/reviewer", ["maidan-reviewer"]),
    "maidan-coordinator": ("https://maidan.world/mcp/coordinator", ["maidan-coordinator"]),
}
SLUGS = [*ENDPOINTS, "maidan-stdio"]
GATED = (
    "approval_decide",
    "submit_review",
    "transition_thread",
    "set_land_gate",
    "cancel_thread",
    "create_secret",
    "rotate_token",
    "delegate_token",
    "link_github_issue",
    "register_fsm_hook",
)


def load(slug: str) -> dict:
    return json.loads((CONTRIBUTIONS / f"mcp.{slug}.json").read_text(encoding="utf-8"))


def states(slug: str) -> dict[str, str]:
    return {tool["name"]: tool["state"] for tool in load(slug)["tools"]}


@pytest.mark.parametrize("slug", SLUGS)
def test_maidan_contribution_schema_and_trust(slug: str) -> None:
    payload = load(slug)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(payload)
    assert payload["id"] == f"mcp.{slug}"
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"
    binding = json.loads((TRUST / f"command.mcp-{slug}.v1.json").read_text(encoding="utf-8"))
    assert binding == {
        "extension": f"command.mcp-{slug}",
        "schemaVersion": "guard.extension-trust-binding.v1",
        "trustClass": "external",
    }


@pytest.mark.parametrize("slug", ENDPOINTS)
def test_maidan_hosted_contributions_bind_to_their_endpoint(slug: str) -> None:
    url, names = ENDPOINTS[slug]
    assert load(slug)["launch"] == {"kind": "remote-http", "url": url, "serverNames": names}


def test_maidan_stdio_contribution_binds_to_the_maidan_binary() -> None:
    assert load("maidan-stdio")["launch"] == {"kind": "direct-command", "command": "maidan"}


@pytest.mark.parametrize("slug", SLUGS)
def test_maidan_contributions_only_tighten(slug: str) -> None:
    assert "allow" not in states(slug).values()


@pytest.mark.parametrize("slug", ["maidan", "maidan-stdio"])
def test_maidan_full_surface_reviews_authority_and_blocks_secret_reads(slug: str) -> None:
    declared = states(slug)
    assert declared["resolve_secret"] == "block"
    for name in GATED:
        assert declared[name] == "review"
    assert declared["other"] == "inherit"
    assert len(declared) <= 80


@pytest.mark.parametrize("slug", ["maidan-worker", "maidan-reviewer", "maidan-coordinator"])
def test_maidan_profiles_review_anything_they_do_not_name(slug: str) -> None:
    declared = states(slug)
    full = states("maidan")
    assert declared["other"] == "review"
    for name, state in declared.items():
        if name in GATED:
            assert state == "review"
        if name in full and full[name] in {"review", "block"}:
            assert state == full[name]


@pytest.mark.parametrize("slug", SLUGS)
def test_maidan_tool_names_are_unique(slug: str) -> None:
    names = [tool["name"] for tool in load(slug)["tools"]]
    assert len(names) == len(set(names))
