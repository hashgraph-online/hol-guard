"""The benign gate pins every browser driver tool, verb class, provider state and protect row.

Four rules over ``mcp_cases`` of ``tests/fixtures/benign_false_positive_gate.json``:

1. Every tool of the gate's driver stand-ins and of every shipped driver profile
   (``contributions/browser-drivers``) has a row on a server the driver answers as.
2. Every verb a shipped profile maps has an ``allow`` row under a grant preset and a row that is not
   ``allow``, both on tools the profile maps to that verb.
3. Every shipped provider manifest (``contributions/provider-integrations``) has a row, naming it
   in ``provider``, for each verdict and failure state.
4. Every browser protect row (an id starting ``neg-``) has a benign pair: an ``allow`` row for the
   same server and tool.

No profile or manifest ships yet, so rules 1 to 3 also run against a synthetic driver and provider
here; the real checks start biting when the first profile or manifest lands.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet.browser_fixtures import REFERENCE_DRIVER, UNPROFILED_DRIVER, UNPROFILED_TOOLS, recorded_tools
from tests.benign_fp_gate_browser import BROWSER_SERVERS

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "tests" / "fixtures" / "benign_false_positive_gate.json"
_PROFILES = _ROOT / "contributions" / "browser-drivers"
_MANIFESTS = _ROOT / "contributions" / "provider-integrations"

# Presets that grant a site or a verb class (PRD 8.2); an exact saved approval is not a class grant.
GRANT_STATES = frozenset({"site-grant", "session-site-grant", "saved-verb-site"})
# A provider's verdicts and the state it fails into (PRD 8.3).
PROVIDER_STATES = ("provider-ok", "provider-unknown", "provider-caution", "provider-danger", "provider-down")

Row = dict[str, Any]


def gate_rows() -> list[Row]:
    return list(json.loads(_GATE.read_text(encoding="utf-8"))["mcp_cases"])


def _documents(root: Path) -> list[dict[str, Any]]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(root.glob("*.json"))]


def profile_servers(profile: dict[str, Any]) -> set[str]:
    """Server names a profile's tools arrive under: MCP server names and tool namespaces."""
    match = profile.get("match") or {}
    servers = set(match.get("mcpServerNames") or [])
    servers.update(namespace.removesuffix("__") for namespace in match.get("toolNamespaces") or [])
    return servers


def tool_verbs(tool: dict[str, Any]) -> set[str]:
    """Verbs one profile tool maps to; a CDP passthrough maps to none of its own."""
    if "verb" in tool:
        return {tool["verb"]}
    return {case["verb"] for case in (tool.get("cases") or {}).values()}


def missing_tool_rows(servers: set[str], tools: list[str], rows: list[Row]) -> list[str]:
    """Tools with no gate row on any of ``servers``."""
    pinned = {row["tool"] for row in rows if row["server"] in servers}
    return [tool for tool in tools if tool not in pinned]


def verb_class_gaps(profile: dict[str, Any], rows: list[Row]) -> list[str]:
    """Verbs of ``profile`` missing a granted ``allow`` row or a row that is not ``allow``."""
    servers = profile_servers(profile)
    by_verb: dict[str, set[str]] = {}
    for tool in profile["tools"]:
        for verb in tool_verbs(tool):
            by_verb.setdefault(verb, set()).add(tool["name"])
    gaps = []
    for verb, tools in sorted(by_verb.items()):
        mapped = [row for row in rows if row["server"] in servers and row["tool"] in tools]
        if not any(row["expect"] == "allow" and row.get("state", "none") in GRANT_STATES for row in mapped):
            gaps.append(f"{verb}: no allow row under a grant")
        if not any(row["expect"] != "allow" for row in mapped):
            gaps.append(f"{verb}: no row that is not allow")
    return gaps


def provider_gaps(provider: str, rows: list[Row]) -> list[str]:
    """Provider states with no row naming ``provider``."""
    covered = {row.get("state") for row in rows if row.get("provider") == provider}
    return [state for state in PROVIDER_STATES if state not in covered]


def unpaired_protect_rows(rows: list[Row], servers: set[str]) -> list[str]:
    """Browser protect rows without an ``allow`` row for the same server and tool."""
    allowed = {(row["server"], row["tool"]) for row in rows if row["expect"] == "allow"}
    return [
        row["id"]
        for row in rows
        if row["server"] in servers and row["id"].startswith("neg-") and (row["server"], row["tool"]) not in allowed
    ]


def _row(row_id: str, server: str, tool: str, expect: str, **extra: Any) -> Row:
    return {"id": row_id, "server": server, "tool": tool, "arguments": {}, "expect": expect, **extra}


_PILOT = {
    "id": "browser.example-pilot",
    "match": {"mcpServerNames": ["pilot-browser"], "packages": [], "toolNamespaces": [], "harnessTools": []},
    "tools": [
        {"name": "go", "verb": "Navigate"},
        {"name": "act", "discriminator": "kind", "cases": {"press": {"verb": "Click"}, "fill": {"verb": "Type"}}},
        {"name": "raw", "cdpPassthrough": {"method": ["method"]}},
    ],
}


# Rule 1: tools.


def test_every_stand_in_driver_tool_has_a_row() -> None:
    rows = gate_rows()
    reference = [tool["name"] for tool in recorded_tools()]
    assert missing_tool_rows({REFERENCE_DRIVER}, reference, rows) == []
    assert missing_tool_rows({UNPROFILED_DRIVER}, [tool["name"] for tool in UNPROFILED_TOOLS], rows) == []


@pytest.mark.parametrize("profile", _documents(_PROFILES), ids=lambda profile: profile["id"])
def test_every_tool_of_a_shipped_profile_has_a_row(profile: dict[str, Any]) -> None:
    tools = [tool["name"] for tool in profile["tools"]]
    missing = missing_tool_rows(profile_servers(profile), tools, gate_rows())
    assert not missing, f"{profile['id']}: add gate rows for {missing}"


def test_a_profile_tool_without_a_row_is_reported() -> None:
    rows = [_row("pilot-go", "pilot-browser", "go", "setup"), _row("other-act", "elsewhere", "act", "allow")]
    tools = [tool["name"] for tool in _PILOT["tools"]]
    assert missing_tool_rows(profile_servers(_PILOT), tools, rows) == ["act", "raw"]


# Rule 2: verb classes.


@pytest.mark.parametrize("profile", _documents(_PROFILES), ids=lambda profile: profile["id"])
def test_every_verb_of_a_shipped_profile_has_a_granted_allow_and_a_stop(profile: dict[str, Any]) -> None:
    gaps = verb_class_gaps(profile, gate_rows())
    assert not gaps, f"{profile['id']}: {gaps}"


def test_a_verb_needs_both_a_granted_allow_and_a_stop() -> None:
    rows = [
        _row("pilot-go-granted", "pilot-browser", "go", "allow", state="site-grant"),
        _row("neg-pilot-go", "pilot-browser", "go", "review"),
        _row("pilot-act-ungranted", "pilot-browser", "act", "allow"),
        _row("pilot-act-exact", "pilot-browser", "act", "allow", state="saved-exact"),
    ]
    assert verb_class_gaps(_PILOT, rows) == [
        "Click: no allow row under a grant",
        "Click: no row that is not allow",
        "Type: no allow row under a grant",
        "Type: no row that is not allow",
    ]


def test_a_cdp_passthrough_tool_adds_no_verb_of_its_own() -> None:
    assert tool_verbs(_PILOT["tools"][2]) == set()
    assert tool_verbs(_PILOT["tools"][1]) == {"Click", "Type"}


# Rule 3: providers.


@pytest.mark.parametrize("manifest", _documents(_MANIFESTS), ids=lambda manifest: manifest["id"])
def test_every_shipped_provider_has_a_row_per_state(manifest: dict[str, Any]) -> None:
    missing = provider_gaps(manifest["id"], gate_rows())
    assert not missing, f"{manifest['id']}: add gate rows for {missing}"


def test_a_provider_state_without_a_row_is_reported() -> None:
    rows = [
        _row(f"pilot-{state}", REFERENCE_DRIVER, "browser_navigate", "allow", state=state, provider="provider.pilot")
        for state in PROVIDER_STATES[:3]
    ]
    rows.append(_row("other", REFERENCE_DRIVER, "browser_navigate", "allow", state="provider-danger"))
    assert provider_gaps("provider.pilot", rows) == ["provider-danger", "provider-down"]


# Rule 4: protect rows.


def test_every_browser_protect_row_has_a_benign_pair() -> None:
    unpaired = unpaired_protect_rows(gate_rows(), set(BROWSER_SERVERS))
    assert not unpaired, f"add an allow row for the same server and tool: {unpaired}"


def test_a_protect_row_without_an_allow_pair_is_reported() -> None:
    rows = [
        _row("neg-paired", REFERENCE_DRIVER, "browser_navigate", "review"),
        _row("paired", REFERENCE_DRIVER, "browser_navigate", "allow", state="site-grant"),
        _row("neg-alone", REFERENCE_DRIVER, "browser_evaluate", "block"),
        _row("neg-elsewhere", "echo-mcp", "lookup", "review"),
    ]
    assert unpaired_protect_rows(rows, set(BROWSER_SERVERS)) == ["neg-alone"]
