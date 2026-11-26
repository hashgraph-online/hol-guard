"""Each reference driver profile maps exactly the tools of its recorded reference server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet.browser_fixtures import recorded_tools

_ROOT = Path(__file__).resolve().parents[1]
_PROFILES = _ROOT / "contributions" / "browser-drivers"
_BUNDLE = _ROOT / "rust" / "crates" / "guard-command" / "src" / "browser_first_party_drivers.rs"

# Profile id, recorded vector directory, default profile mode.
REFERENCE_PROFILES = (
    ("browser.puppeteer-mcp", "puppeteer", "unknown"),
    ("browser.browsermcp", "browsermcp", "shared"),
    ("browser.computer-use", "computer-use", "shared"),
)


def _profile(identity: str) -> dict[str, Any]:
    return json.loads((_PROFILES / f"{identity}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(("identity", "vector", "mode"), REFERENCE_PROFILES)
def test_profile_lists_every_recorded_tool_and_no_other(identity: str, vector: str, mode: str) -> None:
    profiled = sorted(tool["name"] for tool in _profile(identity)["tools"])
    recorded = sorted(tool["name"] for tool in recorded_tools(vector))
    assert profiled == recorded


@pytest.mark.parametrize(("identity", "vector", "mode"), REFERENCE_PROFILES)
def test_every_pointer_names_an_argument_the_tool_takes(identity: str, vector: str, mode: str) -> None:
    schemas = {tool["name"]: tool["inputSchema"]["properties"] for tool in recorded_tools(vector)}
    checked = 0
    for tool in _profile(identity)["tools"]:
        arguments = schemas[tool["name"]]
        shapes = [tool]
        if "discriminator" in tool:
            assert tool["discriminator"] in arguments, tool["name"]
            shapes = list(tool["cases"].values())
            checked += 1
        for shape in shapes:
            for field, pointers in shape.items():
                if field in {"name", "verb"}:
                    continue
                names = pointers["name"] if isinstance(pointers, dict) else pointers
                for name in names:
                    assert name in arguments, (tool["name"], field, name)
                    checked += 1
    assert checked > 0


@pytest.mark.parametrize(("identity", "vector", "mode"), REFERENCE_PROFILES)
def test_the_profile_is_bundled_and_tracked_upstream(identity: str, vector: str, mode: str) -> None:
    profile = _profile(identity)
    assert f"contributions/browser-drivers/{identity}.json" in _BUNDLE.read_text(encoding="utf-8")
    assert (_ROOT / "contracts" / "extensions" / "trust" / f"{identity}.v1.json").is_file()
    assert profile["referenceVersion"]
    assert profile["publisher"]["verified"] is True
    assert profile["profileMode"] == {"default": mode}


def test_a_command_script_tool_is_never_below_privileged() -> None:
    script = next(tool for tool in _profile("browser.browsermcp")["tools"] if tool["name"] == "browser")
    assert script["verb"] == "Other"


def test_every_published_computer_use_action_has_a_case() -> None:
    (computer,) = recorded_tools("computer-use")
    published = set(computer["inputSchema"]["properties"]["action"]["enum"])
    (tool,) = _profile("browser.computer-use")["tools"]
    assert published <= set(tool["cases"])
