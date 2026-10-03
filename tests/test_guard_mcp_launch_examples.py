"""Catalog example commands for package-launched MCP contributions must be runnable."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_catalog import _values_for_payload, package_launch_example

_CONTRIBUTIONS = Path(__file__).resolve().parents[1] / "contributions/mcp-servers"

_EXPECTED = {
    "npx": "npx -y @scope/pkg",
    "npm": "npm exec --yes @scope/pkg",
    "pnpm": "pnpm dlx @scope/pkg",
    "yarn": "yarn dlx @scope/pkg",
    "pipx": "pipx run @scope/pkg",
    "uvx": "uvx @scope/pkg",
    "bunx": "bunx @scope/pkg",
}


@pytest.mark.parametrize(("launcher", "expected"), sorted(_EXPECTED.items()))
def test_example_uses_the_launcher_form(launcher: str, expected: str) -> None:
    assert package_launch_example(launcher, "@scope/pkg") == expected


@pytest.mark.parametrize("launcher", sorted(_EXPECTED))
def test_example_parses_back_to_the_package(launcher: str) -> None:
    command, *args = shlex.split(package_launch_example(launcher, "@scope/pkg"))
    identity = build_mcp_server_identity(config_path="", command=command, args=tuple(args), transport="stdio")
    assert identity.package_name == "@scope/pkg"


def test_only_npx_examples_carry_the_yes_flag() -> None:
    for path in sorted(_CONTRIBUTIONS.glob("mcp.*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        launch = payload["launch"]
        if launch["kind"] != "package-launcher":
            continue
        permissions = _values_for_payload(payload)["permissions"]
        examples = {getattr(p, "example_command", None) for p in permissions}
        assert examples == {package_launch_example(launch["command"], launch["package"])}, path.name
        (example,) = examples
        assert ("-y" in example.split()) == (launch["command"] == "npx"), path.name
