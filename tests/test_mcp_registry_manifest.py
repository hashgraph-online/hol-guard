from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "io.github.hashgraph-online/hol-guard"
OWNERSHIP_MARKER = f"<!-- mcp-name: {SERVER_NAME} -->"


def test_official_mcp_registry_manifest_contract() -> None:
    manifest = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))

    assert manifest["$schema"] == "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
    assert manifest["name"] == SERVER_NAME
    assert manifest["repository"] == {
        "url": "https://github.com/hashgraph-online/hol-guard",
        "source": "github",
    }

    packages = manifest["packages"]
    assert len(packages) == 1
    package = packages[0]
    assert package["registryType"] == "pypi"
    assert package["registryBaseUrl"] == "https://pypi.org"
    assert package["identifier"] == "hol-guard"
    assert package["runtimeHint"] == "uvx"
    assert package["transport"] == {"type": "stdio"}
    # `hol-guard` is already Guard-mode; a leading `guard` would break Registry launches.
    assert [argument["value"] for argument in package["packageArguments"]] == [
        "mcp",
        "serve",
        "--stdio",
    ]
    assert manifest["version"] == package["version"]


def test_pypi_readme_declares_mcp_registry_ownership() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert OWNERSHIP_MARKER in readme
