"""Contracts for consumers of the current release/3.0 alpha family."""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_release_3_0_consumers_follow_the_patch_prerelease_train() -> None:
    publish = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    assert "alpha/v${TRAIN}.1a*" in publish

    for name in ("publish-mcp-registry.yml", "publish-mcpb.yml"):
        workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        assert "alpha/v3.0.1a*" in workflow
        assert "alpha/v3.0.0a*" not in workflow


def test_mcpb_release_cli_uses_a_clean_lockfile_install() -> None:
    workflow = (ROOT / ".github/workflows/publish-mcpb.yml").read_text(encoding="utf-8")
    package_lock = json.loads((ROOT / ".github/tools/mcpb-cli/package-lock.json").read_text(encoding="utf-8"))

    assert "npm exec" not in workflow
    assert "npm ci --ignore-scripts --prefix .github/tools/mcpb-cli" in workflow
    assert package_lock["packages"]["node_modules/tmp"]["version"] == "0.2.7"
    assert package_lock["packages"]["node_modules/tmp"]["integrity"].startswith("sha512-")


def test_mcp_registry_authentication_and_publication_exclude_development_releases() -> None:
    """Neither OIDC authentication nor publication may run for a prerelease version."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish-mcp-registry.yml").read_text(encoding="utf-8"))
    steps = {step["name"]: step for step in workflow["jobs"]["publish"]["steps"]}
    expected = " && ".join(
        f"!contains(steps.release.outputs.version, '{marker}')" for marker in ("a", "b", "rc", "dev")
    )
    for name in ("Authenticate with GitHub OIDC", "Publish to MCP registry"):
        assert steps[name]["if"] == expected
