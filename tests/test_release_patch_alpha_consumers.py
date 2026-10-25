"""Contracts for consumers of the current release/3.0 alpha family."""

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


def test_mcpb_release_packs_with_the_repository_script() -> None:
    workflow = (ROOT / ".github/workflows/publish-mcpb.yml").read_text(encoding="utf-8")

    assert workflow.count("python3 scripts/ci/pack_mcpb.py") == 2
    assert "npm " not in workflow
    assert "mcpb-cli" not in workflow


def test_mcp_registry_authentication_and_publication_exclude_development_releases() -> None:
    """Neither OIDC authentication nor publication may run for a prerelease version."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish-mcp-registry.yml").read_text(encoding="utf-8"))
    steps = {step["name"]: step for step in workflow["jobs"]["publish"]["steps"]}
    expected = " && ".join(
        f"!contains(steps.release.outputs.version, '{marker}')" for marker in ("a", "b", "rc", "dev")
    )
    for name in ("Authenticate with GitHub OIDC", "Publish to MCP registry"):
        assert steps[name]["if"] == expected
