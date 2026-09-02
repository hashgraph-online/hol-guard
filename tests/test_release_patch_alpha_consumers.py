"""Contracts for consumers of the current release/3.0 alpha family."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_3_0_consumers_follow_the_patch_prerelease_train() -> None:
    publish = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    assert 'alpha/v${TRAIN}.1a*' in publish

    for name in ("publish-mcp-registry.yml", "publish-mcpb.yml"):
        workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        assert "alpha/v3.0.1a*" in workflow
        assert "alpha/v3.0.0a*" not in workflow
