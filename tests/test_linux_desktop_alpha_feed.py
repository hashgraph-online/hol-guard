"""Linux alpha publication must preserve the stable feed's trust boundaries."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_linux_alpha_dispatch_is_explicit_and_separately_queued() -> None:
    config = yaml.safe_load((ROOT / ".github/workflows/desktop-core-linux-feed.yml").read_text())
    inputs = config[True]["workflow_dispatch"]["inputs"]
    assert inputs["release_channel"]["default"] == "stable"
    assert inputs["release_channel"]["options"] == ["stable", "alpha"]
    job = config["jobs"]["publish-linux-x64"]
    assert job["env"]["RELEASE_CHANNEL"] == "${{ inputs.release_channel || 'stable' }}"
    assert job["concurrency"]["group"].endswith("-feed-linux-x64")
    assert "inputs.release_channel == 'alpha'" in job["concurrency"]["group"]
    steps = {step["name"]: step for step in job["steps"]}
    assert "validate-request" in steps["Validate release channel request"]["run"]
    assert steps["Authorize exact Core source with release provenance"]["run"] == (
        "bash scripts/release/authorize_macos_core_source.sh"
    )
    source = (ROOT / "scripts/release/authorize_macos_core_source.sh").read_text()
    assert '"$SOURCE_SHA" != "$PUBLICATION_SOURCE_SHA"' in source
    registry = steps["Check registry readiness before scheduled or backfill builds"]["run"]
    assert "--channel alpha" in registry
    names = [step["name"] for step in job["steps"]]
    gate = names.index("Require alpha prerelease and tag to still be published")
    assert gate < names.index("Publish immutable Core assets")
    assert "require-prerelease" in steps["Require alpha prerelease and tag to still be published"]["run"]
    assert '--channel "$RELEASE_CHANNEL"' in steps["Create or validate update manifest"]["run"]
    assert '--channel "$RELEASE_CHANNEL"' in steps["Create or validate immutable marker"]["run"]


def test_published_alpha_dispatches_both_desktop_platform_feeds() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    steps = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("name") == "Dispatch the exact published alpha Core version"
    ]
    assert len(steps) == 1
    run = steps[0]["run"]
    for name in ("desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml"):
        command = next(line for line in run.splitlines() if f"gh workflow run {name}" in line)
        assert "-f release_channel=alpha" in command
        assert "publication_run_id=$PUBLICATION_RUN_ID" in command
        assert "publication_source_sha=$PUBLICATION_SOURCE_SHA" in command


@pytest.mark.parametrize(
    ("target", "pattern"),
    [("x86_64-unknown-linux-gnu", "manylinux_*_x86_64"), ("aarch64-apple-darwin", "macosx_*_arm64")],
)
@pytest.mark.parametrize("matching_source", [True, False])
def test_alpha_authorizer_rejects_moved_source_before_platform_download(
    tmp_path: Path, target: str, pattern: str, matching_source: bool
) -> None:
    tools = tmp_path / "bin"
    tools.mkdir()
    git = tools / "git"
    git.write_text('#!/bin/sh\ncase "$*" in *rev-parse*) printf "%s\\n" "$TEST_TAG_SHA";; esac\n')
    gh = tools / "gh"
    gh.write_text('#!/bin/sh\nprintf "download-boundary:%s\\n" "$*"\nexit 17\n')
    git.chmod(0o755)
    gh.chmod(0o755)
    sha = "a" * 40
    env = {
        "PATH": f"{tools}{os.pathsep}/usr/bin:/bin",
        "CORE_VERSION": "3.44.0a1",
        "CORE_TAG": "alpha/v3.44.0a1",
        "RELEASE_BRANCH": "main",
        "RELEASE_CHANNEL": "alpha",
        "RELEASE_TARGET": target,
        "PUBLICATION_SOURCE_SHA": sha,
        "TEST_TAG_SHA": sha if matching_source else "b" * 40,
        "GITHUB_REPOSITORY": "hashgraph-online/hol-guard",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "GITHUB_ENV": str(tmp_path / "env"),
    }
    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/release/authorize_macos_core_source.sh")],
        env=env, capture_output=True, text=True, timeout=10,
    )
    if matching_source:
        assert result.returncode == 17
        assert f"hol_guard-3.44.0a1-*-{pattern}.whl" in result.stdout
    else:
        assert result.returncode == 1
        assert "download-boundary" not in result.stdout
        assert "does not target the dispatched publication source" in result.stderr
