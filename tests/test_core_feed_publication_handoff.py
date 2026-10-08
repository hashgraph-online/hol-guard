from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).parents[1] / ".github/workflows/publish.yml"


def handoff() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["wake-main-core-feeds"]


def test_handoff_requires_verified_stable_publication() -> None:
    job = handoff()
    assert job["needs"] == ["build", "publish-main-assets"]
    for gate in (
        "github.repository == 'hashgraph-online/hol-guard'",
        "github.event_name == 'workflow_dispatch'",
        "github.run_attempt == 1",
        "needs.publish-main-assets.result == 'success'",
        "needs.publish-main-assets.outputs.core_ready == 'true'",
        "needs.build.outputs.channel == 'stable'",
    ):
        assert gate in job["if"]
    assert job["permissions"] == {"actions": "write", "contents": "read"}
    assert job["runs-on"] == "ubuntu-latest"
    assert job["steps"][0]["env"]["VERSION"] == "${{ needs.build.outputs.version }}"
    release = yaml.safe_load(WORKFLOW.read_text())["jobs"]["release-main"]
    assert "publish-main-pypi" in release["needs"]
    assert "needs.publish-main-pypi.result == 'success'" in release["if"]
    assert release["steps"][-2]["name"] == "Create discoverable main release"
    assert "gh attestation verify" in release["steps"][-2]["run"]
    assert release["steps"][-1]["name"] == "Record completed stable publication for future repairs and backfills"


@pytest.mark.parametrize(
    "filename", ["desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml", "wake-desktop-core-alpha-feed.yml"]
)
def test_completion_handoff_has_no_overlapping_triggers(filename: str) -> None:
    workflow = yaml.safe_load((WORKFLOW.parent / filename).read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert "workflow_run" not in triggers
    assert {"push", "pull_request"} <= triggers.keys()
    assert "tests/test_core_feed_publication_handoff.py" in triggers["pull_request"]["paths"]
    if filename.startswith("wake-"):
        assert "issues" in triggers
    else:
        assert {"schedule", "workflow_dispatch"} <= triggers.keys()
        assert "core_version" in triggers["workflow_dispatch"]["inputs"]


@pytest.mark.parametrize("version", ["3.15.1", "3.0.0", "3.15.1a1", "3.015.1", "3.15.1; echo invalid", ""])
@pytest.mark.skipif(os.name == "nt", reason="Publication handoff executes Bash on Ubuntu")
def test_handoff_dispatches_only_canonical_exact_versions(tmp_path: Path, version: str) -> None:
    executable = tmp_path / "gh"
    capture = tmp_path / "calls.jsonl"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "with open(os.environ['CAPTURE_FILE'], 'a') as output:\n"
        "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    executable.chmod(0o700)
    result = subprocess.run(
        ["bash", "-c", handoff()["steps"][0]["run"]],
        env={
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "CAPTURE_FILE": str(capture),
            "GITHUB_REPOSITORY": "hashgraph-online/hol-guard",
            "VERSION": version,
            "PUBLICATION_RUN_ID": "123",
            "PUBLICATION_SOURCE_SHA": "a" * 40,
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if version not in {"3.15.1", "3.0.0"}:
        assert result.returncode == 1
        assert "not canonical stable" in result.stderr
        assert not capture.exists()
        return
    assert result.returncode == 0, result.stderr
    assert [json.loads(line) for line in capture.read_text().splitlines()] == [
        [
            "workflow",
            "run",
            workflow,
            "--repo",
            "hashgraph-online/hol-guard",
            "--ref",
            "main",
            "-f",
            f"core_version={version}",
            "-f",
            "publication_run_id=123",
            "-f",
            "publication_source_sha=" + "a" * 40,
        ]
        for workflow in ("desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml")
    ]
