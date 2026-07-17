"""Contract checks for the pull-request TestPyPI canary workflow."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_pr_canary_uses_trusted_publishing_for_same_repository_prs() -> None:
    workflow_path = ROOT / ".github/workflows/publish.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    assert workflow[True]["pull_request"] == {"branches": ["main", "release/3.1"]}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["publish-testpypi"]
    assert job["permissions"] == {"id-token": "write"}
    assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    assert "github.base_ref != 'release/3.1'" in job["if"]
    assert job["environment"] == "testpypi"
    assert "github.event_name == 'pull_request'" in job["if"]
    publish_step = next(
        step
        for step in job["steps"]
        if isinstance(step, dict) and step.get("uses", "").startswith("pypa/gh-action-pypi-publish")
    )
    assert "password" not in publish_step.get("with", {})
    assert "token" not in publish_step.get("with", {})
    assert "username" not in publish_step.get("with", {})
    assert any(
        step.get("name") == "Keep only the Guard canary distribution" for step in job["steps"] if isinstance(step, dict)
    )
    assert "rm -f dist/plugin_scanner-* dist/plugin-scanner-*" in (ROOT / ".github/workflows/publish.yml").read_text(
        encoding="utf-8"
    )


def test_pr_canary_builds_a_unique_pep440_dev_release() -> None:
    workflow_path = ROOT / ".github/workflows/publish.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")

    assert "def pair(left: int, right: int) -> int:" in workflow_text
    assert "pair(pair(int(os.environ['PR_NUMBER']), int(os.environ['GITHUB_RUN_NUMBER']))" in workflow_text
    assert "scripts/sync_repo_version.py --version" in workflow_text
    assert "python -m build" in workflow_text
    assert "twine check dist/*" in workflow_text
    assert "repository-url: https://test.pypi.org/legacy/" in workflow_text
    assert "TestPyPI canary" in workflow_text
    assert "uv tool install --force --index https://pypi.org/simple" in workflow_text
    assert "--extra-index-url" not in workflow_text
