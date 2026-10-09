"""Serialize writers to each immutable platform asset set while platforms run in parallel."""

from pathlib import Path

import pytest
import yaml


@pytest.mark.parametrize(
    ("name", "publisher", "platform"),
    [
        ("desktop-core-alpha-feed.yml", "publish-macos-arm64", "macos-arm64"),
        ("desktop-core-linux-feed.yml", "publish-linux-x64", "linux-x64"),
    ],
)
def test_platform_feed_writer_queue_retains_pending_versions(name: str, publisher: str, platform: str) -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / name
    config = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    assert "concurrency" not in config
    assert "concurrency" not in config["jobs"]["validate"]
    assert config["jobs"][publisher]["concurrency"] == {
        "group": f"desktop-core-stable-feed-{platform}",
        "cancel-in-progress": False,
        "queue": "max",
    }
    writers = [name for name, job in config["jobs"].items() if job["permissions"]["contents"] == "write"]
    assert writers == [publisher]
    assert "github.event_name != 'pull_request'" in config["jobs"][publisher]["if"]
    assert "tests/test_desktop_core_feed_queue.py" in config[True]["pull_request"]["paths"]
    commands = "\n".join(step.get("run", "") for step in config["jobs"][publisher]["steps"])
    assert "gh release upload" in commands
    assert "gh release edit" not in commands
    assert "gh release create" not in commands


@pytest.mark.parametrize(
    ("name", "publisher"),
    [
        ("desktop-core-alpha-feed.yml", "publish-macos-arm64"),
        ("desktop-core-linux-feed.yml", "publish-linux-x64"),
    ],
)
def test_trusted_dispatch_skips_relint_but_other_events_require_it(name: str, publisher: str) -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / name
    config = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    assert config["jobs"]["validate"]["if"] == "github.event_name != 'workflow_dispatch'"
    job = config["jobs"][publisher]
    assert job["needs"] == "validate"
    condition = job["if"]
    assert condition.startswith("${{ !cancelled() && github.event_name != 'pull_request' &&")
    assert "needs.validate.result == 'success' ||" in condition
    assert "(github.event_name == 'workflow_dispatch' && needs.validate.result == 'skipped')" in condition


@pytest.mark.parametrize("name", ["desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml"])
def test_named_core_version_discovers_one_release(name: str) -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / name
    config = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    publisher = next(job for job_name, job in config["jobs"].items() if job_name != "validate")
    step = next(step for step in publisher["steps"] if step.get("id") == "release")
    script = step["run"]
    assert '[[ "$REQUESTED_CORE_VERSION" =~ ^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$ ]]' in script
    assert 'gh api "repos/${GITHUB_REPOSITORY}/releases/tags/v${REQUESTED_CORE_VERSION}"' in script
    assert 'gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100"' in script
    assert script.index("ready_core_releases.py") > script.index("fi\n")
    assert "--version \"$REQUESTED_CORE_VERSION\"" in script
