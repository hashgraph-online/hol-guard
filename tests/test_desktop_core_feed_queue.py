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
