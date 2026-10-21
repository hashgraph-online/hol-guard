"""Published wheels must contain the dashboard from the release source."""

from pathlib import Path

import yaml


def test_release_builds_dashboard_before_either_distribution() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/publish.yml").read_text())
    steps = workflow["jobs"]["build"]["steps"]
    dashboard = next(step for step in steps if step.get("name") == "Build dashboard assets from release source")
    assert "if" not in dashboard
    assert dashboard["working-directory"] == "dashboard"
    assert "bun install --frozen-lockfile --ignore-scripts" in dashboard["run"]
    assert "bun run build" in dashboard["run"]
    for name in ("Build Guard package (hol-guard)", "Build scanner package (plugin-scanner)"):
        assert steps.index(dashboard) < next(index for index, step in enumerate(steps) if step.get("name") == name)
