from __future__ import annotations

from pathlib import Path

import yaml

from tests.support.ci_workflow import expand_ci_job_actions


def test_ci_runs_trusted_updater_regressions_on_native_windows() -> None:
    """Verify CI runs trusted updater regressions on native windows."""
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "pull_request:\n    branches: [main, release/3.0, release/3.2]" in workflow
    assert "windows-updater:" in workflow
    assert 'python-version: ["3.10", "3.12"]' in workflow
    expanded = expand_ci_job_actions(yaml.safe_load(workflow))
    commands = "\n".join(step.get("run", "") for step in expanded["jobs"]["windows-updater"]["steps"])
    assert "tests/test_guard_update_isolation.py" in commands
    assert "tests/test_guard_update_subprocess.py" in commands
