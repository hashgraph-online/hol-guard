from __future__ import annotations

from pathlib import Path


def test_ci_runs_trusted_updater_regressions_on_native_windows() -> None:
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "branches: [main, release/2.1]" in workflow
    assert "windows-updater:" in workflow
    assert 'python-version: ["3.10", "3.12"]' in workflow
    assert "tests/test_guard_update_isolation.py" in workflow
    assert "tests/test_guard_update_subprocess.py" in workflow
