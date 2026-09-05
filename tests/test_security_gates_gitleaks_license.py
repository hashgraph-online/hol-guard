"""Contracts for the Security Gates Gitleaks license environment."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security-gates.yml"
LICENSE_SECRET = "${{ secrets.GITLEAKS_LICENSE }}"
SCAN_STEP_NAMES = frozenset(
    {
        "Run Gitleaks on isolated commit range",
        "Run Gitleaks on working tree",
    }
)


def test_gitleaks_license_is_limited_to_scan_steps() -> None:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    gitleaks = jobs["gitleaks"]
    assert isinstance(gitleaks, dict)
    assert "env" not in gitleaks or "GITLEAKS_LICENSE" not in (gitleaks.get("env") or {})

    steps = gitleaks["steps"]
    assert isinstance(steps, list)
    licensed_steps: list[str] = []
    for step in steps:
        assert isinstance(step, dict)
        name = step.get("name")
        env = step.get("env")
        has_license = isinstance(env, dict) and env.get("GITLEAKS_LICENSE") == LICENSE_SECRET
        if has_license:
            assert isinstance(name, str)
            licensed_steps.append(name)
            continue
        if isinstance(env, dict):
            assert "GITLEAKS_LICENSE" not in env

    assert len(licensed_steps) == len(SCAN_STEP_NAMES)
    assert set(licensed_steps) == SCAN_STEP_NAMES
