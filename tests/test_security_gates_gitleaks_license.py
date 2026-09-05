"""Contracts for the Security Gates Gitleaks license environment."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security-gates.yml"


def test_gitleaks_job_reads_repository_license_secret() -> None:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    gitleaks = jobs["gitleaks"]
    assert isinstance(gitleaks, dict)
    env = gitleaks["env"]
    assert isinstance(env, dict)
    assert env["GITLEAKS_LICENSE"] == "${{ secrets.GITLEAKS_LICENSE }}"
