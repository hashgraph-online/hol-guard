"""Release jobs keep full commit and tag history without downloading every historical file."""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def test_full_history_checkouts_are_blobless() -> None:
    config = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    full_history = [
        (job_name, step["with"])
        for job_name, job in config["jobs"].items()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("actions/checkout@") and step.get("with", {}).get("fetch-depth") == 0
    ]
    assert {job_name for job_name, _ in full_history} >= {"build", "reserve-main-tag", "publish-main-pypi", "publish-main-assets"}
    for job_name, options in full_history:
        assert options["filter"] == "blob:none", job_name
        assert "sparse-checkout" not in options, job_name
