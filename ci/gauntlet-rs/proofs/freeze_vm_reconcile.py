"""Freeze the pinned Python host/worker reconcile and finish behavior."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
import sys

sys.path.insert(0, str(ROOT))
from ci.gauntlet.control_plane.agent import Agent  # noqa: E402

SOURCE = "a" * 40
JOB = "0123456789abcdef"
DIGEST = "b" * 64
REPORT = "c" * 64
CONFIG = json.loads(
    (ROOT / "ci/gauntlet-rs/crates/gauntlet-host-state/operations-defaults-v1.json").read_text()
)


class Completed:
    returncode = 0
    stderr = ""

    def __init__(self, response):
        self.stdout = json.dumps(response)


def frozen_worker(job, response):
    agent = object.__new__(Agent)
    agent.config = CONFIG
    captured = {}

    def run(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return Completed(response)

    with patch("ci.gauntlet.control_plane.agent.subprocess.run", run):
        assert agent.worker(job, "reconcile") == response
    assert captured["capture_output"] is True and captured["text"] is True
    return {
        "argv": captured["argv"],
        "request": json.loads(captured["input"]),
        "timeout_seconds": captured["timeout"],
        "response": response,
    }


def frozen_finish(response):
    agent = object.__new__(Agent)
    observations = {}
    agent.save = lambda job: None
    agent.activity = lambda job, phase, message: None
    agent.post = lambda job, state, description: observations.update(
        post_state=state, description=description
    )
    job = {"id": JOB, "sha": SOURCE, "deployment_digest": DIGEST}
    try:
        with patch("ci.gauntlet.control_plane.agent.time.time", return_value=12345.0):
            agent.finish(job, response)
    except ValueError as error:
        return {"error": str(error)}
    return {"state": job["state"], **observations}


def main():
    source_hashes = {
        name: hashlib.sha256((ROOT / f"ci/gauntlet/control_plane/{name}").read_bytes()).hexdigest()
        for name in ("agent.py", "vm_worker.py")
    }
    assert source_hashes == {
        "agent.py": "04aed1ecf337746caed8fbd011c59926b47b37719add867628ac6b70a5309215",
        "vm_worker.py": "fb95cd33bf04c3e68c641972dc6bd5340a8cd87b1ad2948ba131c4a71c60aa9e",
    }
    terminal = {
        "source_sha": SOURCE,
        "job_id": JOB,
        "deployment_digest": DIGEST,
        "exit_code": 0,
        "report_path": f"/var/lib/hol-gauntlet/outputs/{JOB}/report",
        "status": "passed",
        "model_tokens": 0,
        "report_sha256": REPORT,
        "cells": [],
    }
    unknown = {
        "status": "unknown",
        "error": "No terminal worker receipt; inspect VM before admitting more work",
    }
    cases = []
    for name, updates in (
        ("passed", {}),
        ("failed", {"exit_code": 1, "status": "failed"}),
        ("invalid", {"exit_code": 2, "status": "invalid-evidence"}),
        ("failed_code_overrides_pass", {"exit_code": 1}),
        ("missing_report_is_invalid", {"report_sha256": None}),
        ("wrong_source", {"source_sha": "d" * 40}),
        ("wrong_deployment", {"deployment_digest": "e" * 64}),
    ):
        response = {**terminal, **updates}
        cases.append({"name": name, "response": response, "finish": frozen_finish(response)})
    document = {
        "schema": "gauntlet-vm-reconcile-fixtures.v1",
        "source_sha256": source_hashes,
        "without_deployment": frozen_worker({"id": JOB, "sha": SOURCE}, unknown),
        "with_deployment": frozen_worker(
            {"id": JOB, "sha": SOURCE, "deployment_digest": DIGEST}, terminal
        ),
        "finish_cases": cases,
    }
    print(json.dumps(document, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
