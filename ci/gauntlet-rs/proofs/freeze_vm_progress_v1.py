"""Freeze the pinned Python observer's read-only VM progress call."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from ci.gauntlet.control_plane.agent import Agent


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/agent.py"
SOURCE_SHA256 = "04aed1ecf337746caed8fbd011c59926b47b37719add867628ac6b70a5309215"
OPERATIONS = ROOT / "ci/gauntlet-rs/crates/gauntlet-host-state/operations-defaults-v1.json"
SHA = "a" * 40
JOB = "0123456789abcdef"
DIGEST = "b" * 64


def capture(job: dict) -> dict:
    agent = Agent.__new__(Agent)
    agent.config = json.loads(OPERATIONS.read_text())
    positive = {"source_sha": SHA, "job_id": JOB, "checked_at": 1700000000.25,
                "phase": "not-started"}
    completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(positive), stderr="")
    with patch("ci.gauntlet.control_plane.agent.subprocess.run", return_value=completed) as run:
        response = agent.worker(job, "progress", timeout=12)
    args, kwargs = run.call_args
    return {"argv": args[0], "request": json.loads(kwargs["input"]),
            "timeout_seconds": kwargs["timeout"],
            "capture_output": kwargs["capture_output"], "text": kwargs["text"],
            "response": response}


def main() -> None:
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned Python agent source changed")
    base = {"id": JOB, "sha": SHA}
    print(json.dumps({"schema": "gauntlet-vm-progress-fixtures.v1",
                      "source_sha256": SOURCE_SHA256,
                      "without_deployment": capture(base),
                      "with_deployment": capture({**base, "deployment_digest": DIGEST})},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
