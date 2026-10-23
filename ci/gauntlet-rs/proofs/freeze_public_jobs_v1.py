"""Freeze the Python observer's public job allowlist without writing state."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from unittest.mock import patch

from ci.gauntlet.control_plane.agent import Agent


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/agent.py"
SOURCE_SHA256 = "04aed1ecf337746caed8fbd011c59926b47b37719add867628ac6b70a5309215"
NOW = 1_700_000_000.0


def project(jobs: list[dict]) -> dict:
    agent = Agent.__new__(Agent)
    agent.jobs = jobs
    agent.snapshot = {}
    agent.public = Path("/not-written/public")
    agent.lock = threading.RLock()
    copies = []

    def capture(_path, value, mode=0o600):
        assert mode == 0o644
        copies.append(json.loads(json.dumps(value)))

    with patch("ci.gauntlet.control_plane.agent.atomic_json", side_effect=capture), \
         patch("ci.gauntlet.control_plane.agent.time.time", return_value=NOW):
        agent.publish()
    if len(copies) != 1:
        raise AssertionError("one public snapshot required")
    return copies[0]


def main() -> None:
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned Python agent source changed")
    jobs = [
        {"id": "0000000000000001", "kind": "release", "state": "build-failed",
         "created_at": 10, "tag": "v3.48.0", "private_secret": "do-not-publish",
         "local_build": {"status": "build-failed", "source_sha": "a" * 40,
                         "source_archive_sha256": "b" * 64, "error": "compile failed",
                         "log_path": "/var/lib/hol-gauntlet/builds/job/build.log",
                         "version": "3.48.0"}},
        {"id": "0000000000000002", "kind": "release", "state": "archived",
         "created_at": 20, "archived_at": NOW},
        {"id": "0000000000000003", "kind": "pull-request", "state": "queued",
         "created_at": 30, "pr": 41, "title": "Candidate", "sha": "c" * 40,
         "events": [{"at": 25, "phase": "admission", "message": "Queued"}],
         "private_note": "hidden"},
        {"id": "0000000000000004", "kind": "local-candidate", "state": "waiting",
         "created_at": 40, "archived_at": 0, "phase": "source-fetch",
         "vm_progress": {"phase": "transfer", "status": "running"}},
    ]
    mixed = project(jobs)
    many = [{"id": f"{number:016x}", "state": "queued", "created_at": number}
            for number in range(205)]
    limited = project(many)
    print(json.dumps({
        "schema": "gauntlet-public-jobs-fixtures.v1",
        "source_sha256": SOURCE_SHA256,
        "mixed_input": jobs,
        "mixed_output": {"jobs": mixed["jobs"], "archived_jobs": mixed["archived_jobs"]},
        "limit": {"input_count": len(many), "visible_count": len(limited["jobs"]),
                  "first_id": limited["jobs"][0]["id"],
                  "last_id": limited["jobs"][-1]["id"]},
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
