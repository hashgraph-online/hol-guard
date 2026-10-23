"""Freeze the pinned Python release queue's pure decisions without starting it."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from ci.gauntlet.control_plane import releases


ROOT = Path(__file__).resolve().parents[3]
RELEASES = ROOT / "ci/gauntlet/control_plane/releases.py"
AGENT = ROOT / "ci/gauntlet/control_plane/agent.py"
RELEASES_SHA256 = "de558acc1946900d587d2624bfa4128468d649d6bf158f71b628e44dac4598e6"
AGENT_SHA256 = "04aed1ecf337746caed8fbd011c59926b47b37719add867628ac6b70a5309215"
NOW = 1792525000.25
SHA = "a" * 40


def job(number: int, state: str, **fields: object) -> dict:
    return {"id": f"{number:016x}", "state": state, **fields}


class Agent:
    def __init__(self, config: dict, jobs: list[dict]):
        self.config = config
        self.jobs = jobs
        self.saved: list[str] = []

    def save(self, item: dict) -> None:
        self.saved.append(item["id"])


def selected(config: dict, jobs: list[dict], held: bool, active: bool, reasons: bool) -> str | None:
    # Exact predicate/order from pinned Agent.run; the source hash above makes
    # any future change to the owning Python method visible to this fixture.
    halted = any(item["state"] == "unknown" for item in jobs)
    if held or halted or active or reasons:
        return None
    item = next(
        (
            item for item in jobs
            if releases.admitted(config, item)
            and not item.get("status_error") and not item.get("source_error")
            and item["state"] in {"queued", "waiting", "waiting-candidate"}
        ),
        None,
    )
    return None if item is None else item["id"]


def main() -> None:
    for path, expected in [(RELEASES, RELEASES_SHA256), (AGENT, AGENT_SHA256)]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"pinned Python source changed: {path}")

    release = {"discovery_mode": "release-tags", "release_tags": ["v3.48.0", "v3.49.0"]}
    pull = {"discovery_mode": "pull-requests", "release_tags": ["v3.48.0", "v3.49.0"]}
    admission_jobs = [
        job(1, "queued", kind="release", tag="v3.48.0", sha=SHA),
        job(2, "waiting", kind="release", tag="v3.49.0", sha=SHA),
        job(3, "queued", kind="release", tag="v3.50.0", sha=SHA),
        job(4, "queued", kind="release", tag="v3.48.0", archived_at=NOW),
        job(5, "queued", kind="release", tag="v3.48.0", archived_at=0),
        job(6, "queued", kind="pull-request", sha=SHA),
        job(7, "queued", sha=SHA),
        job(8, "queued", kind="local-candidate", sha=SHA, operator_queued=True),
        job(9, "queued", kind="local-candidate", sha=SHA, operator_queued=False),
        job(10, "queued", kind="local-candidate", sha="A" * 40, operator_queued=True),
        job(11, "queued", kind="local-candidate", sha="a" * 39, operator_queued=True),
        job(12, "queued", kind="local-candidate", sha=SHA),
        job(13, "queued", kind="local-candidate", sha=SHA, operator_queued=1),
        job(14, "queued", kind="local-candidate", sha=SHA, operator_queued=True, archived_at=NOW),
        job(15, "queued", kind="release", tag="v3.48.0", archived_at=""),
    ]
    admitted_cases = [
        {"mode": mode, "job": item, "admitted": releases.admitted(config, item)}
        for mode, config in [("release-tags", release), ("pull-requests", pull)]
        for item in admission_jobs
    ]

    initial = [
        job(101, "queued", kind="release", tag="v3.48.0", sha=SHA),
        job(102, "waiting", kind="release", tag="v3.50.0", sha=SHA),
        job(103, "queued", kind="pull-request", sha=SHA),
        job(104, "waiting-candidate", kind="local-candidate", sha=SHA, operator_queued=True),
        job(105, "queued", kind="local-candidate", sha=SHA, operator_queued=False),
        job(106, "superseded", kind="local-candidate", sha=SHA, operator_queued=True),
        job(107, "preparing", kind="pull-request", sha=SHA),
        job(108, "running", kind="pull-request", sha=SHA),
        job(109, "unknown", kind="pull-request", sha=SHA),
        job(110, "waiting-candidate", kind="pull-request", sha=SHA),
        job(111, "passed", kind="pull-request", sha=SHA),
        job(112, "failed", kind="pull-request", sha=SHA, archived_at=NOW - 1),
        job(113, "superseded", kind="local-candidate", sha=SHA, archived_at=NOW - 1),
    ]
    archive_cases = []
    original_time = releases.time.time
    try:
        releases.time.time = lambda: NOW
        for mode, config in [("release-tags", release), ("pull-requests", pull)]:
            agent = Agent(config, copy.deepcopy(initial))
            releases.archive_unwatched(agent)
            archive_cases.append({
                "mode": mode, "before": initial, "after": agent.jobs,
                "saved": agent.saved, "now": NOW,
            })
    finally:
        releases.time.time = original_time

    selection_inputs = [
        ("release-tags", [job(201, "queued", kind="pull-request"), job(202, "queued", kind="release", tag="v3.48.0")], False, False, False),
        ("release-tags", [job(203, "queued", kind="release", tag="v3.48.0", status_error="publish failed"), job(204, "waiting", kind="release", tag="v3.49.0")], False, False, False),
        ("release-tags", [job(205, "queued", kind="release", tag="v3.48.0", source_error="moved"), job(206, "queued", kind="local-candidate", sha=SHA, operator_queued=True)], False, False, False),
        ("release-tags", [job(207, "queued", kind="release", tag="v3.48.0"), job(208, "unknown", kind="pull-request", archived_at=NOW)], False, False, False),
        ("release-tags", [job(209, "queued", kind="release", tag="v3.48.0")], True, False, False),
        ("release-tags", [job(210, "queued", kind="release", tag="v3.48.0")], False, True, False),
        ("release-tags", [job(211, "queued", kind="release", tag="v3.48.0")], False, False, True),
        ("release-tags", [job(212, "passed", kind="release", tag="v3.48.0"), job(213, "waiting-candidate", kind="release", tag="v3.49.0")], False, False, False),
        ("pull-requests", [job(214, "queued", kind="release", tag="v3.48.0"), job(215, "queued", kind="pull-request")], False, False, False),
        ("pull-requests", [job(216, "queued", kind="local-candidate", sha=SHA, operator_queued=True), job(217, "queued", kind="pull-request")], False, False, False),
    ]
    selection_cases = []
    for mode, jobs, held, active, reasons in selection_inputs:
        config = release if mode == "release-tags" else pull
        selection_cases.append({
            "mode": mode, "jobs": jobs, "held": held, "active": active,
            "admission_reasons": reasons,
            "selected": selected(config, jobs, held, active, reasons),
        })
    print(json.dumps({
        "schema": "gauntlet-release-queue-fixtures.v1",
        "releases_sha256": RELEASES_SHA256,
        "agent_sha256": AGENT_SHA256,
        "configs": {"release-tags": release, "pull-requests": pull},
        "admitted": admitted_cases,
        "archived": archive_cases,
        "selected": selection_cases,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
