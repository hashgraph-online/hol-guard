#!/usr/bin/env python3
"""Execute required negative assertions and record bounded, source-bound results."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.release_required_evidence import REQUIRED_RELEASE_NODE_IDS
from scripts.ci.verify_release_negative_outcomes import (
    REQUIRED_CASES,
    SCHEMA,
    result_digest,
    validate_negative_outcomes,
)


class _Results:
    def __init__(self) -> None:
        self.phases: dict[str, dict[str, str]] = {}

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        phases = self.phases.setdefault(report.nodeid, {})
        if report.when in phases:
            raise RuntimeError("required negative test reported a duplicate phase")
        phases[report.when] = report.outcome


def _check_source(root: Path, source_sha: str) -> None:
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if actual != source_sha:
        raise RuntimeError("negative evidence source does not match checkout")
    changed = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all", "--", "src", "tests", "scripts/ci"],
        cwd=root,
        text=True,
    )
    if changed:
        raise RuntimeError("negative evidence requires unchanged source and tests")


def _run_child(root: Path, destination: Path) -> None:
    results = _Results()
    status = pytest.main(
        [
            *(str(root / node.split("::", 1)[0]) + "::" + node.split("::", 1)[1] for node in REQUIRED_RELEASE_NODE_IDS),
            "--rootdir",
            str(root),
            "-o",
            "addopts=",
            "-m",
            "release",
            "-p",
            "no:terminal",
        ],
        plugins=[results],
    )
    destination.write_text(json.dumps({"exit_code": int(status), "phases": results.phases}), encoding="utf-8")


def collect(root: Path, *, source_sha: str) -> dict[str, object]:
    _check_source(root, source_sha)
    # A fresh interpreter prevents already-imported test modules from another
    # collection or checkout from supplying this run's results.
    module_root = str(Path(__file__).resolve().parents[2])
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((module_root, str(root / "src"), os.environ.get("PYTHONPATH", ""))),
    }
    with tempfile.TemporaryDirectory(prefix="release-negative-") as temporary:
        destination = Path(temporary) / "results.json"
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from pathlib import Path; "
                "from scripts.ci.collect_release_negative_outcomes import _run_child; "
                "_run_child(Path(sys.argv[1]), Path(sys.argv[2]))",
                str(root),
                str(destination),
            ],
            cwd=root,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=300,
        )
        recorded = json.loads(destination.read_text(encoding="utf-8"))
    _check_source(root, source_sha)
    phases = recorded.get("phases")
    if recorded.get("exit_code") != 0 or not isinstance(phases, dict) or set(phases) != set(REQUIRED_RELEASE_NODE_IDS):
        raise RuntimeError("required negative test execution did not complete")
    execution = [
        {"nodeid_sha256": hashlib.sha256(node.encode()).hexdigest(), **phases[node]}
        for node in REQUIRED_RELEASE_NODE_IDS
    ]
    payload = {
        "schema": SCHEMA,
        "source_sha": source_sha,
        "pytest_results": execution,
        "pytest_results_sha256": result_digest(source_sha, execution),
        "cases": [
            {
                "name": name,
                "result": "unsupported" if name == "unavailable-runtime" else "refused",
                "passed": False,
                "evidence": "executed-pytest-assertion",
                "pytest_nodeid_sha256": execution[index]["nodeid_sha256"],
            }
            for index, name in enumerate(REQUIRED_CASES)
        ],
    }
    return validate_negative_outcomes(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        payload = collect(Path(__file__).resolve().parents[2], source_sha=args.source_sha)
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
        print("Required negative assertions did not produce complete source-bound evidence.", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
