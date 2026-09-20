"""Retain finite component identities and observed, explicitly limited outcomes."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


def _identity(binary: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    capabilities = json.loads(subprocess.check_output([str(binary), "capabilities"], timeout=5))
    return {
        "sha256": digest.hexdigest(),
        "bytes": binary.stat().st_size,
        "version": capabilities["runtime_version"],
        "build_id": capabilities["build_sha"],
        "rule_digest": capabilities["rule_digest"],
        "protocol": capabilities["protocol_version"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug-binary", type=Path, required=True)
    parser.add_argument("--release-binary", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--python-junit", type=Path, required=True)
    args = parser.parse_args()
    suite = ET.parse(args.python_junit).getroot()
    suites = list(suite) if suite.tag == "testsuites" else [suite]
    validation = {
        key: sum(int(item.attrib[key]) for item in suites) for key in ("tests", "errors", "failures", "skipped")
    }
    validation["elapsed_seconds"] = sum(float(item.attrib["time"]) for item in suites)
    paths = subprocess.check_output(["git", "diff", "--name-only", "HEAD"], text=True).splitlines()
    implementation = {
        name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
        for name in sorted(paths)
        if name.startswith(("rust/", "src/", "scripts/", "tests/"))
    }
    report = {
        "schema": "guard-claude-launcher-component-evidence.v1",
        "scope": "linux_source_component",
        "installed_artifact": False,
        "qualification_complete": False,
        "activation_qualified": False,
        "frozen_python_revision": "ae33987d0c8675c36a77375e03419aee920825f6",
        "development_base": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "debug": {
            "identity": _identity(args.debug_binary),
            "working_tree_snapshot_retained": False,
            "observed_passes": 23,
            "observed_failures": 1,
            "unreached_cases": 11,
            "failed_case": "expired.PreToolUse",
            "failure": "outer_process_timeout",
            "outer_budget_seconds": 10,
            "elapsed_suite_seconds": 118.26,
            "startup_cause_separately_profiled": False,
        },
        "prior_release_attempts": [
            {
                "passed": 68,
                "elapsed_seconds": 135.03,
                "scope": "before_crlf_input_replay_correction",
                "working_tree_snapshot_retained": False,
            },
            {
                "passed": 71,
                "elapsed_seconds": 118.42,
                "scope": "before_http_deadline_and_fifo_open_corrections",
                "working_tree_snapshot_retained": False,
            },
        ],
        "release": {
            "identity": _identity(args.release_binary),
            "python_validation": validation,
            "implementation_files": implementation,
        },
        "missing_scopes": [
            "actual_installed_daemon",
            "native_launcher_performance_comparison",
            "c16",
            "watch_availability_faults",
            "approval_faults",
            "reference_review_faults",
            "other_platforms",
            "frozen_signed",
            "non_utf8_input_encoding",
            "noncanonical_http_framing",
            "transport_failure_detail_parity",
        ],
    }
    args.json.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
