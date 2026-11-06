"""Exercise Bounded hook outage denials against an immutable installed canary wheel."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.installed_canary_proof import (
    InstalledCanaryError,
    add_installed_canary_arguments,
    load_subject,
    verify_install,
)

# Nine harnesses: 18 process failures, one legacy flag, and two daemon misses each.
# Keep this count independent of collected tests so dropped cases invalidate proof.
EXPECTED_CASES = 9 * (2 * 3 * 3 + 1 + 2)


class _Results:
    def __init__(self) -> None:
        self.passed = 0
        self.skipped = 0

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.when == "call" and report.passed:
            self.passed += 1
        if report.skipped:
            self.skipped += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_installed_canary_arguments(parser)
    args = parser.parse_args()
    try:
        subject = load_subject(args.subject, version=args.version, source_sha=args.source_sha)
        installed = verify_install(subject, args.repo_root)
        results = _Results()
        test_path = args.repo_root / "tests/test_bounded_outage_denial.py"
        with patch.dict(os.environ, {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": ""}):
            status = pytest.main(
                [
                    "--noconftest",
                    "--import-mode=importlib",
                    "-o",
                    "pythonpath=",
                    "-o",
                    "addopts=",
                    "-q",
                    str(test_path),
                ],
                plugins=[results],
            )
        if status != 0 or results.passed != EXPECTED_CASES or results.skipped != 0:
            raise InstalledCanaryError(
                f"Installed bounded hook outage qualification requires all {EXPECTED_CASES} cases to pass"
            )
        for name, module in tuple(sys.modules.items()):
            if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
                origin = getattr(module, "__file__", None)
                if origin is not None and Path(origin).resolve().is_relative_to(args.repo_root.resolve()):
                    raise InstalledCanaryError("Bounded hook outage qualification imported checkout code")
        verified_after = verify_install(subject, args.repo_root)
        if verified_after != installed:
            raise InstalledCanaryError("Installed package identity changed during bounded hook outage qualification")
        report = {
            "schema_version": "hol-guard.installed-bounded-outage-evidence.v1",
            "installed": installed,
            "passed": results.passed,
            "skipped": results.skipped,
            "evaluation_failure_injected": True,
            "local_mode_fixture": True,
            "requested_actions_executed": False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (InstalledCanaryError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
