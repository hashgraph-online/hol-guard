"""Qualify parsed Cursor decisions against an immutable installed canary."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.installed_canary_proof import InstalledCanaryError, load_subject, verify_install
from scripts.run_installed_canary import _parser

# Unavailable: 5 events * 2 modes * 6 faults * 2 import states.
# Decisions: 5 events * 2 modes * 10 policy/exit pairs * 2 reason codes.
# Observations: 2 events * 6 faults; imports unavailable: 5 protected events.
_EXPECTED_GROUPS = {"unavailable": 120, "decisions": 200, "observations": 12, "imports_unavailable": 5}


class _Results:
    def __init__(self) -> None:
        self.passed = 0
        self.skipped = 0
        self.groups = dict.fromkeys(_EXPECTED_GROUPS, 0)

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.when == "call" and report.passed:
            self.passed += 1
            name = report.nodeid.rsplit("::", 1)[-1].split("[", 1)[0]
            group = {
                "test_generated_parsed_cursor_unavailable_denies": "unavailable",
                "test_generated_parsed_cursor_preserves_trusted_decision": "decisions",
                "test_generated_parsed_cursor_observations_continue": "observations",
                "test_generated_parsed_cursor_without_guard_imports_denies": "imports_unavailable",
            }.get(name)
            if group is not None:
                self.groups[group] += 1
        if report.skipped:
            self.skipped += 1


def main() -> int:
    parser = _parser()
    parser.description = __doc__
    args = parser.parse_args()
    try:
        subject = load_subject(args.subject, version=args.version, source_sha=args.source_sha)
        installed = verify_install(subject, args.repo_root)
        results = _Results()
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
                    str(args.repo_root / "tests/test_cursor_parsed_outage_denial.py"),
                ],
                plugins=[results],
            )
        if status != 0 or results.skipped or results.passed != 337 or results.groups != _EXPECTED_GROUPS:
            raise InstalledCanaryError(
                f"Parsed Cursor qualification requires all 337 cases and groups; observed {results.groups}"
            )
        for name, module in tuple(sys.modules.items()):
            if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
                origin = getattr(module, "__file__", None)
                if origin is not None and Path(origin).resolve().is_relative_to(args.repo_root.resolve()):
                    raise InstalledCanaryError("Parsed Cursor qualification imported checkout code")
        if verify_install(subject, args.repo_root) != installed:
            raise InstalledCanaryError("Installed package identity changed during parsed Cursor qualification")
        report = {
            "schema_version": "hol-guard.installed-cursor-parsed-outage-evidence.v1",
            "installed": installed,
            "passed": results.passed,
            "skipped": results.skipped,
            "case_groups": results.groups,
            "evaluation_failure_injected": True,
            "policy_decision_fixture": True,
            "local_mode_fixture": True,
            "generated_adapter_execution": True,
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
