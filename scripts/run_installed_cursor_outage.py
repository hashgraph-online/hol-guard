"""Exercise generated Cursor outage denials against an immutable installed wheel."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.installed_canary_proof import InstalledCanaryError, load_subject, verify_install


class _Results:
    def __init__(self) -> None:
        self.passed = 0
        self.skipped = 0
        self.group_passed = {"import_unavailable": 0, "unacknowledged_watch": 0}

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.when == "call" and report.passed:
            self.passed += 1
            test_name = report.nodeid.rsplit("::", 1)[-1].split("[", 1)[0]
            group = {
                "test_generated_cursor_import_failure_denies_unparsed_actions": "import_unavailable",
                "test_generated_cursor_unparsed_input_ignores_unacknowledged_watch": "unacknowledged_watch",
            }.get(test_name)
            if group is not None:
                self.group_passed[group] += 1
        if report.skipped:
            self.skipped += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
                    str(args.repo_root / "tests/test_cursor_outage_denial.py"),
                ],
                plugins=[results],
            )
        if status != 0 or results.passed != 10 or results.skipped != 0:
            raise InstalledCanaryError("Installed Cursor outage qualification requires all ten cases to pass")
        if results.group_passed != {"import_unavailable": 5, "unacknowledged_watch": 5}:
            raise InstalledCanaryError(
                f"Installed Cursor outage qualification requires both five-case groups; observed {results.group_passed}"
            )
        for name, module in tuple(sys.modules.items()):
            if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
                origin = getattr(module, "__file__", None)
                if origin is not None and Path(origin).resolve().is_relative_to(args.repo_root.resolve()):
                    raise InstalledCanaryError("Cursor outage qualification imported checkout code")
        if verify_install(subject, args.repo_root) != installed:
            raise InstalledCanaryError("Installed package identity changed during Cursor outage qualification")
        report = {
            "schema_version": "hol-guard.installed-cursor-outage-evidence.v1",
            "installed": installed,
            "passed": results.passed,
            "skipped": results.skipped,
            "unparsed_input_fixture": True,
            "case_groups": {
                "import_unavailable": {
                    "passed": results.group_passed["import_unavailable"],
                    "guard_imports_unavailable": True,
                },
                "unacknowledged_watch": {
                    "passed": results.group_passed["unacknowledged_watch"],
                    "guard_imports_unavailable": False,
                    "mode_authority_fixture": True,
                },
            },
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
