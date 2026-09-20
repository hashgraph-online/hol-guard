#!/usr/bin/env python3
"""Prepare identical owned Linux/macOS interpreters and retain both arm results."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from scripts.native_qualification_interpreter import (
    InterpreterProvisioningError,
    provision_venv_interpreter,
)


def provision_pair(baseline: Path, candidate: Path) -> dict[str, object]:
    """Attempt each disposable arm independently; failed setup cannot qualify."""
    arms = {}
    for label, python in (("baseline", baseline), ("candidate", candidate)):
        try:
            arms[label] = provision_venv_interpreter(python)
        except InterpreterProvisioningError as error:
            arms[label] = error.evidence
    both_prepared = all(value.get("passed") is True for value in arms.values())
    same_source = (
        both_prepared
        and isinstance(arms["baseline"].get("source_sha256"), str)
        and arms["baseline"]["source_sha256"] == arms["candidate"].get("source_sha256")
    )
    return {
        "schema": "hol-guard.qualification-interpreter-pair.v1",
        "scope": {
            "linux": "disposable_linux_venv_interpreters_only",
            "darwin": "disposable_macos_venv_interpreters_only",
        }.get(sys.platform, "unsupported_platform"),
        "arms": arms,
        "attempted": len(arms),
        "both_prepared": both_prepared,
        "same_original_interpreter_bytes": same_source,
        "passed": both_prepared and same_source,
        "headline_timing_eligible": False,
        "installed_native_qualification_claimed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--candidate-python", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    arguments = parser.parse_args()
    result = provision_pair(arguments.baseline_python, arguments.candidate_python)
    arguments.json.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    arguments.json.write_text(encoded, encoding="utf-8")
    print(encoded, end="", flush=True)
    return 0 if result["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
