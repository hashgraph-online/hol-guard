#!/usr/bin/env python3
"""Run portable HOL Guard MDM contract checks inside the network-isolated lab."""

from __future__ import annotations

import argparse
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Final

from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION
from codex_plugin_scanner.guard.mdm.lifecycle import user_status, validate_user_home
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy

_LAB_SCHEMA_VERSION: Final = "hol-guard-mdm-local-lab.v1"


def _check_absent_user_status() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="hol-guard-mdm-local-lab-") as temporary_directory:
        home = Path(temporary_directory) / "home"
        home.mkdir()
        status = user_status(home)
        expected = {
            "scope": "user",
            "state": "absent",
            "healthy": False,
            "reasonCodes": ["user_not_activated"],
        }
        for key, value in expected.items():
            if status.get(key) != value:
                raise RuntimeError(f"absent_user_status_{key}_unexpected")
        if any(home.iterdir()):
            raise RuntimeError("absent_user_status_created_files")
    return {"state": "absent", "sideEffectFree": True}


def _check_user_home_rejection() -> dict[str, object]:
    try:
        validate_user_home("relative-home")
    except ValueError as error:
        if str(error) != "mdm_home_must_be_absolute":
            raise RuntimeError("relative_home_rejection_code_unexpected") from error
    else:
        raise RuntimeError("relative_home_was_accepted")
    return {"reasonCode": "mdm_home_must_be_absolute"}


def _check_managed_policy_parser() -> dict[str, object]:
    policy = parse_managed_policy(
        {
            "schemaVersion": MDM_POLICY_SCHEMA_VERSION,
            "settings": {"defaultAction": "block"},
            "lockedSettings": ["defaultAction"],
        }
    )
    if policy.settings != {"defaultAction": "block"} or policy.locked_settings != frozenset({"defaultAction"}):
        raise RuntimeError("managed_policy_round_trip_unexpected")
    return {"schemaVersion": policy.schema_version, "lockedSettings": ["defaultAction"]}


def _result(identifier: str, run_check: Callable[[], dict[str, object]]) -> dict[str, object]:
    try:
        evidence = run_check()
    except Exception as error:  # pragma: no cover - exercised through the process exit path.
        return {"id": identifier, "status": "fail", "error": str(error)}
    return {"id": identifier, "status": "pass", "evidence": evidence}


def build_report() -> dict[str, object]:
    results = [
        _result("absent-user-status", _check_absent_user_status),
        _result("relative-home-rejection", _check_user_home_rejection),
        _result("managed-policy-parser", _check_managed_policy_parser),
    ]
    return {
        "schemaVersion": _LAB_SCHEMA_VERSION,
        "healthy": all(result["status"] == "pass" for result in results),
        "results": results,
        "nativeCertification": {
            "outcome": "not-evaluated",
            "reason": "requires real macOS or Windows MDM enrollment and native signing evidence",
            "requiredGates": [
                {"id": "macos-mdm-enrollment", "platform": "macOS"},
                {"id": "macos-package-signing", "platform": "macOS"},
                {"id": "windows-intune-enrollment", "platform": "Windows"},
                {"id": "windows-msix-signing", "platform": "Windows"},
            ],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the machine-readable lab report")
    args = parser.parse_args()

    report = build_report()
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        outcome = "passed" if report["healthy"] else "failed"
        print(f"HOL Guard MDM local lab {outcome}. Use --json for the machine-readable report.")
    return 0 if report["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
