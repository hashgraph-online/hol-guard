#!/usr/bin/env python3
"""Run the portable HOL Guard MDM conformance lab and emit bounded evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class Suite:
    name: str
    capabilities: tuple[str, ...]
    paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Result:
    name: str
    capabilities: tuple[str, ...]
    command: tuple[str, ...]
    duration_seconds: float
    outcome: str
    output_digest: str
    summary: str


SUITES = (
    Suite(
        "adapter-contract",
        ("observer", "remediation", "signature", "replay", "mapping"),
        ("tests/test_guard_mdm_adapter_conformance.py", "tests/test_guard_self_protection_schemas.py"),
    ),
    Suite(
        "machine-integrity",
        ("acl", "continuity", "device-key", "manifest", "tamper"),
        (
            "tests/test_guard_mdm_acl.py",
            "tests/test_guard_mdm_continuity.py",
            "tests/test_guard_mdm_device_key.py",
            "tests/test_guard_mdm_device_key_signing.py",
            "tests/test_guard_mdm_integrity.py",
            "tests/test_guard_mdm_integrity_detection.py",
            "tests/test_guard_mdm_manifest.py",
        ),
    ),
    Suite(
        "user-lifecycle",
        ("activate", "repair", "deactivate", "multi-user", "harness-coverage"),
        (
            "tests/test_guard_mdm_lifecycle.py",
            "tests/test_guard_mdm_native.py",
            "tests/test_guard_mdm_harness_coverage.py",
            "tests/test_guard_mdm_harness_coverage_lifecycle.py",
            "tests/test_guard_mdm_supervisor.py",
            "tests/test_guard_mdm_user_health.py",
        ),
    ),
    Suite(
        "health-lease",
        ("health", "lease", "key-rotation", "acknowledgement", "offline-outbox"),
        tuple(str(path.relative_to(ROOT)) for path in sorted((ROOT / "tests").glob("test_guard_mdm_health*.py"))),
    ),
    Suite(
        "enterprise-network",
        ("managed-policy", "proxy", "private-ca", "tls", "offline"),
        ("tests/test_guard_mdm_network.py", "tests/test_guard_mdm_policy.py"),
    ),
)

NATIVE_GATES = (
    "apple-apns-enrollment",
    "apple-supervision",
    "apple-signing-notarization",
    "windows-csp-enrollment",
    "windows-system-context",
    "windows-authenticode-wdac",
    "real-vendor-command-delivery",
)


def _summary(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    matches = [line for line in lines if " passed" in line or " failed" in line or " error" in line]
    return (matches[-1] if matches else (lines[-1] if lines else "no output"))[:240]


def run_suite(suite: Suite) -> Result:
    command = ("pytest", "-p", "no:cacheprovider", "--tb=short", "-q", *suite.paths)
    started = time.monotonic()
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    output = f"{completed.stdout}\n{completed.stderr}"
    return Result(
        name=suite.name,
        capabilities=suite.capabilities,
        command=command,
        duration_seconds=round(time.monotonic() - started, 3),
        outcome="passed" if completed.returncode == 0 else "failed",
        output_digest=hashlib.sha256(output.encode()).hexdigest(),
        summary=_summary(output),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit canonical JSON only")
    parser.add_argument("--output", type=Path, help="write the canonical report to this path")
    parser.add_argument("--suite", action="append", choices=[suite.name for suite in SUITES])
    args = parser.parse_args()
    selected = [suite for suite in SUITES if not args.suite or suite.name in args.suite]
    results = [run_suite(suite) for suite in selected]
    report = {
        "schemaVersion": "hol-guard-mdm-local-lab.v1",
        "mode": "portable-contract",
        "executionPlatform": platform.system().casefold(),
        "healthy": all(result.outcome == "passed" for result in results),
        "results": [
            {
                **asdict(result),
                "durationSeconds": result.duration_seconds,
                "outputDigest": result.output_digest,
            }
            for result in results
        ],
        "nativeCertification": {
            "outcome": "not-evaluated",
            "requiredGates": NATIVE_GATES,
            "reason": "native_platform_or_vendor_required",
        },
    }
    for result in report["results"]:
        result.pop("duration_seconds")
        result.pop("output_digest")
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if args.output is not None:
        args.output.write_text(f"{encoded}\n", encoding="utf-8")
    print(encoded if args.json else json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
