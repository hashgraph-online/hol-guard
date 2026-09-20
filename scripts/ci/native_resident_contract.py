"""Run the preserved resident groups and retain every real failure status."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    results: list[int] = []

    def run(label: str, arguments: list[str], *, native: str | None = None) -> bool:
        environment = os.environ.copy()
        if native is not None:
            environment.update(
                HOL_GUARD_NATIVE=native,
                HOL_GUARD_NATIVE_BINARY=str(ROOT / "rust/target/release/hol-guard-runtime"),
                PYTHONPATH="src",
            )
        result = subprocess.run(arguments, cwd=ROOT, env=environment, check=False)
        results.append(result.returncode)
        print(json.dumps({"residentContract": label, "exitCode": result.returncode}), flush=True)
        return result.returncode == 0

    for name in ("native-managed-resident", "native-sensitive-resident", "native-installation-retirement"):
        directory = ROOT / "artifacts" / name
        directory.mkdir(parents=True, exist_ok=True)
        for filename in ("results.xml", "proof.json"):
            (directory / filename).unlink(missing_ok=True)

    managed_ready = run(
        "managed-fixture",
        [
            "uv",
            "run",
            "--no-sync",
            "pytest",
            "-q",
            "tests/test_native_managed_policy_resident.py::test_managed_resident_fixture_has_genuine_signed_and_local_authority",
            "tests/test_native_managed_control_catalog.py",
        ],
    )
    if managed_ready:
        run(
            "managed",
            [
                "uv",
                "run",
                "--no-sync",
                "pytest",
                "-q",
                "-m",
                "slow",
                "tests/test_native_managed_policy_resident.py",
                "--junitxml=artifacts/native-managed-resident/results.xml",
            ],
            native="force",
        )
    run("managed-results", ["uv", "run", "--no-sync", "python", "scripts/ci/native_managed_resident_evidence.py"])

    auto_ready = run("auto-fixture", ["bash", "scripts/ci/native_origin_resident.sh", "prepare"])
    if auto_ready:
        run("origin", ["bash", "scripts/ci/native_origin_resident.sh", "origin"])
    run("origin-results", ["uv", "run", "--no-sync", "python", "scripts/ci/native_origin_resident_evidence.py"])
    if auto_ready:
        run("retirement", ["bash", "scripts/ci/native_origin_resident.sh", "retirement"])
    run(
        "retirement-results",
        ["uv", "run", "--no-sync", "python", "scripts/ci/native_retirement_resident_evidence.py"],
    )
    return next((code for code in results if code != 0), 0)


if __name__ == "__main__":
    raise SystemExit(main())
