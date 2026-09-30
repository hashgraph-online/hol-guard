#!/usr/bin/env python3
"""Verify and exercise the pinned Pi/OMP continuation SDK installation."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

PI_PACKAGE = "@earendil-works/pi-coding-agent"
OMP_PACKAGE = "@oh-my-pi/pi-coding-agent"
EXPECTED = {
    PI_PACKAGE: (
        "0.87.1",
        "sha512-m8ArJUtVcQMSe1lLE/Ei7vX/JV7O39sWmWBsXV2NOU70F0qCp8GubA24pT3LnwTmM6LL2xV80/h6sQg85n69ew==",
    ),
    OMP_PACKAGE: (
        "18.1.18",
        "sha512-EcgVLAo8V/p6xrvUFogAzHVaTDK/COBiWkD4VwZqg8QVcJX5PbwzsvV/ucA4M/dUJIP1MuO5z5YI9BRT3i25sw==",
    ),
}
EXPECTED_NODE = "v22.19.0"
EXPECTED_BUN = "1.3.14"
MINIMUM_TESTCASES = 10
REQUIRED_TESTS = {
    "test_installed_pi_runner_cancels_generated_pending_tool_call",
    "test_actual_pi_runner_survives_five_second_tool_call_handler",
    "test_installed_omp_runner_contract_is_outer_signal_aware",
    "test_actual_omp_runner_executes_original_once_and_blocks_late_continuation",
}


def fail(message: str) -> None:
    raise SystemExit(f"pi exact continuation verification failed: {message}")


def command_version(command: str, env: dict[str, str]) -> str:
    executable = shutil.which(command, path=env["PATH"])
    if executable is None:
        fail(f"required executable is unavailable: {command}")
    try:
        completed = subprocess.run(
            [executable, "--version"],
            check=True,
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail(f"could not execute {command} --version: {exc}")
    output = (completed.stdout or completed.stderr).strip().splitlines()
    if not output:
        fail(f"{command} --version returned no output")
    return output[-1].strip()


def verify_lock(lock_path: Path) -> None:
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid package lock: {exc}")
    if lock.get("lockfileVersion") != 3:
        fail("package lock must use lockfileVersion 3")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        fail("package lock has no packages map")

    root = packages.get("")
    if not isinstance(root, dict) or root.get("dependencies") != {
        PI_PACKAGE: "0.87.1",
        OMP_PACKAGE: "18.1.18",
    }:
        fail("root package dependencies are not the reviewed exact SDK versions")

    for package_path, package in packages.items():
        if package_path == "" or not isinstance(package, dict) or package.get("link"):
            continue
        resolved = package.get("resolved")
        if resolved is None:
            continue
        if not resolved.startswith("https://registry.npmjs.org/"):
            fail(f"unapproved package source: {package_path} -> {resolved}")
        if not package.get("integrity"):
            fail(f"registry package has no integrity: {package_path}")

    for package_name, (version, integrity) in EXPECTED.items():
        package = packages.get(f"node_modules/{package_name}")
        if not isinstance(package, dict):
            fail(f"exact package is missing from lock: {package_name}")
        if package.get("version") != version or package.get("integrity") != integrity:
            fail(f"lock entry drifted: {package_name}")


def package_json(package_root: Path) -> dict[str, object]:
    try:
        value = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read installed package metadata at {package_root}: {exc}")
    if not isinstance(value, dict):
        fail(f"invalid package metadata at {package_root}")
    return value


def verify_installed_sdk(prefix: Path) -> dict[str, str]:
    node_modules = prefix / "node_modules"
    pi_root = node_modules / "@earendil-works" / "pi-coding-agent"
    omp_root = node_modules / "@oh-my-pi" / "pi-coding-agent"
    pi_metadata = package_json(pi_root)
    omp_metadata = package_json(omp_root)
    if pi_metadata.get("version") != EXPECTED[PI_PACKAGE][0]:
        fail("installed Pi version drifted")
    if omp_metadata.get("version") != EXPECTED[OMP_PACKAGE][0]:
        fail("installed OMP version drifted")

    required_paths = (
        pi_root / "dist" / "index.js",
        pi_root / "dist" / "bundle" / "cli.js",
        omp_root / "src" / "extensibility" / "extensions" / "runner.ts",
        omp_root / "src" / "extensibility" / "extensions" / "types.ts",
        omp_root / "src" / "session" / "agent-session.ts",
    )
    for path in required_paths:
        if not path.is_file():
            fail(f"required SDK path is missing: {path}")

    path_entries = [str(node_modules / ".bin"), os.environ.get("PATH", "")]
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(path_entries)
    # Tests must import the SDK from this immutable job-local package root. The
    # published CLI is qualified independently below rather than being wrapped.
    env["HOL_GUARD_PI_SDK_ROOT"] = str(pi_root.resolve())
    env["PI_OFFLINE"] = "1"
    env["PI_SKIP_VERSION_CHECK"] = "1"
    env["PI_TELEMETRY"] = "0"

    node_version = command_version("node", env)
    if node_version != EXPECTED_NODE:
        fail(f"Node version must be {EXPECTED_NODE}, got {node_version}")
    bun_version = command_version("bun", env)
    if bun_version != EXPECTED_BUN:
        fail(f"Bun version must be {EXPECTED_BUN}, got {bun_version}")
    pi_cli = shutil.which("pi", path=env["PATH"])
    omp_cli = shutil.which("omp", path=env["PATH"])
    expected_pi_cli = (pi_root / "dist" / "bundle" / "cli.js").resolve()
    if pi_cli is None or Path(pi_cli).resolve() != expected_pi_cli:
        fail("Pi CLI did not resolve to the published job-local package binary")
    if omp_cli is None or not Path(omp_cli).resolve().is_file():
        fail("OMP CLI is unavailable from the installed SDK")
    if not str(Path(omp_cli).resolve()).startswith(str(omp_root.resolve()) + os.sep):
        fail("OMP CLI resolved outside the installed package")
    if command_version("pi", env) == "":
        fail("Pi CLI returned an empty version")
    if command_version("omp", env) == "":
        fail("OMP CLI returned an empty version")
    return env


def run_continuation_tests(env: dict[str, str], junit_path: Path) -> None:
    junit_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/test_pi_exact_continuation.py",
        "--tb=short",
        f"--junitxml={junit_path}",
    ]
    result = subprocess.run(command, env=env, check=False)
    if not junit_path.is_file():
        fail("pytest did not produce the requested JUnit report")
    try:
        suite = ElementTree.parse(junit_path)
    except ElementTree.ParseError as exc:
        fail(f"invalid pytest JUnit report: {exc}")
    cases = suite.findall(".//testcase")
    skipped = [case.get("name", "<unknown>") for case in cases if case.find("skipped") is not None]
    if skipped:
        fail(f"SDK continuation tests were skipped: {', '.join(skipped)}")
    names = {case.get("name", "") for case in cases}
    missing = sorted(name for name in REQUIRED_TESTS if not any(name in case for case in names))
    if len(cases) < MINIMUM_TESTCASES or missing:
        fail(f"insufficient continuation coverage: cases={len(cases)}, missing={missing}")
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--junitxml", type=Path, required=True)
    args = parser.parse_args()
    verify_lock(args.lock)
    env = verify_installed_sdk(args.prefix)
    run_continuation_tests(env, args.junitxml)
    print("Pi/OMP exact continuation verification passed with zero skipped tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
