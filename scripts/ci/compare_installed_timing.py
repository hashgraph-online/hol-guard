#!/usr/bin/env python3
"""Compare retained installed builds under one fixed diagnostic schedule."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
import zipfile
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_MEMBER = "codex_plugin_scanner/_native/runtime-manifest.json"
RUNTIME_MEMBER = "codex_plugin_scanner/_native/hol-guard-runtime"
RULE_DIGEST = "3fa3b088382604d99a68ba38fbc4f12dd685200a9fa2d601453104c490bd36fd"
SCHEDULE = ("previous", "current", "current", "previous")
BUILDS = {
    "previous": {
        "source_sha": "20424ce0ddca611769c61ff4ad83d76b9d929c53",
        "wheel_sha256": "b5e527478854f2b889facb5a0ffadf77ca817db5f1a0dc7b165079623c5f29d3",
        "runtime_sha256": "e71c72cf50b5d92418091843e95187b2deb78e0134e53e381f8a7d0a501d8b59",
    },
    "current": {
        "source_sha": "1cd97f7281d26ad5155eef51281a8db0a739543d",
        "wheel_sha256": "4782e88fd2c3dd8abd8a9206daf314e2896129cc5cd794fe5b16b215cbacfbcf",
        "runtime_sha256": "3961a0f01d1e09a0f86048ba9b893dfc99614899b4d98e7df7c72f8dececd866",
    },
}


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_wheel(path: Path, expected: Mapping[str, str]) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("installed_comparison_wheel_invalid")
    if sha256_file(path) != expected["wheel_sha256"]:
        raise ValueError("installed_comparison_wheel_digest_mismatch")
    with zipfile.ZipFile(path) as archive:
        for member, limit in ((MANIFEST_MEMBER, 16_384), (RUNTIME_MEMBER, 32 * 1024 * 1024)):
            matches = [item for item in archive.infolist() if item.filename == member]
            if len(matches) != 1 or not 0 < matches[0].file_size <= limit:
                raise ValueError("installed_comparison_member_invalid")
        manifest = json.loads(archive.read(MANIFEST_MEMBER))
        required = {
            "schema": "hol-guard-native-runtime.v1",
            "source_sha": expected["source_sha"],
            "package_version": "3.0.1",
            "platform_tag": "macosx_13_0_x86_64",
            "target": "x86_64-apple-darwin",
            "protocol_version": 1,
            "rule_digest": RULE_DIGEST,
            "runtime_sha256": expected["runtime_sha256"],
            "runtime_size": 5_916_868,
        }
        if (
            type(manifest) is not dict
            or manifest.keys() != required.keys()
            or any(type(manifest[key]) is not type(value) or manifest[key] != value for key, value in required.items())
        ):
            raise ValueError("installed_comparison_manifest_mismatch")
        with archive.open(RUNTIME_MEMBER) as runtime:
            actual_digest = hashlib.file_digest(runtime, "sha256").hexdigest()
        if actual_digest != expected["runtime_sha256"]:
            raise ValueError("installed_comparison_runtime_digest_mismatch")
        if archive.getinfo(RUNTIME_MEMBER).file_size != required["runtime_size"]:
            raise ValueError("installed_comparison_runtime_size_mismatch")
    return {**required, "wheel_sha256": expected["wheel_sha256"]}


def bounded_number(value: object, maximum: float) -> float | int | None:
    if type(value) not in (float, int) or not 0 <= value <= maximum:
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def capacity_state(session: Any) -> dict[str, object]:
    """Read counters only; never issue a hook request or warm a native client."""
    import resource

    started = time.perf_counter()
    stats = session.daemon._server.hook_process_runner.stats()
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    result: dict[str, object] = {
        "workers": {
            name: bounded_number(stats.get(name), 4096)
            for name in ("target", "workers", "ready", "busy", "starting", "queued")
        },
        "observer_threads": bounded_number(threading.active_count(), 4096),
        "load_average": [bounded_number(value, 4096) for value in os.getloadavg()],
        "self_user_seconds": bounded_number(own.ru_utime, 86_400),
        "self_system_seconds": bounded_number(own.ru_stime, 86_400),
        "reaped_children_user_seconds": bounded_number(children.ru_utime, 86_400),
        "reaped_children_system_seconds": bounded_number(children.ru_stime, 86_400),
    }
    result["observation_ms"] = round((time.perf_counter() - started) * 1000, 6)
    return result


def safe_capacity_state(session: Any) -> dict[str, object]:
    try:
        return capacity_state(session)
    except Exception:
        return {"available": False}


def observed_call(
    original: Callable[..., Any],
    observations: list[dict[str, object]],
    phase: str,
    *,
    capacity: bool = False,
) -> Callable[..., Any]:
    def call(*args: Any, **kwargs: Any) -> Any:
        item: dict[str, object] = {"phase": phase}
        if capacity:
            item["before"] = safe_capacity_state(args[0])
        started = time.perf_counter()
        try:
            result = original(*args, **kwargs)
            item["completed"] = True
            return result
        finally:
            item["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 6)
            if capacity:
                item["after"] = safe_capacity_state(args[0])
            observations.append(item)

    return call


def run_worker(build: str, output: Path) -> int:
    if str(ROOT) not in sys.path:
        sys.path.append(str(ROOT))
    import importlib.metadata

    import codex_plugin_scanner
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from scripts import bench_guard_native_installed_slo as benchmark
    from scripts import native_slo_capacity

    distribution = importlib.metadata.distribution("hol-guard")
    installed_package = Path(distribution.locate_file("codex_plugin_scanner/__init__.py")).resolve()
    if Path(codex_plugin_scanner.__file__).resolve() != installed_package:
        raise RuntimeError("installed_comparison_package_origin_mismatch")

    def stop_observation(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, stop_observation)
    benchmark._clear_proof_overrides()
    identity = native_runtime_status().identity
    if identity is None or sha256_file(identity.path) != BUILDS[build]["runtime_sha256"]:
        raise RuntimeError("installed_comparison_installed_runtime_mismatch")
    phases: list[dict[str, object]] = []
    originals = []
    result = None
    failure_type = None
    try:
        for module, name, phase, capacity in (
            (benchmark, "_run_cold", "cold", False),
            (benchmark, "_run_warm", "warm", False),
            (benchmark, "_run_sizes", "sizes", False),
            (benchmark, "_run_recovery", "recovery", False),
            (native_slo_capacity, "_measure_c16", "c16", True),
            (native_slo_capacity, "_measure_rss_and_c64", "rss_and_c64", False),
        ):
            original = getattr(module, name)
            originals.append((module, name, original))
            setattr(module, name, observed_call(original, phases, phase, capacity=capacity))
        result = benchmark.run_slo(
            identity.path,
            warm_iterations=2,
            cold_iterations=2,
            recovery_iterations=2,
            readiness_samples=2,
            include_capacity=True,
        )
    except Exception as error:
        failure_type = type(error).__name__
        if failure_type not in {"RuntimeError", "ValueError", "OSError", "TimeoutError", "AssertionError"}:
            failure_type = "unclassified_exception"
    finally:
        for module, name, original in originals:
            setattr(module, name, original)
    report = {
        "schema": "guard-installed-timing-observation.v1",
        "build": build,
        "source_sha": BUILDS[build]["source_sha"],
        "runtime_sha256": BUILDS[build]["runtime_sha256"],
        "runtimeAcceptance": False,
        "phases": phases,
        "failure_type": failure_type,
        "slo": result,
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if isinstance(result, dict) and result.get("passed") is True else 1


def run_isolated(
    command: list[str],
    *,
    cwd: Path,
    check: bool,
    capture_output: bool,
    timeout: float,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    if check or not capture_output:
        raise ValueError("installed_comparison_process_options_invalid")
    with subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as child:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
            try:
                child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=5)
            raise
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)


def run_schedule(
    wheels: Mapping[str, Path],
    output: Path,
    execute: Callable[..., subprocess.CompletedProcess] = run_isolated,
) -> int:
    output.mkdir(parents=True, exist_ok=False)
    manifests = {name: verify_wheel(wheels[name], BUILDS[name]) for name in BUILDS}
    report: dict[str, object] = {
        "schema": "guard-installed-timing-comparison.v1",
        "schedule": list(SCHEDULE),
        "runtimeAcceptance": False,
        "manifests": manifests,
        "observations": [],
    }
    entries: list[dict[str, object]] = []
    try:
        for index, name in enumerate(SCHEDULE, 1):
            stem = f"{index:02d}-{name}"
            installed = execute(
                [
                    "uv",
                    "pip",
                    "install",
                    "--python",
                    sys.executable,
                    "--no-deps",
                    "--force-reinstall",
                    str(wheels[name]),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                timeout=120,
            )
            entry: dict[str, object] = {"order": index, "build": name, "installed": installed.returncode == 0}
            entries.append(entry)
            if installed.returncode != 0:
                break
            observed = execute(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    name,
                    "--output",
                    str(output / f"{stem}.json"),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                timeout=480,
                env={**os.environ, "NATIVE_STOP_DIAGNOSTIC_PATH": str(output / f"{stem}-stop.json")},
            )
            entry["exit_code"] = observed.returncode
            report_path = output / f"{stem}.json"
            if report_path.is_file():
                observation = json.loads(report_path.read_text(encoding="utf-8"))
                valid = (
                    observation.get("schema") == "guard-installed-timing-observation.v1"
                    and observation.get("build") == name
                    and observation.get("source_sha") == BUILDS[name]["source_sha"]
                    and observation.get("runtime_sha256") == BUILDS[name]["runtime_sha256"]
                    and observation.get("runtimeAcceptance") is False
                    and isinstance(observation.get("slo"), dict)
                    and observation.get("failure_type") is None
                    and isinstance(observation.get("phases"), list)
                    and [item.get("phase") for item in observation["phases"]]
                    == [
                        "cold",
                        "warm",
                        "sizes",
                        "recovery",
                        "c16",
                        "rss_and_c64",
                    ]
                    and all(item.get("completed") is True for item in observation["phases"])
                )
                entry["report_valid"] = valid
                entry["gates_passed"] = valid and observation["slo"].get("passed") is True
            else:
                entry["report_valid"] = False
                entry["gates_passed"] = False
    finally:
        report["observations"] = entries
        report["all_observations_passed"] = len(entries) == len(SCHEDULE) and all(
            entry.get("installed") is True
            and entry.get("exit_code") == 0
            and entry.get("report_valid") is True
            and entry.get("gates_passed") is True
            for entry in entries
        )
        (output / "comparison.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0 if report["all_observations_passed"] is True else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker", choices=tuple(BUILDS))
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("this comparison requires the selected macOS platform")
    if args.worker:
        return run_worker(args.worker, args.output.resolve())
    if args.artifacts is None:
        parser.error("--artifacts is required")
    wheels = {}
    for name in BUILDS:
        matches = list((args.artifacts / name).rglob("*-macosx_13_0_x86_64.whl"))
        if len(matches) != 1:
            raise ValueError("installed_comparison_platform_wheel_ambiguous")
        wheels[name] = matches[0]
    return run_schedule(wheels, args.output.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
