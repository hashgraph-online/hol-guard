#!/usr/bin/env python3
"""Measure installed native runtime admission, never a binary-env override.

This is a component benchmark. A capability-cache-warm status lookup is not an
evaluated hook, and its timing excludes interpreter/import startup. A retained
client, when requested, is an actual installed Rust stdin/stdout process; no
hook frame, resident socket connection, or fabricated decision is submitted.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.metadata
import json
import os
import platform
import statistics
import tempfile
import threading
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--live-client", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.samples <= 10000 or not 1 <= args.runs <= 20:
        parser.error("samples must be 1..10000 and runs 1..20")
    for key in ("HOL_GUARD_NATIVE_BINARY", "HOL_GUARD_NATIVE", "HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE"):
        if key in os.environ:
            raise RuntimeError(f"Remove {key}; this benchmark uses the installed production admission path")

    from codex_plugin_scanner.guard import native_runtime as runtime

    distribution = importlib.metadata.distribution("hol-guard")
    installed_root = Path(distribution.locate_file("codex_plugin_scanner")).resolve()
    module_path = Path(runtime.__file__).resolve()
    if not module_path.is_relative_to(installed_root) or "site-packages" not in str(installed_root):
        raise RuntimeError("The selected interpreter did not import the installed wheel")
    initial = runtime.native_runtime_status()
    if not initial.available or not initial.compatible or initial.identity is None or initial.capabilities is None:
        raise RuntimeError(f"Installed native admission failed: {initial.reason}")
    executable = initial.identity.path
    manifest = json.loads(executable.with_name("runtime-manifest.json").read_text())
    actual_binary_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    if actual_binary_digest != manifest["runtime_sha256"]:
        raise RuntimeError("Runtime bytes differ from the installed manifest")

    original_sha256 = runtime.hashlib.sha256
    original_validate = runtime._validate_binary
    original_package_version = runtime._python_package_version
    original_open = Path.open
    active = threading.local()
    counts = {"validation_calls": 0, "hashed_bytes": 0, "manifest_opens": 0, "package_version_lookups": 0}

    class HashCounter:
        def __init__(self, *factory_args, **factory_kwargs):
            self._digest = original_sha256(*factory_args, **factory_kwargs)

        def update(self, data):
            if getattr(active, "validation", False):
                counts["hashed_bytes"] += len(data)
            return self._digest.update(data)

        def __getattr__(self, name):
            return getattr(self._digest, name)

    def validate(path, *validator_args, **validator_kwargs):
        counts["validation_calls"] += 1
        previous = getattr(active, "validation", False)
        active.validation = True
        try:
            return original_validate(path, *validator_args, **validator_kwargs)
        finally:
            active.validation = previous

    def package_version():
        counts["package_version_lookups"] += 1
        return original_package_version()

    def opened(path, *open_args, **open_kwargs):
        if path == executable.with_name("runtime-manifest.json"):
            counts["manifest_opens"] += 1
        return original_open(path, *open_args, **open_kwargs)

    runtime.hashlib.sha256 = HashCounter
    runtime._validate_binary = validate
    runtime._python_package_version = package_version
    Path.open = opened
    phases = []
    client = None

    def measure(label, samples, run):
        before = dict(counts)
        cache_before = runtime._capabilities_for_identity.cache_info()
        wall, cpu = [], []
        for _ in range(samples):
            cpu_start = time.process_time_ns()
            wall_start = time.perf_counter_ns()
            status = runtime.native_runtime_status()
            wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)
            cpu.append((time.process_time_ns() - cpu_start) / 1_000_000)
            if not status.compatible or status.identity is None or status.identity.sha256 != actual_binary_digest:
                raise RuntimeError("Runtime identity changed during measurement")
        cache_after = runtime._capabilities_for_identity.cache_info()
        observation = {
            "phase": label,
            "run": run,
            "samples": samples,
            "wall_ms": wall,
            "cpu_ms": cpu,
            "wall_median_ms": statistics.median(wall),
            "cpu_median_ms": statistics.median(cpu),
            "counts": {key: counts[key] - before[key] for key in counts},
            "capability_cache_hits": cache_after.hits - cache_before.hits,
            "capability_cache_misses": cache_after.misses - cache_before.misses,
        }
        phases.append(observation)
        print(
            json.dumps({key: observation[key] for key in ("phase", "run", "samples", "cpu_median_ms", "counts")}),
            flush=True,
        )

    try:
        with tempfile.TemporaryDirectory(prefix="guard-identity-component-") as temporary:
            if args.live_client:
                from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient

                state_dir = Path(temporary) / "native-runtime"
                client = _PersistentNativeClient(
                    executable=executable,
                    state_dir=state_dir,
                    environment=runtime._isolated_environment(),
                )
                if not client._start():
                    raise RuntimeError("Installed persistent client could not start")
            for run in range(args.runs):
                if client is None:
                    runtime._capabilities_for_identity.cache_clear()
                    measure("capability_cache_cold_status", 1, run)
                measure(
                    "retained_client_status" if client is not None else "capability_cache_warm_status",
                    args.samples,
                    run,
                )
    finally:
        if client is not None:
            client.close()
        runtime.hashlib.sha256 = original_sha256
        runtime._validate_binary = original_validate
        runtime._python_package_version = original_package_version
        Path.open = original_open

    report = {
        "schema": "guard-runtime-identity-component-v1",
        "boundary": "installed native_runtime_status only; interpreter/import startup excluded",
        "installed_wheel": True,
        "environment_overrides": False,
        "live_client": args.live_client,
        "native_identity": dataclasses.asdict(initial.identity) | {"path": "installed wheel/_native/hol-guard-runtime"},
        "native_capabilities": dataclasses.asdict(initial.capabilities),
        "manifest": manifest,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "phases": phases,
        "limitations": [
            "Component measurement, not a successful managed resident hook or end-to-end launcher result",
            "CPU covers the Python process; capability subprocess CPU is not included",
            "Hash counting wraps real SHA256 updates and adds a small instrumentation cost",
            "A capability cache hit does not imply a full-byte digest was reused",
            "Shared-host load and installed platform qualification remain separate",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, default=str) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
