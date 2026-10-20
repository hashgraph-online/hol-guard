#!/usr/bin/env python3
"""Measure source-built native Bash admission with bounded synthetic graphs.

The timed route includes authenticated policy binding, native host observation,
resident IPC, filesystem capture and hashing, native policy evaluation, and the
local decision-store lookup. It does not execute the script or contact Cloud.
Only aggregate synthetic measurements and artifact provenance are emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _import_root in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_import_root) not in sys.path:
        sys.path.insert(0, str(_import_root))

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker  # noqa: E402
from codex_plugin_scanner.guard.hook_execution_environment import (  # noqa: E402
    HOOK_EXECUTION_ENVIRONMENT_KEY,
)
from codex_plugin_scanner.guard.native_bash_protocol import (  # noqa: E402
    observe_host,
    prepare,
    request_id,
    runtime_status,
)
from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope  # noqa: E402
from codex_plugin_scanner.guard.native_policy_snapshot import (  # noqa: E402
    provision_native_policy_verifier_key,
)
from codex_plugin_scanner.guard.native_resident_client import close_native_residents  # noqa: E402
from codex_plugin_scanner.guard.runtime.bound_bash_sink import _authorization  # noqa: E402
from codex_plugin_scanner.guard.store import GuardStore  # noqa: E402
from scripts.bench_guard_native_release_gate import _percentile  # noqa: E402
from scripts.installed_canary_proof import sha256_file as _sha256  # noqa: E402

_MAX_WARM_P95_MS = 20.0
_MAX_COLD_P95_MS = 100.0
_MAX_CODE_INPUTS = 64
_MAX_SOURCE_BYTES = 1_048_576


class _MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get_secret(self, key: str) -> str | None:
        return self.values.get(key)

    def set_secret(self, key: str, value: str) -> None:
        self.values[key] = value

    def delete_secret(self, key: str) -> None:
        self.values.pop(key, None)


@dataclass(frozen=True)
class _Case:
    name: str
    cwd: Path
    entry: Path
    mutable: Path
    code_inputs: int
    source_bytes: int


def _summary(values: list[float]) -> dict[str, float | int]:
    return {
        "count": len(values),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(_percentile(values, 0.95), 3),
        "p99_ms": round(_percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def _write_case(root: Path, name: str, *, source_count: int, source_bytes: int) -> _Case:
    cwd = root / name
    cwd.mkdir()
    entry = cwd / "entry.sh"
    source_names = [f"input-{index:02d}.sh" for index in range(source_count)]
    entry_text = (
        "#!/bin/bash\nset -euo pipefail\n# marker=00\n"
        + "".join(f"source './{source}'\n" for source in source_names)
        + "printf '%s\\n' \"${VALUE_00:-ok}\"\n"
    )
    if not source_names:
        padding = source_bytes - len(entry_text)
        if padding < 2:
            raise ValueError("source byte budget is too small for the requested graph")
        entry_text += "#" + ("x" * (padding - 2)) + "\n"
    entry.write_text(entry_text, encoding="utf-8")
    entry.chmod(0o700)
    remaining = source_bytes - entry.stat().st_size
    if remaining < source_count * 20:
        raise ValueError("source byte budget is too small for the requested graph")
    for index, source_name in enumerate(source_names):
        files_left = source_count - index
        target_size = remaining // files_left
        prefix = f"VALUE_{index:02d}='{index:02d}'\n# marker=00\n#"
        body = prefix + ("x" * (target_size - len(prefix) - 1)) + "\n"
        target = cwd / source_name
        target.write_text(body, encoding="utf-8")
        remaining -= target.stat().st_size
    actual_bytes = entry.stat().st_size + sum((cwd / source).stat().st_size for source in source_names)
    if actual_bytes != source_bytes:
        raise RuntimeError(f"synthetic graph size mismatch: expected={source_bytes} actual={actual_bytes}")
    mutable = cwd / source_names[0] if source_names else entry
    return _Case(
        name=name,
        cwd=cwd,
        entry=entry,
        mutable=mutable,
        code_inputs=source_count + 2,
        source_bytes=actual_bytes,
    )


def _payload(case: _Case) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": f"/bin/bash '{case.entry}' benchmark"},
        "cwd": str(case.cwd),
    }


def _sample(
    case: _Case,
    *,
    store: GuardStore,
    workspace: Path,
) -> tuple[dict[str, float], str]:
    payload = _payload(case)
    command = payload["tool_input"]["command"]
    assert isinstance(command, str)
    stages: dict[str, float] = {}
    total_at = time.perf_counter()
    at = time.perf_counter()
    worker = HookWorker(
        store=store,
        workspace=workspace,
        home_dir=Path(os.environ["HOME"]),
        wait_for_native_policy=False,
        publish_native_policy=False,
        start_native_policy=False,
    )
    try:
        snapshot = worker.prepare_workspace_policy(workspace, deadline=time.monotonic() + 5)
        stages["policy_binding"] = (time.perf_counter() - at) * 1_000
        if snapshot is None:
            raise RuntimeError("resident-acknowledged policy binding unavailable")
        at = time.perf_counter()
        capture = observe_host(
            {
                "harness": "omp",
                "command": command,
                "cwd": str(case.cwd),
                "workspace": str(workspace),
                "home_dir": "",
                "guard_home": str(store.guard_home),
                "environment": {},
                "file_creation_mask": None,
                "execution_environment": {
                    "path": "",
                    "environment_names": [],
                    "environment_digest": "",
                    "home": None,
                    "git_pager_disabled": False,
                    "pager_disabled": False,
                    "xdg_config_home": None,
                    "git_config_no_system": False,
                },
                "budget_ms": 5_000,
            },
            cwd=case.cwd,
        )
        stages["host_observation"] = (time.perf_counter() - at) * 1_000
        encoded = _encode_hook_envelope(
            payload={**payload, HOOK_EXECUTION_ENVIRONMENT_KEY: capture["execution_environment"]},
            harness="omp",
            event="PreToolUse",
            guard_home=store.guard_home,
            home_dir=Path(str(capture["home_dir"])),
            cwd=case.cwd,
            source_ref_external_allowed=False,
            deadline_budget_ms=5_000,
            snapshot=snapshot,
            execution_context_supported=True,
            request_id=request_id(),
        )
        if encoded is None:
            raise RuntimeError("native hook envelope unavailable")
        at = time.perf_counter()
        prepared = prepare(
            {
                "schema": "guard-native-bash-prepare-request.v1",
                "request_id": request_id(),
                "capture": capture,
                "envelope": json.loads(encoded),
                "budget_ms": 5_000,
            },
            guard_home=store.guard_home,
        )
        stages["native_prepare"] = (time.perf_counter() - at) * 1_000
        at = time.perf_counter()
        authorization = _authorization(store, prepared, harness="omp", workspace=workspace)
        stages["decision_store"] = (time.perf_counter() - at) * 1_000
        if authorization.get("kind") != "current_policy":
            raise RuntimeError("isolated benchmark unexpectedly found a saved decision")
        artifact_hash = prepared.get("artifact_hash")
        if not isinstance(artifact_hash, str):
            raise RuntimeError("native Bash preparation returned no artifact identity")
    finally:
        worker.close()
    stages["total"] = (time.perf_counter() - total_at) * 1_000
    return stages, artifact_hash


def _run_case(
    case: _Case,
    *,
    store: GuardStore,
    workspace: Path,
    warm_samples: int,
    cold_samples: int,
) -> dict[str, object]:
    baseline_stat = case.mutable.stat()
    _, baseline_hash = _sample(case, store=store, workspace=workspace)
    warm: dict[str, list[float]] = {}
    warm_hashes: set[str] = set()
    for _ in range(warm_samples):
        stages, artifact_hash = _sample(case, store=store, workspace=workspace)
        warm_hashes.add(artifact_hash)
        for name, elapsed in stages.items():
            warm.setdefault(name, []).append(elapsed)
    cold: dict[str, list[float]] = {}
    cold_hashes: set[str] = set()
    original = case.mutable.read_text(encoding="utf-8")
    marker_start = original.index("marker=") + len("marker=")
    marker_end = marker_start + 2
    for index in range(cold_samples):
        marker = f"{(index + 1) % 100:02d}"
        changed = original[:marker_start] + marker + original[marker_end:]
        case.mutable.write_text(changed, encoding="utf-8")
        os.utime(case.mutable, ns=(baseline_stat.st_atime_ns, baseline_stat.st_mtime_ns))
        current = case.mutable.stat()
        if current.st_size != baseline_stat.st_size or current.st_mtime_ns != baseline_stat.st_mtime_ns:
            raise RuntimeError("same-size/same-mtime negative control was not preserved")
        stages, artifact_hash = _sample(case, store=store, workspace=workspace)
        if artifact_hash == baseline_hash:
            raise RuntimeError("same-size/same-mtime content mutation reused the prior artifact identity")
        cold_hashes.add(artifact_hash)
        for stage, elapsed in stages.items():
            cold.setdefault(stage, []).append(elapsed)
    return {
        "graph": {
            "code_config_inputs": case.code_inputs,
            "source_bytes": case.source_bytes,
        },
        "warm": {name: _summary(values) for name, values in warm.items()},
        "cold_content_miss": {name: _summary(values) for name, values in cold.items()},
        "controls": {
            "unchanged_identity_stable": warm_hashes == {baseline_hash},
            "same_size_same_mtime_mutations_detected": len(cold_hashes) == cold_samples,
            "cold_unique_artifact_identities": len(cold_hashes),
        },
        "gates": {
            "warm_p95_at_most_20_ms": _summary(warm["total"])["p95_ms"] <= _MAX_WARM_P95_MS,
            "cold_p95_at_most_100_ms": _summary(cold["total"])["p95_ms"] <= _MAX_COLD_P95_MS,
        },
    }


def _command_output(argv: list[str]) -> str | None:
    try:
        result = subprocess.run(
            argv,
            cwd=_REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value or None


def _write_report(report: dict[str, object], destination: Path | None, output: TextIO) -> None:
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if destination is not None:
        destination.write_text(encoded, encoding="utf-8")
    output.write(encoded)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--warm-samples", type=int, default=60)
    parser.add_argument("--cold-samples", type=int, default=20)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    runtime = args.runtime.expanduser().resolve(strict=True)
    if args.warm_samples < 20 or args.cold_samples < 20:
        parser.error("warm and cold samples must both be at least 20")
    os.environ["HOL_GUARD_NATIVE"] = "force"
    os.environ["HOL_GUARD_NATIVE_BINARY"] = str(runtime)
    os.environ.setdefault("HOL_GUARD_TEST_MODE", "1")
    os.environ.setdefault("HOL_GUARD_RESIDENT_TEST_SEAMS", "1")
    status = runtime_status()
    if status.identity is None or status.identity.path.resolve() != runtime:
        raise RuntimeError("selected native runtime identity did not match --runtime")
    with tempfile.TemporaryDirectory(prefix="guard-bash-admission-") as raw_root:
        root = Path(raw_root).resolve()
        workspace, home, guard_home = root / "project", root / "home", root / "guard"
        workspace.mkdir()
        home.mkdir()
        os.environ["HOME"] = str(home)
        os.environ["PATH"] = "/usr/bin:/bin"
        small = _write_case(workspace, "small", source_count=0, source_bytes=256)
        maximum = _write_case(
            workspace,
            "maximum",
            source_count=_MAX_CODE_INPUTS - 2,
            source_bytes=1_000_000,
        )
        store = GuardStore(guard_home, prime_policy_integrity=False)
        store._policy_integrity_secret_store = _MemorySecrets()
        integrity_key, _ = store._policy_integrity_secret_material(create=True)
        if integrity_key is None:
            raise RuntimeError("isolated policy integrity key unavailable")
        (guard_home / "native-runtime").mkdir(mode=0o700, parents=True, exist_ok=True)
        provision_native_policy_verifier_key(guard_home, integrity_key)
        publisher = HookWorker(
            store=store,
            workspace=workspace,
            home_dir=home,
            wait_for_native_policy=False,
        )
        try:
            if publisher.prepare_workspace_policy(workspace, deadline=time.monotonic() + 25) is None:
                raise RuntimeError(
                    f"native policy publisher was not ready: {publisher.policy_snapshot_publisher.last_error}"
                )
        finally:
            publisher.close()
        try:
            cases = {
                small.name: _run_case(
                    small,
                    store=store,
                    workspace=workspace,
                    warm_samples=args.warm_samples,
                    cold_samples=args.cold_samples,
                ),
                maximum.name: _run_case(
                    maximum,
                    store=store,
                    workspace=workspace,
                    warm_samples=args.warm_samples,
                    cold_samples=args.cold_samples,
                ),
            }
        finally:
            close_native_residents(guard_home=guard_home)
    report: dict[str, object] = {
        "schema": "guard-native-bash-admission-benchmark.v1",
        "scope": "source-built local admission; no script execution or Cloud request",
        "measurement": {
            "included": [
                "resident-acknowledged policy file verification",
                "native host observation",
                "resident IPC",
                "filesystem capture and hashing",
                "native policy evaluation",
                "local decision-store lookup",
            ],
            "analysis_cache": (
                "bounded process-local graph cache for builtins and local sources only; "
                "hits reread and hash all code, recheck source lookup order, reacquire "
                "interpreter/output handles, and re-evaluate current policy and saved decisions"
            ),
        },
        "source": {
            "git_sha": _command_output(["git", "rev-parse", "HEAD"]),
            "runtime_build_sha": status.capabilities.build_sha if status.capabilities is not None else None,
            "runtime_sha256": _sha256(runtime),
            "runtime_bytes": runtime.stat().st_size,
        },
        "hardware": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or None,
            "logical_cpus": os.cpu_count(),
            "cpu_brand": _command_output(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"]),
            "hardware_model": _command_output(["/usr/sbin/sysctl", "-n", "hw.model"]),
            "memory_bytes": _command_output(["/usr/sbin/sysctl", "-n", "hw.memsize"]),
        },
        "targets_ms": {
            "warm_p95": _MAX_WARM_P95_MS,
            "cold_content_miss_p95": _MAX_COLD_P95_MS,
        },
        "cases": cases,
        "passed": all(all(case["gates"].values()) for case in cases.values()),
    }
    _write_report(report, args.output, sys.stdout)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
