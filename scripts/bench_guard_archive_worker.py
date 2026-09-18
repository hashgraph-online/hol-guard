#!/usr/bin/env python3
"""Qualify the real isolated archive worker on deterministic synthetic archives.

Example: python scripts/bench_guard_archive_worker.py --samples 30 --profile-samples 10 --output archive.json

Fresh children, warm filesystem cache; no extraction, content execution, or
network access. Timed samples use inspect_archive_offline unchanged. Separate
instrumented children attribute imports, immutable digest reads, expansion
preflight, member decoding and manifest policy. Output contains no archive
contents or local paths. A retained Python decision is not native parity proof.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArchiveCase:
    name: str
    path: Path
    digest: str
    status: str = "clean"
    code: str = "external_archive_inspection_clean"
    limits: dict[str, int | float] = field(default_factory=dict)


def archive_blob(root: Path, name: str, entries: list[tuple[str, bytes]], *, compressed: bool = True) -> Path:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for member_name, contents in entries:
            member = tarfile.TarInfo(member_name)
            member.size = len(contents)
            archive.addfile(member, io.BytesIO(contents))
    payload = gzip.compress(buffer.getvalue(), mtime=0) if compressed else buffer.getvalue()
    path = root / (name + (".tgz" if compressed else ".tar"))
    path.write_bytes(payload)
    path.chmod(0o400)
    return path


def build_cases(root: Path) -> list[ArchiveCase]:
    random_bytes = random.Random(70)
    manifest = ("package/package.json", b'{"name":"archive-qualification","version":"1.0.0"}')
    cases = []

    def add(name: str, entries: list[tuple[str, bytes]], **kwargs: Any) -> None:
        compressed = kwargs.pop("compressed", True)
        path = archive_blob(root, name, entries, compressed=compressed)
        cases.append(ArchiveCase(name, path, hashlib.sha256(path.read_bytes()).hexdigest(), **kwargs))

    add("one_manifest", [manifest])
    add("hundred_members", [(f"package/file-{index}", random_bytes.randbytes(128)) for index in range(99)] + [manifest])
    add(
        "five_hundred_members",
        [(f"package/file-{index}", random_bytes.randbytes(128)) for index in range(499)] + [manifest],
    )
    add("one_mib_gzip", [("package/data.bin", random_bytes.randbytes(1024 * 1024)), manifest])
    add("five_mib_gzip", [("package/data.bin", random_bytes.randbytes(5 * 1024 * 1024)), manifest])
    add("five_mib_tar", [("package/data.bin", random_bytes.randbytes(5 * 1024 * 1024)), manifest], compressed=False)
    hostile = {"status": "blocked"}
    add("parent_path", [("../outside", b"never extracted")], code="tarball_zip_slip", **hostile)
    add(
        "install_script",
        [("package/package.json", b'{"scripts":{"postinstall":"exit 91"}}')],
        code="tarball_install_script",
        **hostile,
    )
    add(
        "invalid_manifest_utf8",
        [("package/package.json", b"\xff")],
        code="external_archive_manifest_invalid",
        **hostile,
    )
    add(
        "over_file_count",
        [(f"package/file-{index}", random_bytes.randbytes(128)) for index in range(501)],
        code="tarball_file_count_limit",
        **hostile,
    )
    add("path_depth", [("/".join(["x"] * 65), b"value")], code="external_archive_path_depth_limit", **hostile)
    add(
        "member_size",
        [("package/big", random_bytes.randbytes(4096))],
        limits={"max_member_bytes": 2048},
        code="external_archive_member_size_limit",
        **hostile,
    )
    add(
        "expanded_stream",
        [("package/data", random_bytes.randbytes(1024))],
        limits={"max_expanded_bytes": 2048},
        code="external_archive_expanded_size_limit",
        **hostile,
    )
    add(
        "compression_ratio",
        [("package/repeated", b"A" * (1024 * 1024))],
        code="external_archive_decompression_ratio_limit",
        **hostile,
    )
    add(
        "nested_archives",
        [(f"package/inner-{index}.tgz", random_bytes.randbytes(256)) for index in range(9)],
        code="external_archive_nesting_limit",
        **hostile,
    )
    add(
        "worker_deadline",
        [manifest],
        limits={"timeout_seconds": 1e-9},
        status="incomplete",
        code="external_archive_inspection_timeout",
    )
    malformed = root / "truncated-gzip.tgz"
    malformed.write_bytes(cases[0].path.read_bytes()[:-8])
    malformed.chmod(0o400)
    cases.append(
        ArchiveCase(
            "truncated_gzip",
            malformed,
            hashlib.sha256(malformed.read_bytes()).hexdigest(),
            "incomplete",
            "external_archive_inspection_incomplete",
        )
    )
    return cases


def _assert_result(case: ArchiveCase, result: Any) -> None:
    if (result.status, result.code) != (case.status, case.code):
        raise RuntimeError(f"{case.name}: unexpected result {result.status}/{result.code}")
    if result.status == "clean" and result.sha256 != case.digest:
        raise RuntimeError(f"{case.name}: clean result did not verify fixture digest")


def _cpu_tree() -> float:
    import resource

    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time() + child.ru_utime + child.ru_stime


def _measure(inspector: Any, case: ArchiveCase) -> dict[str, Any]:
    cpu = _cpu_tree()
    started = time.perf_counter()
    result = inspector.inspect_archive_offline(case.path, expected_sha256=case.digest, **case.limits)
    wall_ms = (time.perf_counter() - started) * 1000
    cpu_ms = (_cpu_tree() - cpu) * 1000
    expected = (result.status, result.code) == (case.status, case.code)
    expected = expected and (result.status != "clean" or result.sha256 == case.digest)
    return {
        "wall_ms": wall_ms,
        "process_tree_cpu_ms": cpu_ms,
        "status": result.status,
        "code": result.code,
        "expected_result_verified": expected,
    }


def _profile(inspector: Any, case: ArchiveCase) -> dict[str, Any]:
    contract = sys.modules["codex_plugin_scanner.guard.runtime.offline_archive_contract"]
    parameters = (
        ("timeout_seconds", "_DEFAULT_TIMEOUT_SECONDS"),
        ("max_archive_bytes", "_DEFAULT_MAX_ARCHIVE_BYTES"),
        ("max_files", "_DEFAULT_MAX_FILES"),
        ("max_expanded_bytes", "_DEFAULT_MAX_EXPANDED_BYTES"),
        ("max_member_bytes", "_DEFAULT_MAX_MEMBER_BYTES"),
        ("max_package_json_bytes", "_DEFAULT_MAX_PACKAGE_JSON_BYTES"),
        ("max_memory_bytes", "_DEFAULT_MAX_MEMORY_BYTES"),
        ("max_decompression_ratio", "_DEFAULT_MAX_DECOMPRESSION_RATIO"),
        ("max_nested_archives", "_DEFAULT_MAX_NESTED_ARCHIVES"),
        ("max_path_depth", "_DEFAULT_MAX_PATH_DEPTH"),
    )
    arguments = ["--child-inspect", str(case.path), case.digest]
    arguments += [str(case.limits.get(name, getattr(contract, constant))) for name, constant in parameters]
    command = inspector._isolated_child_command(arguments)
    trailer = "raise SystemExit(m._child_main(sys.argv[1:]))"
    if command[5].count(trailer) != 1:
        raise RuntimeError("archive child bootstrap changed; inspect diagnostic injection before profiling")
    helper = Path(__file__).with_name("archive_worker_profile.py").read_text(encoding="utf-8")
    command[5] = "import time;_archive_child_started=time.perf_counter();" + command[5].replace(
        trailer,
        f"_archive_child_imported=time.perf_counter();n={{}};exec({helper!r},n);"
        "raise SystemExit(n['run_profile'](m,sys.argv[1:],_archive_child_started,_archive_child_imported))",
    )
    sandboxed = inspector._platform_sandbox_command(command)
    if sandboxed is None:
        raise RuntimeError("archive platform sandbox unavailable")
    started = time.perf_counter()
    process = subprocess.run(
        sandboxed,
        cwd=case.path.parent,
        env=inspector._child_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=float(case.limits.get("timeout_seconds", 2.0)) + 0.5,
    )
    wall_ms = (time.perf_counter() - started) * 1000
    if process.returncode != 0 or len(process.stdout) > contract._CHILD_RESULT_MAX_BYTES:
        raise RuntimeError(f"{case.name}: instrumented child failed")
    result = inspector.ArchiveInspectionResult(**json.loads(process.stdout))
    _assert_result(case, result)
    sample = json.loads(process.stderr)
    phases = sample["phases"]
    inspect_ms = phases["inspection_total"]["wall_ms"]
    attributed = sum(
        phases.get(name, {}).get("wall_ms", 0)
        for name in ("digest_reads", "expanded_stream_preflight", "tar_member_decode", "manifest_policy")
    )
    sample.update(
        {
            "wall_ms": wall_ms,
            "startup_exit_and_parent_ms": wall_ms - inspect_ms,
            "inspection_remainder_ms": inspect_ms - attributed,
            "child_exit_code": process.returncode,
        }
    )
    return sample


def _summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "median": statistics.median(ordered),
        "p95": ordered[math.ceil(len(ordered) * 0.95) - 1],
        "max": ordered[-1],
    }


def _source_identity(root: Path) -> dict[str, str]:
    paths = sorted((root / "src/codex_plugin_scanner/guard/runtime").glob("offline_archive_*.py"))
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()
    harness_digest = hashlib.sha256()
    for path in [Path(__file__).resolve(), Path(__file__).with_name("archive_worker_profile.py").resolve()]:
        harness_digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return {
        "commit": commit,
        "archive_source_sha256": digest.hexdigest(),
        "qualification_harness_sha256": harness_digest.hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--profile-samples", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1 or args.profile_samples < 1:
        parser.error("sample counts must be positive")
    if os.name != "posix":
        parser.error("qualification requires the POSIX resource sandbox")
    root = args.source_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from codex_plugin_scanner.guard.runtime import offline_archive_inspection as inspector

    report: dict[str, Any] = {
        "schema": "hol-guard.archive-worker-qualification.v1",
        "source": _source_identity(root),
        "environment": {
            "python": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
        },
        "measurement": {
            "boundary": "unchanged inspect_archive_offline parent through fresh isolated child result",
            "cache": "warm filesystem; interpreter restarts each sample",
            "concurrency": 1,
            "samples_per_case": args.samples,
            "profiles_per_clean_case": args.profile_samples,
            "quantile": "nearest-rank p95",
            "contents": "deterministic synthetic tar/gzip only",
            "phase_profile_is_instrumented": True,
            "native_worker_qualified": False,
        },
        "cases": [],
        "complete": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def checkpoint() -> None:
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="guard-archive-qualification-") as temporary:
        cases = build_cases(Path(temporary))
        # Warmup results remain visible, but are excluded from timing aggregates.
        report["warmups"] = {case.name: _measure(inspector, case) for case in cases}
        samples: dict[str, list[dict[str, Any]]] = {case.name: [] for case in cases}
        rows = {}
        for case in cases:
            row = {
                "case": case.name,
                "archive_bytes": case.path.stat().st_size,
                "archive_sha256": case.digest,
                "limits_overridden": case.limits,
                "expected": {"status": case.status, "code": case.code},
                "samples": samples[case.name],
                "diagnostic_profiles": [],
                "diagnostic_failures": [],
            }
            rows[case.name] = row
            report["cases"].append(row)
        for iteration in range(args.samples):
            # Deterministically rotate case order to avoid a size/position trend.
            order = cases[iteration % len(cases) :] + cases[: iteration % len(cases)]
            for case in order:
                samples[case.name].append(_measure(inspector, case))
            for row in report["cases"]:
                row["wall_ms"] = _summary([sample["wall_ms"] for sample in row["samples"]])
                row["process_tree_cpu_ms"] = _summary([sample["process_tree_cpu_ms"] for sample in row["samples"]])
            report["completed_iterations"] = iteration + 1
            checkpoint()  # Preserve baseline evidence even if a later diagnostic child fails.
            if (iteration + 1) % 5 == 0:
                print(json.dumps({"completed_iterations": iteration + 1}), flush=True)
        for case in cases:
            if case.status != "clean":
                continue
            for attempt in range(args.profile_samples):
                try:
                    rows[case.name]["diagnostic_profiles"].append(_profile(inspector, case))
                except (subprocess.TimeoutExpired, RuntimeError, ValueError, OSError) as error:
                    # Diagnostics keep the production limits; a timeout never
                    # becomes a missing sample or an apparent speed improvement.
                    rows[case.name]["diagnostic_failures"].append(
                        {"attempt": attempt + 1, "error": type(error).__name__}
                    )
                checkpoint()
    verified = all(sample["expected_result_verified"] for row in report["cases"] for sample in row["samples"])
    verified = verified and all(sample["expected_result_verified"] for sample in report["warmups"].values())
    failures = sum(len(row["diagnostic_failures"]) for row in report["cases"])
    report.update({"complete": True, "expected_results_verified": verified, "diagnostic_failures": failures})
    checkpoint()
    print(
        json.dumps(
            {
                "cases": len(report["cases"]),
                "samples": args.samples,
                "expected_results_verified": verified,
                "diagnostic_failures": failures,
                "native_worker_qualified": False,
            }
        )
    )
    return 0 if verified and not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
