#!/usr/bin/env python3
"""Qualify offline Python scanner workflows without exporting fixture inputs.

Run with a pinned --baseline-root and --source-root. Each arm uses a fresh
interpreter; full CLI, scanner CPU, import, serialization and Git I/O boundaries
are reported separately. An unimplemented native port is never reported as a
performance pass. See --cache-state for verified fixture-data eviction.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from .secret_scan_benchmark_cache import prepare_cache
    from .secret_scan_benchmark_fixtures import WORKLOADS, context_examples, create_fixture, provider_examples
else:
    from secret_scan_benchmark_cache import prepare_cache
    from secret_scan_benchmark_fixtures import WORKLOADS, context_examples, create_fixture, provider_examples


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, timeout=30)
    return result.stdout.decode().strip()


def _source_identity(root: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    files = sorted((root / "src/codex_plugin_scanner/guard/secrets").glob("*.py"))
    files.extend(sorted((root / "src/codex_plugin_scanner/checks").glob("security*.py")))
    files.append(root / "src/codex_plugin_scanner/path_support.py")
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return {"commit": _git(root, "rev-parse", "HEAD"), "scanner_source_sha256": digest.hexdigest()}


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


@contextmanager
def _measurement_block(path: Path | None) -> Iterator[None]:
    """Share a Linux/POSIX timing host without holding its lock for the matrix."""
    if path is None:
        yield
        return
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _qualify_detector() -> dict[str, object]:
    from codex_plugin_scanner.guard.secrets.secret_detection import SECRET_RULES, scan_secret_text

    expected_catalog = {example.label for example in provider_examples()}
    if {rule.rule_id for rule in SECRET_RULES} != expected_catalog:
        raise RuntimeError("provider qualification examples no longer cover the full catalog")
    outputs = []
    for example in (*provider_examples(), *context_examples()):
        result = scan_secret_text(example.text, path=example.path)
        if {finding.rule_id for finding in result.findings} != example.expected_rules:
            raise RuntimeError("independent detector expectation failed: " + example.label)
        for finding in result.findings:
            expected_hmac = hmac.new(
                b"qualification-a", (finding.rule_id + "\0" + finding.candidate).encode(), hashlib.sha256
            ).hexdigest()
            first = finding.to_public_dict(fingerprint_key=b"qualification-a")
            second = finding.to_public_dict(fingerprint_key=b"qualification-b")
            if first["fingerprint"] != expected_hmac or first["fingerprint"] == second["fingerprint"]:
                raise RuntimeError("caller-scoped finding HMAC changed")
            if finding.candidate in json.dumps(first):
                raise RuntimeError("public finding exposed candidate bytes")
        outputs.append(result.to_public_dict(fingerprint_key=b"qualification-a"))
    return {
        "provider_rules": len(expected_catalog),
        "context_examples": len(context_examples()),
        "public_hmac_sha256": _digest(outputs),
        "independent_expectations_passed": True,
    }


def _cpu_children() -> float | None:
    try:
        import resource
    except ImportError:
        return None
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def _worker(args: argparse.Namespace) -> dict[str, object]:
    sys.path.insert(0, str(args.source_root / "src"))
    import_start = time.perf_counter()
    from codex_plugin_scanner.checks import security
    from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository
    from codex_plugin_scanner.guard.secrets import secret_staged_scanner as staged

    import_wall = time.perf_counter() - import_start
    if args.workflow == "contracts":
        return _qualify_detector()
    subprocess_count = 0
    object_process_count = 0
    detector_calls = 0
    detector_cpu = 0.0
    object_io_wall = 0.0
    original_popen = subprocess.Popen

    def launch(command: list[str], *positional: object, **kwargs: object) -> subprocess.Popen[bytes]:
        nonlocal subprocess_count, object_process_count
        subprocess_count += 1
        object_process_count += int("cat-file" in command)
        return original_popen(command, *positional, **kwargs)

    def instrument_detector(function: object) -> object:
        def measure(*positional: object, **kwargs: object) -> object:
            nonlocal detector_calls, detector_cpu
            detector_calls += 1
            start = time.process_time()
            result = function(*positional, **kwargs)
            detector_cpu += time.process_time() - start
            return result

        return measure

    def instrument_io(function: object) -> object:
        def measure(*positional: object, **kwargs: object) -> object:
            nonlocal object_io_wall
            start = time.perf_counter()
            result = function(*positional, **kwargs)
            object_io_wall += time.perf_counter() - start
            return result

        return measure

    subprocess.Popen = launch
    repository.scan_secret_text = instrument_detector(repository.scan_secret_text)
    security._first_hardcoded_secret_line = instrument_detector(security._first_hardcoded_secret_line)
    try:
        from codex_plugin_scanner.guard.secrets.git_object_reader import _BatchProcess
    except ImportError:
        repository._git_blob = instrument_io(repository._git_blob)
        staged._git_staged_blob = instrument_io(staged._git_staged_blob)
    else:
        _BatchProcess.request = instrument_io(_BatchProcess.request)
    cpu_before = time.process_time()
    children_before = _cpu_children()
    start = time.perf_counter()
    if args.workflow == "plugin":
        results = security.run_security_checks(args.target)
        scan_wall = time.perf_counter() - start
        scan_cpu = time.process_time() - cpu_before
        serialization_start = time.perf_counter()
        public = [asdict(result) for result in results]
        counts = {"files_scanned": args.file_count, "bytes_scanned": args.input_bytes, "finding_count": 0}
    else:
        result = (
            staged.scan_staged_secrets(args.target, max_findings=10_000)
            if args.workflow == "staged"
            else repository.scan_repository_secrets(
                args.target, include_history=args.workflow == "history", max_findings=10_000
            )
        )
        scan_wall = time.perf_counter() - start
        scan_cpu = time.process_time() - cpu_before
        serialization_start = time.perf_counter()
        public = result.to_public_dict()
        if result.truncated or result.errors:
            raise RuntimeError("synthetic benchmark scan was incomplete")
        counts = {
            "files_scanned": result.files_scanned,
            "bytes_scanned": result.bytes_scanned,
            "finding_count": len(result.findings),
        }
    public_json = json.dumps(public, sort_keys=True)
    digest = hashlib.sha256(public_json.encode()).hexdigest()
    serialization_wall = time.perf_counter() - serialization_start
    if args.workflow != "plugin" and any(
        candidate in public_json for candidate in {f.candidate for f in result.findings}
    ):
        raise RuntimeError("public scanner output exposed candidate bytes")
    children_after = _cpu_children()
    git_cpu = None if children_before is None or children_after is None else children_after - children_before
    return {
        **counts,
        "scan_wall_ms": scan_wall * 1000,
        "python_cpu_ms": scan_cpu * 1000,
        "scanner_import_wall_ms": import_wall * 1000,
        "result_serialization_wall_ms": serialization_wall * 1000,
        "child_cpu_ms": None if git_cpu is None else git_cpu * 1000,
        "detector_cpu_ms": detector_cpu * 1000,
        "object_io_wall_ms": object_io_wall * 1000,
        "subprocess_count": subprocess_count,
        "object_process_count": object_process_count,
        "detector_calls": detector_calls,
        "result_sha256": digest,
        "finding_rules": dict(sorted(Counter(item["rule_id"] for item in public.get("findings", [])).items()))
        if isinstance(public, dict)
        else {},
    }


class CLIExecutionError(RuntimeError):
    """Keep bounded, non-sensitive evidence when a full command fails."""

    def __init__(self, message: str, evidence: dict[str, object]) -> None:
        super().__init__(message)
        self.evidence = evidence


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _command_diagnostics(stdout: bytes, stderr: bytes) -> dict[str, object]:
    combined = stdout + stderr
    categories = [
        category
        for marker, category in (
            (b"No such file or directory", "missing-path"),
            (b"No space left on device", "storage-full"),
            (b"Permission denied", "permission-denied"),
            (b"timed out", "timeout-text"),
        )
        if marker in combined
    ]
    return {
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "diagnostic_categories": categories,
        "diagnostic_scope": "fixed text markers only; no inferred root cause or raw command output",
    }


def _full_cli(
    source_root: Path,
    target: Path,
    workflow: str,
    *,
    extra_args: tuple[str, ...] = (),
    expected_exit: int = 0,
    default_bounds: bool = False,
    native_pilot_binary: Path | None = None,
) -> tuple[dict[str, object], dict[str, object] | None]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(source_root / "src")
    code = "import sys; sys.argv[0]='hol-guard'; from codex_plugin_scanner.cli import main; raise SystemExit(main())"
    if native_pilot_binary is not None:
        env["PYTHONPATH"] += os.pathsep + str(Path(__file__).resolve().parent)
        code = (
            "import sys; from pathlib import Path; sys.argv[0]='hol-guard'; "
            "from secret_scan_native_pilot import cli_main; "
            f"raise SystemExit(cli_main(Path({str(native_pilot_binary)!r})))"
        )
    command = [sys.executable, "-c", code, "secrets", "scan", str(target), "--json"]
    if not default_bounds:
        command.extend(("--max-findings", "10000"))
    if workflow in {"staged", "history"}:
        command.append("--" + workflow)
    command.extend(extra_args)
    cpu_before = _cpu_children()
    started_utc = _utc_now()
    start = time.perf_counter()
    try:
        process = subprocess.run(command, env=env, capture_output=True, timeout=120, check=False)
    except subprocess.TimeoutExpired as error:
        cpu_after = _cpu_children()
        raise CLIExecutionError(
            "CLI exceeded 120-second command deadline",
            {
                "command_started_utc": started_utc,
                "command_finished_utc": _utc_now(),
                "full_cli_wall_ms": (time.perf_counter() - start) * 1000,
                "full_cli_process_tree_cpu_ms": None
                if cpu_before is None or cpu_after is None
                else (cpu_after - cpu_before) * 1000,
                "expected_exit": expected_exit,
                "failure_category": "command-timeout",
                **_command_diagnostics(error.stdout or b"", error.stderr or b""),
            },
        ) from error
    elapsed = (time.perf_counter() - start) * 1000
    cpu_after = _cpu_children()
    sample = {
        "command_started_utc": started_utc,
        "command_finished_utc": _utc_now(),
        "full_cli_wall_ms": elapsed,
        "full_cli_process_tree_cpu_ms": None
        if cpu_before is None or cpu_after is None
        else (cpu_after - cpu_before) * 1000,
        "cli_exit": process.returncode,
    }
    if process.returncode != expected_exit:
        raise CLIExecutionError(
            f"CLI exit {process.returncode} differs from expected {expected_exit}",
            {
                **sample,
                "expected_exit": expected_exit,
                "failure_category": "unexpected-exit",
                **_command_diagnostics(process.stdout, process.stderr),
            },
        )
    public = json.loads(process.stdout) if process.stdout else None
    pilot_stats = {}
    if native_pilot_binary is not None:
        prefix = b"GUARD_REGEX_PILOT_STATS="
        stats = [line[len(prefix) :] for line in process.stderr.splitlines() if line.startswith(prefix)]
        if len(stats) != 1:
            raise RuntimeError("native pilot did not report its boundary use")
        pilot_stats = {"native_pilot_" + key: value for key, value in json.loads(stats[0]).items()}
    return {
        **sample,
        **pilot_stats,
        "cli_result_sha256": _digest(public),
    }, public


def _cli_contracts(
    source_root: Path, target: Path, workflow: str, *, has_findings: bool, native_pilot_binary: Path | None = None
) -> dict[str, object]:
    def cli(*args, **kwargs):
        return _full_cli(*args, **kwargs, native_pilot_binary=native_pilot_binary)

    checks = []
    samples = (
        ("complete", (), 0),
        ("fail-on-findings", ("--fail-on-findings",), 3 if has_findings else 0),
        ("file-limit", ("--max-files", "1", "--fail-on-findings"), 2),
        ("byte-limit", ("--max-total-bytes", "1", "--fail-on-findings"), 2),
    )
    for label, options, expected in samples:
        _, public = cli(source_root, target, workflow, extra_args=options, expected_exit=expected)
        if not isinstance(public, dict) or bool(public["truncated"]) != (expected == 2):
            raise RuntimeError("CLI coverage contract failed: " + label)
        if label == "complete" and bool(public["finding_count"]) != has_findings:
            raise RuntimeError("fixture did not exercise its declared findings class")
        checks.append({"case": label, "exit": expected, "result_sha256": _digest(public)})
    if has_findings:
        _, limited = cli(
            source_root, target, workflow, extra_args=("--max-findings", "1", "--fail-on-findings"), expected_exit=2
        )
        if not isinstance(limited, dict) or not limited["truncated"] or limited["finding_count"] != 1:
            raise RuntimeError("finding limit did not preserve partial-coverage behavior")
        checks.append({"case": "finding-limit", "exit": 2, "result_sha256": _digest(limited)})
    _, complete = cli(source_root, target, workflow)
    expected_default_exit = 2 if complete["finding_count"] >= 500 else 0
    _, defaults = cli(source_root, target, workflow, expected_exit=expected_default_exit, default_bounds=True)
    if not isinstance(defaults, dict) or bool(defaults["truncated"]) != (expected_default_exit == 2):
        raise RuntimeError("default finding bound changed")
    checks.append({"case": "default-bounds", "exit": expected_default_exit, "result_sha256": _digest(defaults)})
    _, public = cli(source_root, target / "absent", "working", expected_exit=2)
    if public is not None:
        raise RuntimeError("missing target unexpectedly produced a scan result")
    return {"checks": checks, "missing_target_exit": 2}


def _summary(group: list[dict[str, object]]) -> dict[str, object]:
    result = {}
    for key in group[0]:
        values = [sample[key] for sample in group]
        if all(isinstance(value, (int, float)) for value in values):
            ordered = sorted(values)
            result[key] = {
                "median": statistics.median(ordered),
                "p95": ordered[max(0, int(len(ordered) * 0.95 + 0.999999) - 1)],
                "min": ordered[0],
                "max": ordered[-1],
                "samples": len(ordered),
            }
    return result


def _write_report(
    args: argparse.Namespace,
    source_identities: dict[str, object],
    contracts: dict[str, object],
    cli_contracts: dict[str, object],
    rows: list[dict[str, object]],
    cache_states: list[str],
    *,
    complete: bool,
) -> None:
    report = {
        "schema": "guard-secret-algorithm-benchmark.v2",
        "run_complete": complete,
        "sources": source_identities,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "python": platform.python_version(),
            "git": _git(args.source_root, "--version"),
        },
        "method": {
            "repeats": args.repeats,
            "contracts_only": args.contracts_only,
            "measurement_lock_scope": "workload" if args.measurement_lock else "caller",
            "order": "alternating",
            "cache_states_requested": cache_states,
            "cache_scope": "fixture regular-file data only; interpreter/code/dentry/metadata caches uncontrolled",
            "cache_unavailable": "no samples or performance claim for a state whose preparation fails",
            "full_cli": "fresh interpreter running codex_plugin_scanner.cli.main",
            "qualification": "local synthetic algorithm diagnostic; no native implementation compared",
            "fixtures": "safe/finding-heavy source; 17 rules, context/entropy/HMAC; staged differs from worktree",
            "privacy": "aggregate counts, timing and result digests only",
            "percentile": "nearest rank; small sample p95 is diagnostic, not a release tail claim",
            "startup": "fresh-process envelope excludes scanner; includes imports/instrumentation/serialization",
            "native_boundary": "not measured; detector CPU bounds removable detector work only",
        },
        "detector_contracts": contracts,
        "cli_contracts": cli_contracts,
        "cases": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pending = args.output.with_suffix(args.output.suffix + ".partial")
    pending.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    pending.replace(args.output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--measurement-lock", type=Path, help="POSIX shared timing lock; released after each workload")
    parser.add_argument("--contracts-only", action="store_true", help="Run semantic/CLI gates without timed samples")
    parser.add_argument("--case", action="append", choices=[case.name for case in WORKLOADS])
    parser.add_argument(
        "--cache-state",
        action="append",
        choices=("uncontrolled", "prewarmed", "evicted"),
        help="Default: prewarmed and verified Linux file-data eviction; metadata/code caches remain uncontrolled",
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--target", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--workflow", help=argparse.SUPPRESS)
    parser.add_argument("--file-count", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--input-bytes", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(_worker(args), sort_keys=True))
        return 0
    if args.baseline_root is None or args.output is None or not 1 <= args.repeats <= 100:
        parser.error("provide --baseline-root and --output, with 1..100 repeats")
    roots = {"baseline_python": args.baseline_root.resolve(), "optimized_python": args.source_root.resolve()}
    source_identities = {name: _source_identity(root) for name, root in roots.items()}
    rows = []
    cases = [case for case in WORKLOADS if not args.case or case.name in args.case]
    cache_states = list(dict.fromkeys(args.cache_state or ("prewarmed", "evicted")))
    contracts = {}
    command_prefix = [sys.executable, str(Path(__file__).resolve()), "--worker"]
    with _measurement_block(args.measurement_lock):
        for name, root in roots.items():
            process = subprocess.run(
                [*command_prefix, "--source-root", str(root), "--workflow", "contracts"],
                capture_output=True,
                timeout=30,
                check=True,
            )
            contracts[name] = json.loads(process.stdout)
    if len({_digest(value) for value in contracts.values()}) != 1:
        raise RuntimeError("baseline and optimized detector/HMAC contracts differ")
    cli_contracts = {}
    with tempfile.TemporaryDirectory(prefix="guard-secret-benchmark-") as directory:
        for case in cases:
            with _measurement_block(args.measurement_lock):
                target = Path(directory) / case.name
                dimensions = create_fixture(target, case)
                contract_key = case.workflow + ("_findings" if case.content != "safe" else "_clean")
                contract_key += "_large" if case.files >= 500 or case.content in {"dense", "catalog"} else "_small"
                if case.workflow != "plugin" and contract_key not in cli_contracts:
                    checks = {
                        name: _cli_contracts(root, target, case.workflow, has_findings=case.content != "safe")
                        for name, root in roots.items()
                    }
                    if len({_digest(value) for value in checks.values()}) != 1:
                        raise RuntimeError("baseline and optimized CLI exit/completeness contracts differ")
                    cli_contracts[contract_key] = checks
                for cache_state in () if args.contracts_only else cache_states:
                    try:
                        preparation = prepare_cache(target, cache_state)
                    except (OSError, RuntimeError) as error:
                        rows.append(
                            {
                                "case": case.name,
                                "workflow": case.workflow,
                                "cache_state": cache_state,
                                "status": "cache-unavailable",
                                "reason": str(error),
                                "samples": {},
                            }
                        )
                        print(case.name + ": " + cache_state + " unavailable", flush=True)
                        continue
                    samples: dict[str, list[dict[str, object]]] = {name: [] for name in roots}
                    for repeat in range(args.repeats):
                        for name in list(roots) if repeat % 2 == 0 else list(reversed(roots)):
                            command = [
                                *command_prefix,
                                "--source-root",
                                str(roots[name]),
                                "--target",
                                str(target),
                                "--workflow",
                                case.workflow,
                                "--file-count",
                                str(case.files),
                                "--input-bytes",
                                str(dimensions["input_bytes"]),
                            ]
                            prepare_cache(target, cache_state)
                            worker_start = time.perf_counter()
                            worker = subprocess.run(command, capture_output=True, timeout=180, check=True)
                            worker_wall = (time.perf_counter() - worker_start) * 1000
                            sample = json.loads(worker.stdout)
                            sample["worker_process_wall_ms"] = worker_wall
                            sample["worker_startup_import_envelope_ms"] = worker_wall - sample["scan_wall_ms"]
                            if sample["files_scanned"] != dimensions["file_occurrences"]:
                                raise RuntimeError("scanner lost expected file occurrences")
                            if case.workflow != "plugin":
                                if sample["bytes_scanned"] != dimensions["file_occurrences"] * case.size:
                                    raise RuntimeError("scanner lost expected input-byte coverage")
                                expected_exit = 3 if case.content != "safe" else 0
                                prepare_cache(target, cache_state)
                                cli, _public = _full_cli(
                                    roots[name],
                                    target,
                                    case.workflow,
                                    extra_args=("--fail-on-findings",),
                                    expected_exit=expected_exit,
                                )
                                if cli.pop("cli_result_sha256") != sample["result_sha256"]:
                                    raise RuntimeError("full CLI output differs from instrumented scanner")
                                sample.update(cli)
                                sample["full_cli_bytes_per_second"] = sample["bytes_scanned"] / (
                                    cli["full_cli_wall_ms"] / 1000
                                )
                            samples[name].append(sample)
                    if len({sample["result_sha256"] for group in samples.values() for sample in group}) != 1:
                        raise RuntimeError("baseline and optimized Python produced different scan results")
                    rows.append(
                        {
                            "case": case.name,
                            "workflow": case.workflow,
                            "dimensions": dimensions,
                            "cache": preparation,
                            "status": "equivalent",
                            "samples": samples,
                            "statistics": {name: _summary(group) for name, group in samples.items()},
                        }
                    )
                    print(case.name + ": " + cache_state + " equivalent", flush=True)
                _write_report(args, source_identities, contracts, cli_contracts, rows, cache_states, complete=False)
    if source_identities != {name: _source_identity(root) for name, root in roots.items()}:
        raise RuntimeError("scanner sources changed during benchmark; rerun against frozen sources")
    _write_report(args, source_identities, contracts, cli_contracts, rows, cache_states, complete=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
