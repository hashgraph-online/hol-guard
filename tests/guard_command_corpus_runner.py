"""Bounded fresh-process runner for the deterministic command corpus."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from itertools import chain, islice
from pathlib import Path
from typing import TypedDict, cast

# Each shard has both a Python evaluator and a native subprocess. Keep the
# aggregate peak below the 512 MiB corpus budget, including coverage overhead.
EVALUATION_SHARD_COUNT = 3
MAX_CONCURRENT_WORKERS = EVALUATION_SHARD_COUNT
WORKER_TIMEOUT_SECONDS = 60
REPO_ROOT = Path(__file__).parents[1]
SYNTHETIC_CWD = REPO_ROOT / "workspace"
SYNTHETIC_HOME = REPO_ROOT / "home"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class WorkerReport(TypedDict):
    groups: dict[str, list[str]]
    native_contract_groups: dict[str, list[str]]
    native_error_groups: dict[str, list[str]]
    elapsed: float
    rss_mib: float


def peak_rss_mib(*, include_children: bool = False) -> float:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.PeakWorkingSetSize / (1024 * 1024)

    import resource

    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    child_rss_mib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / divisor if include_children else 0.0
    if sys.platform.startswith("linux"):
        try:
            return linux_peak_rss_mib_from_status(Path("/proc/self/status").read_text(encoding="utf-8")) + child_rss_mib
        except (OSError, ValueError):
            pass

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / divisor + child_rss_mib


def linux_peak_rss_mib_from_status(status: str) -> float:
    for line in status.splitlines():
        if not line.startswith("VmHWM:"):
            continue
        fields = line.split()
        if len(fields) == 3 and fields[0] == "VmHWM:" and fields[2] == "kB":
            return int(fields[1]) / 1024
        break
    raise ValueError("missing Linux VmHWM")


def _install_evaluator_packages() -> None:
    """Import Guard evaluator modules without unrelated scanner package exports."""

    package_root = REPO_ROOT / "src" / "codex_plugin_scanner"
    packages = (
        ("codex_plugin_scanner", package_root),
        ("codex_plugin_scanner.guard", package_root / "guard"),
        ("codex_plugin_scanner.guard.runtime", package_root / "guard" / "runtime"),
    )
    for name, path in packages:
        spec = importlib.util.spec_from_file_location(
            name, str(path / "__init__.py"), submodule_search_locations=[str(path)]
        )
        assert spec is not None
        sys.modules[name] = importlib.util.module_from_spec(spec)


def _worker_report(worker_index: int, worker_count: int) -> WorkerReport:
    _install_evaluator_packages()

    from codex_plugin_scanner.guard.action_lattice import guard_action_severity
    from tests.guard_command_corpus import iter_adversarial_corpus, iter_benign_corpus
    from tests.guard_command_corpus_native import (
        NATIVE_CORPUS_BATCH_SIZE,
        evaluate_native_corpus_batch,
        pin_neutral_attribution,
    )
    from tests.guard_command_corpus_native_contract import configure_native_contract_shard, validate_native_case
    from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle

    pin_neutral_attribution()
    configure_native_contract_shard(worker_index, worker_count)
    ranks = {
        action: guard_action_severity(action)
        for action in ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
    }
    ranks["monitor"] = ranks["warn"]
    groups: defaultdict[str, list[str]] = defaultdict(list)
    native_contract_groups: defaultdict[str, list[str]] = defaultdict(list)
    native_error_groups: defaultdict[str, list[str]] = defaultdict(list)
    streams = chain(
        zip(
            iter_benign_corpus(shard_index=worker_index, shard_count=worker_count),
            iter_benign_oracle(shard_index=worker_index, shard_count=worker_count),
            strict=True,
        ),
        zip(
            iter_adversarial_corpus(shard_index=worker_index, shard_count=worker_count),
            iter_adversarial_oracle(shard_index=worker_index, shard_count=worker_count),
            strict=True,
        ),
    )
    started = time.perf_counter()
    while batch := tuple(islice(streams, NATIVE_CORPUS_BATCH_SIZE)):
        evaluations = evaluate_native_corpus_batch(
            [case for case, _oracle in batch], cwd=SYNTHETIC_CWD, home_dir=SYNTHETIC_HOME
        )
        for (case, oracle), reviewed in zip(batch, evaluations, strict=True):
            native_contract_groups[validate_native_case(case, oracle, reviewed)].append(case.case_id)
            evidence = reviewed.payload.get("command_extensions")
            if isinstance(evidence, dict) and evidence.get("evaluation_error") is not None:
                native_error_groups[str(evidence["evaluation_error"])].append(case.case_id)
            observed = reviewed.evaluation.decision_plane.action
            if ranks[observed] == ranks[oracle.minimum_floor]:
                continue
            kind = "underclassified" if ranks[observed] < ranks[oracle.minimum_floor] else "overclassified"
            key = "|".join((oracle.owner, kind, oracle.minimum_floor, observed))
            groups[key].append(case.case_id)
        # Release native evidence before constructing the next batch. Keeping
        # the previous result alive doubles the live projection payloads.
        del evaluations
    return {
        "groups": dict(groups),
        "native_contract_groups": dict(native_contract_groups),
        "native_error_groups": dict(native_error_groups),
        "elapsed": time.perf_counter() - started,
        "rss_mib": peak_rss_mib(include_children=True),
    }


def _decode_worker(stdout: str) -> WorkerReport:
    value = cast(object, json.loads(stdout))
    if not isinstance(value, dict):
        raise ValueError("worker report must be an object")
    report = cast(dict[str, object], value)
    elapsed, rss_mib = report.get("elapsed"), report.get("rss_mib")
    if not isinstance(elapsed, int | float):
        raise ValueError("worker report shape is invalid")
    if not isinstance(rss_mib, int | float):
        raise ValueError("worker RSS must be numeric")
    return {
        "groups": _decode_groups(report.get("groups")),
        "native_contract_groups": _decode_groups(report.get("native_contract_groups")),
        "native_error_groups": _decode_groups(report.get("native_error_groups")),
        "elapsed": float(elapsed),
        "rss_mib": float(rss_mib),
    }


def _decode_groups(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise ValueError("worker groups must be an object")
    groups: dict[str, list[str]] = {}
    for key, ids_value in cast(dict[object, object], value).items():
        if not isinstance(key, str) or not isinstance(ids_value, list):
            raise ValueError("worker group shape is invalid")
        ids = cast(list[object], ids_value)
        if not all(isinstance(case_id, str) for case_id in ids):
            raise ValueError("worker case IDs must be strings")
        groups[key] = cast(list[str], ids)
    return groups


def _run_worker(worker_index: int) -> WorkerReport:
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker", str(worker_index)],
        check=True,
        capture_output=True,
        text=True,
        timeout=WORKER_TIMEOUT_SECONDS,
    )
    return _decode_worker(completed.stdout)


def _iter_reports() -> Iterator[WorkerReport]:
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_WORKERS) as executor:
        yield from executor.map(_run_worker, range(EVALUATION_SHARD_COUNT))


def _coordinator_report() -> dict[str, object]:
    from tests.guard_command_corpus_native_contract import expected_native_groups

    groups: defaultdict[str, list[str]] = defaultdict(list)
    native_contract_groups: defaultdict[str, list[str]] = defaultdict(list)
    native_error_groups: defaultdict[str, list[str]] = defaultdict(list)
    started = time.perf_counter()
    reports = tuple(_iter_reports())
    elapsed = time.perf_counter() - started
    for report in reports:
        for key, case_ids in report["groups"].items():
            groups[key].extend(case_ids)
        for key, case_ids in report["native_contract_groups"].items():
            native_contract_groups[key].extend(case_ids)
        for key, case_ids in report["native_error_groups"].items():
            native_error_groups[key].extend(case_ids)
    actual = {
        key: [len(ids), hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode()).hexdigest()]
        for key, ids in groups.items()
    }
    worker_rss = [report["rss_mib"] for report in reports]
    active_worker_rss = sum(sorted(worker_rss, reverse=True)[:MAX_CONCURRENT_WORKERS])
    observed_contract = {key: (len(ids), _framed_ids_sha256(ids)) for key, ids in native_contract_groups.items()}
    if observed_contract != expected_native_groups():
        raise ValueError("native corpus groups differ from the inherited native contract")
    below_original = sum(len(ids) for key, ids in groups.items() if "|underclassified|" in key)
    if below_original:
        raise ValueError("native corpus decisions fall below the original oracle")
    return {
        "actual": actual,
        "scope": "reviewed-native-engine-with-original-oracle-differences",
        "native_contract_equality": True,
        "native_contract_groups": observed_contract,
        "native_rejection_count": sum(len(ids) for ids in native_error_groups.values()),
        "native_rejection_groups": {
            key: [len(ids), _framed_ids_sha256(ids)] for key, ids in native_error_groups.items()
        },
        "original_oracle_below_count": below_original,
        "original_oracle_above_count": sum(len(ids) for key, ids in groups.items() if "|overclassified|" in key),
        "elapsed": elapsed,
        "rss_mib": peak_rss_mib() + active_worker_rss,
        "worker_elapsed": [report["elapsed"] for report in reports],
    }


def _framed_ids_sha256(values: list[str]) -> str:
    digest = hashlib.sha256()
    for value in sorted(values):
        encoded = value.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        print(json.dumps(_worker_report(int(sys.argv[2]), EVALUATION_SHARD_COUNT), sort_keys=True))
    elif len(sys.argv) == 1:
        print(json.dumps(_coordinator_report(), sort_keys=True))
    else:
        raise SystemExit("usage: guard_command_corpus_runner.py [--worker INDEX]")
