"""Bounded fresh-process runner for the deterministic command corpus."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import types
from collections import defaultdict
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from itertools import chain
from pathlib import Path
from typing import TypedDict, cast

EVALUATION_SHARD_COUNT = 4
MAX_CONCURRENT_WORKERS = 1
WORKER_TIMEOUT_SECONDS = 15
REPO_ROOT = Path(__file__).parents[1]
SYNTHETIC_CWD = REPO_ROOT / "workspace"
SYNTHETIC_HOME = REPO_ROOT / "home"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class WorkerReport(TypedDict):
    groups: dict[str, list[str]]
    elapsed: float
    rss_mib: float


def peak_rss_mib() -> float:
    if sys.platform == "win32":
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-Process -Id {os.getpid()}).PeakWorkingSet64",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return int(completed.stdout.strip()) / (1024 * 1024)

    import resource

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / (1024 * 1024 if sys.platform == "darwin" else 1024)


def _install_evaluator_packages() -> None:
    """Import Guard evaluator modules without unrelated scanner package exports."""

    package_root = REPO_ROOT / "src" / "codex_plugin_scanner"
    packages = (
        ("codex_plugin_scanner", package_root),
        ("codex_plugin_scanner.guard", package_root / "guard"),
        ("codex_plugin_scanner.guard.runtime", package_root / "guard" / "runtime"),
    )
    for name, path in packages:
        package = types.ModuleType(name)
        package.__dict__["__path__"] = [str(path)]
        sys.modules[name] = package


def _worker_report(worker_index: int, worker_count: int) -> WorkerReport:
    _install_evaluator_packages()

    from codex_plugin_scanner.guard.action_lattice import guard_action_severity
    from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
    from tests.guard_command_corpus import iter_adversarial_corpus, iter_benign_corpus
    from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle

    ranks = {
        action: guard_action_severity(action)
        for action in ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
    }
    ranks["monitor"] = ranks["warn"]
    groups: defaultdict[str, list[str]] = defaultdict(list)
    streams = chain(
        zip(iter_benign_corpus(), iter_benign_oracle(), strict=True),
        zip(iter_adversarial_corpus(), iter_adversarial_oracle(), strict=True),
    )
    started = time.perf_counter()
    for position, (case, oracle) in enumerate(streams):
        if position % worker_count != worker_index:
            continue
        observed = evaluate_command(case.command, cwd=SYNTHETIC_CWD, home_dir=SYNTHETIC_HOME).minimum_action
        if ranks[observed] == ranks[oracle.minimum_floor]:
            continue
        kind = "underclassified" if ranks[observed] < ranks[oracle.minimum_floor] else "overclassified"
        key = "|".join((oracle.owner, kind, oracle.minimum_floor, observed))
        groups[key].append(case.case_id)
    return {
        "groups": dict(groups),
        "elapsed": time.perf_counter() - started,
        "rss_mib": peak_rss_mib(),
    }


def _decode_worker(stdout: str) -> WorkerReport:
    value = cast(object, json.loads(stdout))
    if not isinstance(value, dict):
        raise ValueError("worker report must be an object")
    report = cast(dict[str, object], value)
    groups_value = report.get("groups")
    elapsed, rss_mib = report.get("elapsed"), report.get("rss_mib")
    if not isinstance(groups_value, dict) or not isinstance(elapsed, int | float):
        raise ValueError("worker report shape is invalid")
    if not isinstance(rss_mib, int | float):
        raise ValueError("worker RSS must be numeric")
    groups: dict[str, list[str]] = {}
    for key, ids_value in cast(dict[object, object], groups_value).items():
        if not isinstance(key, str) or not isinstance(ids_value, list):
            raise ValueError("worker group shape is invalid")
        ids = cast(list[object], ids_value)
        if not all(isinstance(case_id, str) for case_id in ids):
            raise ValueError("worker case IDs must be strings")
        groups[key] = cast(list[str], ids)
    return {"groups": groups, "elapsed": float(elapsed), "rss_mib": float(rss_mib)}


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
    groups: defaultdict[str, list[str]] = defaultdict(list)
    started = time.perf_counter()
    reports = tuple(_iter_reports())
    elapsed = time.perf_counter() - started
    for report in reports:
        for key, case_ids in report["groups"].items():
            groups[key].extend(case_ids)
    actual = {
        key: [len(ids), hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode()).hexdigest()]
        for key, ids in groups.items()
    }
    worker_rss = [report["rss_mib"] for report in reports]
    active_worker_rss = sum(sorted(worker_rss, reverse=True)[:MAX_CONCURRENT_WORKERS])
    return {
        "actual": actual,
        "elapsed": elapsed,
        "rss_mib": peak_rss_mib() + active_worker_rss,
        "worker_elapsed": [report["elapsed"] for report in reports],
    }


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        print(json.dumps(_worker_report(int(sys.argv[2]), EVALUATION_SHARD_COUNT), sort_keys=True))
    elif len(sys.argv) == 1:
        print(json.dumps(_coordinator_report(), sort_keys=True))
    else:
        raise SystemExit("usage: guard_command_corpus_runner.py [--worker INDEX]")
