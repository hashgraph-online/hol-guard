#!/usr/bin/env python3
"""Matched warm-path latency measurement across installed Guard wheels (measurement only).

Each ``--target label=sha=/path/to/venv/bin/python`` names a Python environment
with an installed wheel built from that revision. Targets run on the same
machine, round by round, with the order alternating between rounds so slow
drift does not favor either side. Nothing here enforces a threshold.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from warm_path_probes import clean_env, run_hook_phase, run_mcp_phase
from warm_path_stats import describe

SCHEMA = "guard.warm-path-latency.v1"
_CANARY = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "mcp-canary-server.py"


def _read_first(path: str, prefix: str) -> str:
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.startswith(prefix):
                return line.split(":", 1)[1].strip()
    except OSError:
        return ""
    return ""


def runner_description() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_model": _read_first("/proc/cpuinfo", "model name"),
        "logical_cpus": os.cpu_count(),
        "memory_total": _read_first("/proc/meminfo", "MemTotal"),
        "image_os": os.environ.get("ImageOS", ""),  # noqa: SIM112
        "image_version": os.environ.get("ImageVersion", ""),  # noqa: SIM112
        "runner_name_class": os.environ.get("RUNNER_ENVIRONMENT", ""),
    }


def calibrate(python: Path, env: dict[str, str], runs: int = 25) -> dict[str, float]:
    """Time bare interpreter spawns as a same-runner drift indicator."""

    samples: list[float] = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        subprocess.run([str(python), "-c", "pass"], env=env, capture_output=True, check=True, timeout=30)
        samples.append((time.perf_counter_ns() - started) / 1e6)
    return describe(samples)


def installed_version(python: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        [str(python), "-c", "import importlib.metadata as m; print(m.version('hol-guard'))"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    return result.stdout.strip() or "unknown"


def parse_target(text: str) -> tuple[str, str, Path]:
    label, sha, python = text.split("=", 2)
    return label, sha, Path(python)


def measure_target(label: str, python: Path, args: argparse.Namespace) -> dict[str, object]:
    cli = python.parent / "hol-guard"
    result: dict[str, object] = {"loadavg_before": os.getloadavg()}
    with tempfile.TemporaryDirectory(prefix="wpl-") as scratch:
        base = Path(scratch)
        env = clean_env(python, base / "calibration-home")
        (base / "calibration-home").mkdir()
        result["calibration_spawn_ms"] = calibrate(python, env)
        for path in args.paths:
            root = base / path
            root.mkdir()
            try:
                if path == "hook":
                    phase = run_hook_phase(
                        cli, clean_env(python, root / "home"), root, warmup=args.hook_warmup, samples=args.hook_samples
                    )
                else:
                    phase = run_mcp_phase(
                        cli,
                        clean_env(python, root / "home"),
                        root,
                        canary=_CANARY,
                        interpreter=sys.executable,
                        warmup=args.mcp_warmup,
                        samples=args.mcp_samples,
                    )
            except Exception as error:  # keep the other path and later rounds measurable
                phase = {"error": f"{type(error).__name__}: {error}"[:4000]}
                print(f"  {label} {path} FAILED {phase['error']}", flush=True)
            else:
                print(f"  {label} {path} p95={phase['stats_ms']['p95']:.2f} ms classes={phase['classes']}", flush=True)  # type: ignore[index]
            result[path] = phase
    result["loadavg_after"] = os.getloadavg()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", required=True, help="label=sha=/path/to/python")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--paths", nargs="+", choices=("hook", "mcp"), default=["hook", "mcp"])
    parser.add_argument("--hook-warmup", type=int, default=20)
    parser.add_argument("--hook-samples", type=int, default=300)
    parser.add_argument("--mcp-warmup", type=int, default=50)
    parser.add_argument("--mcp-samples", type=int, default=1000)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()

    targets = [parse_target(text) for text in args.target]
    labels = [label for label, _, _ in targets]
    if len(set(labels)) != len(labels):
        parser.error("target labels must be unique")
    versions = {
        label: installed_version(python, clean_env(python, Path(tempfile.gettempdir()))) for label, _, python in targets
    }
    document: dict[str, object] = {
        "schema": SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "runner": runner_description(),
        "config": {
            "rounds": args.rounds,
            "paths": args.paths,
            "hook_warmup": args.hook_warmup,
            "hook_samples": args.hook_samples,
            "mcp_warmup": args.mcp_warmup,
            "mcp_samples": args.mcp_samples,
        },
        "targets": [{"label": label, "sha": sha, "wheel_version": versions[label]} for label, sha, _ in targets],
        "rounds": [],
    }
    by_label = {label: python for label, _, python in targets}
    for round_index in range(args.rounds):
        # Alternate which target goes first so neither side owns the cold half of a round.
        order = labels if round_index % 2 == 0 else list(reversed(labels))
        print(f"round {round_index + 1}/{args.rounds} order={order}", flush=True)
        results = {label: measure_target(label, by_label[label], args) for label in order}
        document["rounds"].append({"round": round_index + 1, "order": order, "results": results})  # type: ignore[union-attr]
        args.json.write_text(json.dumps(document), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
