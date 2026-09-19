#!/usr/bin/env python3
"""Measure the actual MCP serve route using synthetic client and child pipes."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from profile_guard_mcp_case import run_case_common
from profile_guard_mcp_fixture import BenchmarkCaseError, Phases, fixture_arguments, summarize as _summary
from profile_guard_mcp_matrix import (
    performance_lock,
    run_matrix_common,
    run_remote_case,
    runtime_source_identity,
    write_checkpoint,
)
from profile_guard_mcp_worker import run_worker, tree_sample as _tree_sample


def _worker(config_path: Path) -> int:
    return run_worker(config_path, preparation_variant="owned")


def run_case(
    *,
    catalog_size: int = 100,
    payload_bytes: int = 1024,
    samples: int = 100,
    profile: bool = False,
    uncached: bool = False,
    child_delay_ms: float = 0,
    approval: str = "none",
    approval_delay_ms: float = 30,
    refresh_every: int = 0,
    compact_result: bool = False,
    payload_kind: str = "ascii",
    native_text_helper: Path | None = None,
    native_minimum_characters: int = 256 * 1024,
    owned_preparation_pilot: bool = False,
) -> dict[str, Any]:
    return run_case_common(
        catalog_size=catalog_size,
        payload_bytes=payload_bytes,
        samples=samples,
        profile=profile,
        uncached=uncached,
        child_delay_ms=child_delay_ms,
        approval=approval,
        approval_delay_ms=approval_delay_ms,
        refresh_every=refresh_every,
        compact_result=compact_result,
        payload_kind=payload_kind,
        native_text_helper=native_text_helper,
        native_minimum_characters=native_minimum_characters,
        preparation_variant="owned",
        preparation_pilot=owned_preparation_pilot,
    )


def run_matrix(*, samples: int, output: Path, lock_file: Path | None = None, resume: bool = False) -> dict[str, Any]:
    return run_matrix_common(
        case_runner=run_case,
        schema="hol-guard-mcp-stdio-rebaseline.v1",
        samples=samples,
        output=output,
        lock_file=lock_file,
        resume=resume,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--catalog-size", type=int, default=100)
    parser.add_argument("--payload-bytes", type=int, default=1024)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--uncached", action="store_true")
    parser.add_argument("--child-delay-ms", type=float, default=0)
    parser.add_argument("--approval", choices=("none", "accept", "cancel", "invalidate"), default="none")
    parser.add_argument("--approval-delay-ms", type=float, default=30)
    parser.add_argument("--refresh-every", type=int, default=0)
    parser.add_argument("--compact-result", action="store_true")
    parser.add_argument("--payload-kind", choices=("ascii", "unicode"), default="ascii")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.worker:
        return _worker(args.worker)
    payload_limit = 4 * 1024 * 1024 - 512 if args.compact_result else 131072
    if not (1 <= args.catalog_size <= 1000 and 1 <= args.payload_bytes <= payload_limit and 1 <= args.samples <= 10000):
        parser.error(f"catalog must be 1..1000, payload 1..{payload_limit}, samples 1..10000")
    if not (0 <= args.child_delay_ms <= 1000 and 0 <= args.approval_delay_ms <= 1000 and args.refresh_every >= 0):
        parser.error("delays must be 0..1000 ms; refresh interval must be nonnegative")
    if args.matrix:
        if args.json is None:
            parser.error("--matrix requires --json for per-case checkpoints")
        result = run_matrix(samples=args.samples, output=args.json, lock_file=args.lock_file, resume=args.resume)
        print(json.dumps({"completed_cases": result["completed_cases"], "qualification": False}))
        return 0
    if args.resume:
        parser.error("--resume requires --matrix")
    with performance_lock(args.lock_file):
        result = run_case(**{key: value for key, value in vars(args).items() if key not in {"worker", "matrix", "json", "resume", "lock_file"}})
    result.update({
        "schema": "hol-guard-mcp-stdio-profile.v1",
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "percentile_estimator": "nearest_rank",
        "remote_network": "not_measured_local_stdio_only",
        "limitations": ["source_route_not_installed_cli", "c1_only", "single_host_diagnostic", "memory_samples_are_not_absolute_peak", "profile_timings_are_not_qualification", "human_wait_is_synthetic_client_delay", "uncached_is_counterfactual_not_release"],
    })
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
