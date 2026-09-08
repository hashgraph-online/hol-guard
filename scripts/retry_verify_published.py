#!/usr/bin/env python3
"""Retry native published-artifact checks while a registry set is still propagating."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

ATTEMPTS = 60
SLEEP_SECONDS = 5.0
VERIFY_SCRIPT = Path(__file__).with_name("verify_native_runtime_release.py")


def is_retryable_incomplete_error(stderr: str) -> bool:
    return "missing=" in stderr and "extra=[]" in stderr and "mismatched=[]" in stderr


def wait_for_published(
    argv: Sequence[str],
    *,
    attempts: int = ATTEMPTS,
    sleep_seconds: float = SLEEP_SECONDS,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    run = runner or (
        lambda command: subprocess.run(command, check=False, capture_output=True, text=True)
    )
    command = [sys.executable, str(VERIFY_SCRIPT), "verify-published", *argv]
    last_error = "Published artifacts were not exact"
    for attempt in range(attempts):
        result = run(command)
        if result.returncode == 0:
            if result.stdout:
                sys.stdout.write(result.stdout)
            return 0
        last_error = result.stderr.strip() or last_error
        if not is_retryable_incomplete_error(result.stderr) or attempt == attempts - 1:
            if result.stderr:
                sys.stderr.write(result.stderr)
            return result.returncode or 1
        sleeper(sleep_seconds)
    print(f"Error: {last_error}", file=sys.stderr)
    return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--dist-dir", required=True)
    parser.add_argument("--artifact-set", default="full")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    forwarded = [
        "--registry",
        args.registry,
        "--version",
        args.version,
        "--source-sha",
        args.source_sha,
        "--dist-dir",
        args.dist_dir,
        "--artifact-set",
        args.artifact_set,
    ]
    return wait_for_published(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
