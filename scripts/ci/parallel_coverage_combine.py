#!/usr/bin/env python3
"""Combine every coverage input through bounded, independent CLI workers."""

from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

from coverage import CoverageData
from coverage.exceptions import CoverageException

MAX_WORKERS = 4


def _combine(output: Path, inputs: list[Path]) -> Path:
    result = subprocess.run(
        [sys.executable, "-m", "coverage", "combine", "--keep", "--data-file", str(output), *map(str, inputs)],
        capture_output=True,
        text=True,
        check=False,
    )
    # Coverage can otherwise warn about an unreadable input and succeed with a subset.
    if result.returncode or result.stderr.strip() or "Couldn't combine data file" in result.stdout:
        raise RuntimeError(f"coverage combine failed: {result.stderr.strip() or result.stdout.strip()}")
    if not output.is_file() or not output.stat().st_size:
        raise RuntimeError(f"coverage combine did not produce a database: {output}")
    data = CoverageData(basename=str(output))
    data.read()
    return output


def combine_reports(inputs: list[Path], output: Path, *, workers: int = MAX_WORKERS) -> Path:
    """Preserve coverage's path mapping and all lines, arcs, contexts, and empty files."""
    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"workers must be between 1 and {MAX_WORKERS}")
    output = output.resolve()
    inputs = [path.resolve() for path in inputs]
    if output in inputs:
        raise ValueError("output must not replace an input coverage database")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    if not inputs or any(not path.is_file() or not path.stat().st_size for path in inputs):
        raise ValueError("every coverage input must be an existing non-empty database file")
    groups: list[list[Path]] = [[] for _ in range(min(workers, len(inputs)))]
    sizes = [0] * len(groups)
    for path in sorted(inputs, key=lambda path: (-path.stat().st_size, str(path))):
        index = min(range(len(groups)), key=lambda index: (sizes[index], index))
        groups[index].append(path)
        sizes[index] += path.stat().st_size
    with TemporaryDirectory(prefix="coverage-combine-", dir=output.parent) as directory:
        staging = Path(directory)
        partials = [staging / f"partial-{index}.coverage" for index in range(len(groups))]
        with ThreadPoolExecutor(max_workers=len(groups)) as executor:
            list(executor.map(_combine, partials, groups))
        combined = _combine(staging / "combined.coverage", partials)
        combined.replace(output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=MAX_WORKERS)
    parser.add_argument("--data-file", type=Path, default=Path(".coverage"))
    parser.add_argument("inputs", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        output = combine_reports(args.inputs, args.data_file, workers=args.workers)
    except (OSError, RuntimeError, ValueError, CoverageException) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Combined all {len(args.inputs)} coverage inputs into {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
