#!/usr/bin/env python3
"""Report one combined coverage database in disjoint, parallel Cobertura files."""

from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from coverage import CoverageData

MAX_WORKERS = 4
REPORT_PATTERN = "coverage-*.xml"


def _partition_files(files: set[str], workers: int) -> list[list[str]]:
    """Balance source parsing cost without duplicating or dropping measured files."""

    shards: list[list[str]] = [[] for _ in range(min(workers, len(files)))]
    loads = [0] * len(shards)
    for filename in sorted(files, key=lambda name: (-Path(name).stat().st_size, name)):
        index = min(range(len(shards)), key=lambda index: (loads[index], index))
        shards[index].append(filename)
        loads[index] += max(1, Path(filename).stat().st_size)
    return [sorted(shard) for shard in shards]


def _write_report(data_file: Path, output: Path, files: list[str]) -> Path:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "xml",
            "--data-file",
            str(data_file),
            "-o",
            str(output),
            "--",
            *files,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"coverage XML worker {output.name} failed ({result.returncode}): {detail}")
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError(f"coverage XML worker did not produce a non-empty report: {output}")
    return output


def write_reports(data_file: Path, output_directory: Path, *, workers: int = MAX_WORKERS) -> list[Path]:
    """Keep coverage's source configuration and report every measured file once."""

    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"workers must be between 1 and {MAX_WORKERS}")
    if not data_file.is_file():
        raise ValueError(f"combined coverage database is missing: {data_file}")
    output_directory.mkdir(parents=True, exist_ok=True)
    for stale in output_directory.glob(REPORT_PATTERN):
        stale.unlink()
    data = CoverageData(basename=str(data_file))
    data.read()
    files = data.measured_files()
    if not files:
        raise ValueError("combined coverage database contains no measured files")
    shards = _partition_files(files, workers)
    outputs = [output_directory / f"coverage-{index:02d}.xml" for index in range(len(shards))]
    try:
        with ThreadPoolExecutor(max_workers=len(shards)) as executor:
            return list(executor.map(_write_report, [data_file] * len(shards), outputs, shards))
    except Exception:
        # A failed batch must never leave partial reports available to the scanner.
        for output in outputs:
            output.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-file", type=Path, default=Path(".coverage"))
    parser.add_argument("--output-directory", type=Path, default=Path("coverage-reports"))
    parser.add_argument("--workers", type=int, default=MAX_WORKERS)
    args = parser.parse_args()
    try:
        outputs = write_reports(args.data_file, args.output_directory, workers=args.workers)
    except (OSError, RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Wrote {len(outputs)} disjoint coverage reports to {args.output_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
