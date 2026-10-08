from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from coverage import CoverageData

from scripts.ci import parallel_coverage_combine as combine


def _snapshot(path: Path) -> object:
    data = CoverageData(basename=str(path))
    data.read()
    return (
        data.has_arcs(),
        data.measured_contexts(),
        {
            name: (data.lines(name), data.arcs(name), data.contexts_by_lineno(name), data.file_tracer(name))
            for name in sorted(data.measured_files())
        },
    )


@pytest.mark.parametrize("branches", [False, True])
def test_parallel_combine_preserves_exact_data_and_contexts(tmp_path: Path, branches: bool) -> None:
    inputs = []
    for index in range(9):
        path = tmp_path / f"input-{index}.coverage"
        data = CoverageData(basename=str(path))
        data.set_context(f"context-{index % 3}")
        if branches:
            data.add_arcs({"src/example.py": [(-1, 1), (1, index + 2), (index + 2, -1)]})
        else:
            data.add_lines({"src/example.py": [1, index + 2]})
        data.touch_file(f"src/unexecuted-{index}.py")
        data.write()
        inputs.append(path)
    reference = tmp_path / "serial.coverage"
    subprocess.run(
        [sys.executable, "-m", "coverage", "combine", "--keep", "--data-file", str(reference), *map(str, inputs)],
        check=True,
        capture_output=True,
    )
    output = tmp_path / "parallel.coverage"
    output.write_bytes(b"stale coverage must not be appended")
    combine.combine_reports(inputs, output)
    assert _snapshot(output) == _snapshot(reference)
    assert all(path.is_file() for path in inputs)
    assert not list(tmp_path.glob("coverage-combine-*"))


def test_parallel_combine_accepts_valid_empty_coverage(tmp_path: Path) -> None:
    path = tmp_path / "empty.coverage"
    data = CoverageData(basename=str(path))
    data.add_arcs({})
    data.write()
    reference = tmp_path / "serial.coverage"
    subprocess.run(
        [sys.executable, "-m", "coverage", "combine", "--keep", "--data-file", str(reference), str(path)],
        check=True,
        capture_output=True,
    )
    output = combine.combine_reports([path], tmp_path / "combined.coverage")
    assert _snapshot(output) == _snapshot(reference)


@pytest.mark.parametrize("problem", ["missing", "empty-file", "corrupt", "mixed-modes"])
@pytest.mark.parametrize("workers", [1, 4])
def test_parallel_combine_never_publishes_partial_results(tmp_path: Path, problem: str, workers: int) -> None:
    first = tmp_path / "first.coverage"
    data = CoverageData(basename=str(first))
    data.add_arcs({"src/example.py": [(-1, 1)]})
    data.write()
    second = tmp_path / "second.coverage"
    if problem == "empty-file":
        second.touch()
    elif problem == "corrupt":
        second.write_text("not a coverage database")
    elif problem == "mixed-modes":
        other = CoverageData(basename=str(second))
        other.add_lines({"src/example.py": [1]})
        other.write()
    output = tmp_path / "combined.coverage"
    output.write_text("stale result")
    with pytest.raises((RuntimeError, ValueError)):
        combine.combine_reports([first, second], output, workers=workers)
    assert not output.exists()
    assert not list(tmp_path.glob("coverage-combine-*"))


def test_worker_that_reports_success_without_output_fails(tmp_path: Path) -> None:
    with (
        patch.object(combine.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")),
        pytest.raises(RuntimeError, match="did not produce"),
    ):
        combine._combine(tmp_path / "missing.coverage", [])


@pytest.mark.parametrize("workers", [0, 5])
def test_parallel_combine_bounds_workers(tmp_path: Path, workers: int) -> None:
    with pytest.raises(ValueError, match="workers"):
        combine.combine_reports([], tmp_path / "out.coverage", workers=workers)


def test_parallel_combine_cannot_destroy_an_input(tmp_path: Path) -> None:
    path = tmp_path / "input.coverage"
    path.write_text("retained input")
    with pytest.raises(ValueError, match="output"):
        combine.combine_reports([path], path)
    assert path.read_text() == "retained input"
