from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts.ci import parallel_coverage_xml


@pytest.fixture
def measured_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / "__init__.py").touch()
    for index in range(5):
        (source / f"part_{index}.py").write_text(
            f"def choose(flag):\n    if flag:\n        return 'yes'\n    return 'no'\nchoose({index % 2 == 0})\n",
            encoding="utf-8",
        )
    (source / "uncovered.py").write_text("def untouched():\n    return 42\n", encoding="utf-8")
    (tmp_path / "exercise.py").write_text("\n".join(f"import src.part_{index}" for index in range(5)), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.coverage.run]\nsource = ["src"]\nbranch = true\nrelative_files = true\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    # Override any parent CI coverage destination so this fixture stays isolated.
    monkeypatch.setenv("COVERAGE_FILE", str(tmp_path / ".coverage"))
    subprocess.run([sys.executable, "-m", "coverage", "run", "exercise.py"], check=True, capture_output=True, text=True)
    return tmp_path


def _classes(report: ET.Element) -> dict[str, tuple[dict[str, str], list[dict[str, str]]]]:
    return {
        item.attrib["filename"]: (item.attrib, [line.attrib for line in item.findall("./lines/line")])
        for item in report.findall(".//class")
    }


def test_parallel_xml_preserves_every_source_line_branch_and_coverage_total(measured_project: Path) -> None:
    serial = measured_project / "serial.xml"
    subprocess.run(
        [sys.executable, "-m", "coverage", "xml", "-o", str(serial)], check=True, capture_output=True, text=True
    )
    output = measured_project / "reports"
    output.mkdir()
    stale = output / "coverage-99.xml"
    stale.write_text("stale coverage", encoding="utf-8")
    unrelated = output / "keep.txt"
    unrelated.write_text("keep", encoding="utf-8")

    paths = parallel_coverage_xml.write_reports(measured_project / ".coverage", output)

    assert len(paths) == 4
    assert not stale.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"
    baseline = ET.parse(serial).getroot()
    reports = [ET.parse(path).getroot() for path in paths]
    original = _classes(baseline)
    combined = {}
    for report in reports:
        classes = _classes(report)
        assert not combined.keys() & classes.keys()
        combined.update(classes)
    assert combined == original
    assert len(combined) == 7
    assert combined["uncovered.py"][0]["line-rate"] == "0"
    assert any("condition-coverage" in line for _attributes, lines in combined.values() for line in lines)
    for field in ("lines-valid", "lines-covered", "branches-valid", "branches-covered"):
        assert sum(int(report.attrib[field]) for report in reports) == int(baseline.attrib[field])
    assert {item.text for report in reports for item in report.findall("./sources/source")} == {
        item.text for item in baseline.findall("./sources/source")
    }


def test_parallel_xml_propagates_worker_failure_and_removes_partial_reports(measured_project: Path) -> None:
    (measured_project / "src/part_1.py").write_text("def broken(:\n", encoding="utf-8")
    output = measured_project / "reports"

    with pytest.raises(RuntimeError, match=r"coverage XML worker .* failed"):
        parallel_coverage_xml.write_reports(measured_project / ".coverage", output)

    assert list(output.glob(parallel_coverage_xml.REPORT_PATTERN)) == []


def test_parallel_xml_rejects_successful_workers_without_reports(
    measured_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        parallel_coverage_xml.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    output = measured_project / "reports"

    with pytest.raises(RuntimeError, match="did not produce a non-empty report"):
        parallel_coverage_xml.write_reports(measured_project / ".coverage", output)

    assert list(output.glob(parallel_coverage_xml.REPORT_PATTERN)) == []


@pytest.mark.parametrize("workers", [0, 5])
def test_parallel_xml_bounds_worker_count(tmp_path: Path, workers: int) -> None:
    with pytest.raises(ValueError, match="workers must be between"):
        parallel_coverage_xml.write_reports(tmp_path / ".coverage", tmp_path / "reports", workers=workers)
