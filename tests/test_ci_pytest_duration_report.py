from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "pytest_duration_report.py"
sys.path.insert(0, str(SCRIPT_PATH.parent))
SPEC = importlib.util.spec_from_file_location("pytest_duration_report", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
duration_report = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = duration_report
SPEC.loader.exec_module(duration_report)


@dataclass(frozen=True)
class _Report:
    when: str
    nodeid: str
    duration: float


def test_duration_report_writes_sorted_call_phase_nodes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "durations.json"
    monkeypatch.setenv(duration_report.OUTPUT_ENV, str(output))
    duration_report.pytest_sessionstart()
    duration_report.pytest_runtest_logreport(_Report("setup", "tests/test_a.py::test_a", 8.0))
    duration_report.pytest_runtest_logreport(_Report("call", "tests/test_b.py::test_b", 2.5))
    duration_report.pytest_runtest_logreport(_Report("call", "tests/test_a.py::test_a", 1.0))

    duration_report.pytest_sessionfinish(object(), 0)

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "node_durations_seconds": {
            "tests/test_a.py::test_a": 1.0,
            "tests/test_b.py::test_b": 2.5,
        },
        "schema_version": 1,
    }
    assert duration_report.load_duration_report(output) == {
        "tests/test_a.py::test_a": 1.0,
        "tests/test_b.py::test_b": 2.5,
    }


def test_duration_report_rejects_invalid_values(tmp_path: Path) -> None:
    output = tmp_path / "durations.json"
    output.write_text('{"schema_version": 1, "node_durations_seconds": {"node": -1}}', encoding="utf-8")

    with pytest.raises(ValueError, match="invalid duration"):
        duration_report.load_duration_report(output)
