from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

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
    capstdout: str = ""


def test_duration_report_accounts_for_fixture_setup_call_and_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "durations.json"
    monkeypatch.setenv(duration_report.OUTPUT_ENV, str(output))
    duration_report.pytest_sessionstart()
    duration_report.pytest_runtest_logreport(_Report("setup", "tests/test_a.py::test_a", 8.0))
    duration_report.pytest_runtest_logreport(_Report("call", "tests/test_b.py::test_b", 2.5))
    duration_report.pytest_runtest_logreport(_Report("call", "tests/test_a.py::test_a", 1.0))
    duration_report.pytest_runtest_logreport(_Report("teardown", "tests/test_b.py::test_b", 4.0))
    duration_report.pytest_runtest_logreport(_Report("collect", "tests/test_a.py::test_a", 100.0))

    duration_report.pytest_sessionfinish(object(), 0)

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "node_durations_seconds": {
            "tests/test_a.py::test_a": 9.0,
            "tests/test_b.py::test_b": 6.5,
        },
        "schema_version": 1,
    }
    assert duration_report.load_duration_report(output) == {
        "tests/test_a.py::test_a": 9.0,
        "tests/test_b.py::test_b": 6.5,
    }


def test_worker_process_cannot_overwrite_complete_controller_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "durations.json"
    monkeypatch.setenv(duration_report.OUTPUT_ENV, str(output))
    duration_report.pytest_sessionstart()
    duration_report.pytest_runtest_logreport(_Report("call", "tests/test_a.py::test_a", 1.0))
    duration_report.pytest_sessionfinish(SimpleNamespace(config=SimpleNamespace()), 0)
    complete = output.read_bytes()

    duration_report.pytest_sessionstart()
    duration_report.pytest_runtest_logreport(_Report("call", "tests/test_b.py::test_b", 2.0))
    worker = SimpleNamespace(config=SimpleNamespace(workerinput={"workerid": "gw0"}))
    duration_report.pytest_sessionfinish(worker, 0)

    assert output.read_bytes() == complete


def test_duration_report_rejects_invalid_values(tmp_path: Path) -> None:
    output = tmp_path / "durations.json"
    output.write_text('{"schema_version": 1, "node_durations_seconds": {"node": -1}}', encoding="utf-8")

    with pytest.raises(ValueError, match="invalid duration"):
        duration_report.load_duration_report(output)


def test_offline_captured_setup_storage_reaches_controller_report_without_payloads(tmp_path, monkeypatch):
    output = tmp_path / "durations.json"
    monkeypatch.setenv(duration_report.OUTPUT_ENV, str(output))
    duration_report.pytest_sessionstart()
    node = "tests/test_native_offline_cache.py::test_complete"
    marker = '{"offline_fixture_storage": "disk"}'
    for report in (
        _Report("setup", node, 1.0, "unrelated native payload\n" + marker + "\n"),
        _Report("setup", "tests/test_other.py::test_other", 2.0, '{"offline_fixture_storage": "tmpfs"}'),
        _Report("call", node, 3.0, '{"offline_fixture_storage": "tmpfs"}'),
        _Report("setup", node, 4.0, '{"offline_fixture_storage": "/private/path"}'),
        _Report("setup", node, 5.0, "x" * 65537 + '\n{"offline_fixture_storage": "tmpfs"}'),
    ):
        duration_report.pytest_runtest_logreport(report)
    duration_report.pytest_sessionfinish(SimpleNamespace(config=SimpleNamespace()), 0)
    payload = json.loads(output.read_text())
    assert payload["fixture_storage"] == {"tests/test_native_offline_cache.py": ["disk"]}
    assert duration_report.load_duration_report(output) == {node: 13.0, "tests/test_other.py::test_other": 2.0}
    assert "private/path" not in output.read_text() and "native payload" not in output.read_text()
    duration_report.pytest_sessionstart()
    duration_report.pytest_sessionfinish(SimpleNamespace(config=SimpleNamespace()), 0)
    assert "fixture_storage" not in json.loads(output.read_text())
