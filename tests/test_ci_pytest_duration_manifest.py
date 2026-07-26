from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "pytest_duration_manifest.py"
sys.path.insert(0, str(SCRIPT_PATH.parent))
SPEC = importlib.util.spec_from_file_location("pytest_duration_manifest", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
duration_manifest = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = duration_manifest
SPEC.loader.exec_module(duration_manifest)


def _write_report(path: Path, values: dict[str, float]) -> None:
    path.write_text(
        json.dumps({"schema_version": 1, "node_durations_seconds": values}), encoding="utf-8"
    )


def test_manifest_merges_reports_deterministically_and_rejects_duplicate_nodes(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write_report(first, {"tests/test_b.py::test_b": 2.0})
    _write_report(second, {"tests/test_a.py::test_a": 1.0})

    assert duration_manifest.merge_duration_reports([second, first]) == {
        "tests/test_a.py::test_a": 1.0,
        "tests/test_b.py::test_b": 2.0,
    }
    _write_report(second, {"tests/test_b.py::test_b": 1.0})

    with pytest.raises(ValueError, match="duplicate"):
        duration_manifest.merge_duration_reports([first, second])


def test_manifest_round_trip_and_age_validation(tmp_path: Path) -> None:
    output = tmp_path / "manifest.json"
    observed_at = datetime(2026, 7, 26, 16, 0, tzinfo=timezone.utc)
    duration_manifest.write_duration_manifest(
        output, {"tests/test_a.py::test_a": 1.0}, observed_at
    )

    assert duration_manifest.load_duration_manifest(
        output, now=observed_at + timedelta(days=27), max_age=timedelta(days=28)
    ) == {duration_manifest.node_id_digest("tests/test_a.py::test_a"): 1.0}
    assert "tests/test_a.py::test_a" not in output.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="stale"):
        duration_manifest.load_duration_manifest(
            output, now=observed_at + timedelta(days=29), max_age=timedelta(days=28)
        )
    with pytest.raises(ValueError, match="future-dated"):
        duration_manifest.load_duration_manifest(
            output, now=observed_at - timedelta(seconds=1), max_age=timedelta(days=28)
        )


def test_manifest_rejects_non_finite_durations(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    _write_report(output, {"tests/test_a.py::test_a": float("nan")})

    with pytest.raises(ValueError, match="invalid duration"):
        duration_manifest.load_duration_report(output)
