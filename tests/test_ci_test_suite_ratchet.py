from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "test_suite_ratchet.py"
SPEC = importlib.util.spec_from_file_location("test_suite_ratchet", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
test_suite_ratchet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = test_suite_ratchet
SPEC.loader.exec_module(test_suite_ratchet)


def test_ratchet_accepts_current_or_smaller_metrics() -> None:
    baseline = test_suite_ratchet.TestSuiteRatchetBaseline(100, 200)

    assert test_suite_ratchet.validation_errors(baseline, collected_cases=100, test_source_lines=199) == ()


def test_ratchet_reports_every_unexplained_growth() -> None:
    baseline = test_suite_ratchet.TestSuiteRatchetBaseline(100, 200)

    assert test_suite_ratchet.validation_errors(baseline, collected_cases=101, test_source_lines=201) == (
        "collected cases grew from 100 to 101; update the reviewed ratchet baseline if this is intentional",
        "test source lines grew from 200 to 201; update the reviewed ratchet baseline if this is intentional",
    )


def test_load_inventory_metrics_requires_nested_inventory_shape(tmp_path: Path) -> None:
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"inventory": {"collected_cases": 4}, "test_source_lines": 20}), encoding="utf-8")

    assert test_suite_ratchet.load_inventory_metrics(path) == (4, 20)
    path.write_text(json.dumps({"test_source_lines": 20}), encoding="utf-8")

    with pytest.raises(ValueError, match="missing inventory"):
        test_suite_ratchet.load_inventory_metrics(path)


def test_load_baseline_rejects_invalid_schema(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"schema_version": 2}), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported"):
        test_suite_ratchet.load_baseline(path)
