from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT_PATH = Path("scripts/release/stage_guard_cloud_review_artifacts.py")
SPEC = importlib.util.spec_from_file_location("stage_guard_cloud_review_artifacts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _write_artifacts(root: Path) -> None:
    for source_name in MODULE._ARTIFACTS:
        source = root / source_name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(source_name, encoding="utf-8")


def test_stage_artifacts_copies_every_canonical_artifact(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    staged = MODULE.stage_artifacts(tmp_path)

    assert len(staged) == 4
    for source_name, destination_name in MODULE._ARTIFACTS.items():
        destination = tmp_path / "src/codex_plugin_scanner/guard/contracts/data/guard-cloud-review" / destination_name
        assert destination.read_text(encoding="utf-8") == source_name


def test_stage_artifacts_fails_closed_when_source_is_missing(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "contracts/guard-cloud-review/v2/contract.json").unlink()

    with pytest.raises(FileNotFoundError, match=r"contract\.json"):
        MODULE.stage_artifacts(tmp_path)
