from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/release/stage_guard_cloud_review_artifacts.py"
SPEC = importlib.util.spec_from_file_location("stage_guard_cloud_review_artifacts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _write_artifacts(root: Path) -> None:
    for source_name in MODULE._ARTIFACTS:
        source = root / source_name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(source_name, encoding="utf-8")


def test_stage_artifacts_matches_wheel_package_data(tmp_path: Path) -> None:
    repository = SCRIPT_PATH.parents[2]
    pyproject = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    package_prefix = "codex_plugin_scanner/guard/contracts/data/"
    artifacts = {
        source: destination.removeprefix(package_prefix)
        for source, destination in pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"].items()
        if destination.startswith(package_prefix)
    }
    assert artifacts
    for source_name in artifacts:
        source = tmp_path / source_name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes((repository / source_name).read_bytes())

    staged = MODULE.stage_artifacts(tmp_path)

    data_root = tmp_path / "src/codex_plugin_scanner/guard/contracts/data"
    assert {path.relative_to(data_root).as_posix() for path in staged if path.name != "__init__.py"} == set(
        artifacts.values()
    )
    for source_name, destination_name in artifacts.items():
        destination = data_root / destination_name
        assert destination.read_bytes() == (repository / source_name).read_bytes()
    assert (data_root / "extensions" / "__init__.py").is_file()
    assert (data_root / "extensions" / "contributions" / "__init__.py").is_file()
    assert (data_root / "extensions" / "trust-class-map.v1.json").is_file()
    assert not (data_root / "guard-cloud-review" / "__init__.py").exists()


def test_stage_artifacts_fails_closed_when_source_is_missing(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "contracts/guard-cloud-review/v2/contract.json").unlink()

    with pytest.raises(FileNotFoundError, match=r"contract\.json"):
        MODULE.stage_artifacts(tmp_path)


def test_stage_artifacts_includes_existing_package_inits(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    data_root = tmp_path / "src/codex_plugin_scanner/guard/contracts/data"
    extensions = data_root / "extensions"
    extensions.mkdir(parents=True, exist_ok=True)
    (extensions / "__init__.py").write_text("", encoding="utf-8")

    staged = MODULE.stage_artifacts(tmp_path)

    assert extensions / "__init__.py" in staged
