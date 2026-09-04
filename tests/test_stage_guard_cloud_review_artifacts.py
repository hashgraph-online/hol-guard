from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/release/stage_guard_cloud_review_artifacts.py"
SPEC = importlib.util.spec_from_file_location("stage_guard_cloud_review_artifacts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

_MAPPINGS = {
    "contracts/guard-cloud-review/v2/contract.json": "codex_plugin_scanner/guard/contracts/data/guard-cloud-review/v2/contract.json",
    "contracts/extensions/trust-class-map.v1.json": "codex_plugin_scanner/guard/contracts/data/extensions/trust-class-map.v1.json",
}


def _write_source_tree(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[tool.hatch.build.targets.wheel.force-include]",
                *(f'"{source}" = "{destination}"' for source, destination in _MAPPINGS.items()),
            ]
        ),
        encoding="utf-8",
    )
    for source_name in _MAPPINGS:
        source = root / source_name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(source_name, encoding="utf-8")


def test_stage_artifacts_copies_every_force_include_mapping(tmp_path: Path) -> None:
    _write_source_tree(tmp_path)

    staged = MODULE.stage_artifacts(tmp_path)

    assert set(staged) == {tmp_path / "src" / destination for destination in _MAPPINGS.values()}
    for source_name, destination_name in _MAPPINGS.items():
        staged_file = tmp_path / "src" / destination_name
        assert staged_file.read_text(encoding="utf-8") == source_name


def test_stage_artifacts_fails_closed_when_source_is_missing(tmp_path: Path) -> None:
    _write_source_tree(tmp_path)
    (tmp_path / "contracts/extensions/trust-class-map.v1.json").unlink()

    with pytest.raises(FileNotFoundError, match=r"trust-class-map\.v1\.json"):
        MODULE.stage_artifacts(tmp_path)


def test_stage_artifacts_fails_closed_without_mapping_table(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"force-include"):
        MODULE.stage_artifacts(tmp_path)


def test_staging_this_repository_materializes_the_extension_trust_map() -> None:
    """The real pyproject mappings must include the runtime trust-class map."""

    repo_root = Path(__file__).resolve().parents[1]
    mappings = MODULE._force_includes(repo_root / "pyproject.toml")

    assert any(
        destination.endswith("guard/contracts/data/extensions/trust-class-map.v1.json")
        for destination in mappings.values()
    )
