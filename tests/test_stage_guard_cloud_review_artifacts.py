from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/release/stage_guard_cloud_review_artifacts.py"
SPEC = importlib.util.spec_from_file_location("stage_guard_cloud_review_artifacts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _write_artifacts(root: Path) -> dict[str, str]:
    artifacts = dict(MODULE._STATIC_ARTIFACTS)
    artifacts["contributions/extensions/command.example.json"] = "extensions/contributions/command.example.json"
    artifacts["contributions/mcp-servers/mcp.example.json"] = "mcp_servers/contributions/mcp.example.json"
    for source_name in artifacts:
        source = root / source_name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(source_name, encoding="utf-8")
    binding = root / "contracts/extensions/trust/command.example.v1.json"
    binding.parent.mkdir(parents=True, exist_ok=True)
    binding.write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": "command.example",
                "trustClass": "external",
            }
        )
    )
    return artifacts


def test_external_destination_preserves_source_package_data(tmp_path: Path) -> None:
    source, destination = tmp_path / "source", tmp_path / "bundle-data"
    artifacts = _write_artifacts(source)
    staged = MODULE.stage_artifacts(source, destination_root=destination)
    assert all(path.is_relative_to(destination) for path in staged)
    assert not (source / "src").exists()
    for source_name, destination_name in artifacts.items():
        assert (destination / destination_name).read_bytes() == (source / source_name).read_bytes()


def test_stage_artifacts_copies_every_canonical_artifact(tmp_path: Path) -> None:
    artifacts = _write_artifacts(tmp_path)

    staged = MODULE.stage_artifacts(tmp_path)

    data_root = tmp_path / "src/codex_plugin_scanner/guard/contracts/data"
    assert len(staged) >= len(artifacts)
    for source_name, destination_name in artifacts.items():
        destination = data_root / destination_name
        assert destination.read_text(encoding="utf-8") == source_name
    assert (data_root / "extensions" / "__init__.py").is_file()
    assert (data_root / "extensions" / "contributions" / "__init__.py").is_file()
    assert (data_root / "extensions" / "trust-class-map.v1.json").is_file()
    assert not (tmp_path / "contracts/extensions/trust-class-map.v1.json").exists()
    trust = json.loads((data_root / "extensions/trust-class-map.v1.json").read_text())
    assert trust["classes"]["external"] == ["command.example"]
    assert not (data_root / "guard-cloud-review" / "__init__.py").exists()


def test_stage_artifacts_fails_closed_when_source_is_missing(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "contracts/guard-cloud-review/v2/contract.json").unlink()

    with pytest.raises(FileNotFoundError, match=r"contract\.json"):
        MODULE.stage_artifacts(tmp_path)


def test_stage_artifacts_validates_before_resetting_staged_contributions(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    MODULE.stage_artifacts(tmp_path)
    data_root = tmp_path / "src/codex_plugin_scanner/guard/contracts/data"
    staged_mcp = data_root / "mcp_servers/contributions/mcp.example.json"
    assert staged_mcp.is_file()
    (tmp_path / "contracts/guard-cloud-review/v2/contract.json").unlink()

    with pytest.raises(FileNotFoundError, match=r"contract\.json"):
        MODULE.stage_artifacts(tmp_path)

    assert staged_mcp.is_file()


def test_stage_artifacts_removes_stale_staged_contributions(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    MODULE.stage_artifacts(tmp_path)
    data_root = tmp_path / "src/codex_plugin_scanner/guard/contracts/data"
    staged_mcp = data_root / "mcp_servers/contributions/mcp.example.json"
    assert staged_mcp.is_file()

    (tmp_path / "contributions/mcp-servers/mcp.example.json").unlink()
    (tmp_path / "contributions/mcp-servers/mcp.second.json").write_text("mcp.second", encoding="utf-8")
    MODULE.stage_artifacts(tmp_path)

    assert not staged_mcp.exists()
    assert (data_root / "mcp_servers/contributions/mcp.second.json").read_text(encoding="utf-8") == "mcp.second"


def test_stage_artifacts_fails_closed_on_empty_contribution_directory(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "contributions/mcp-servers/mcp.example.json").unlink()

    with pytest.raises(FileNotFoundError, match=r"mcp-servers"):
        MODULE.stage_artifacts(tmp_path)


def test_stage_artifacts_includes_existing_package_inits(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    data_root = tmp_path / "src/codex_plugin_scanner/guard/contracts/data"
    extensions = data_root / "extensions"
    extensions.mkdir(parents=True, exist_ok=True)
    (extensions / "__init__.py").write_text("", encoding="utf-8")

    staged = MODULE.stage_artifacts(tmp_path)

    assert extensions / "__init__.py" in staged
