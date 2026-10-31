"""The MCP bundle packer checks the manifest and writes a zip without the MCPB CLI."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from scripts.ci.pack_mcpb import MAX_LIST, MAX_MANIFEST_BYTES, PackError, pack_bundle

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "distributions" / "mcpb"
EXPECTED = ("manifest.json", "pyproject.toml", "server/main.py")


def _copy_bundle(tmp_path: Path) -> Path:
    destination = tmp_path / "bundle"
    shutil.copytree(BUNDLE, destination)
    return destination


def _members(archive: Path) -> list[str]:
    with zipfile.ZipFile(archive) as packed:
        return packed.namelist()


def test_pack_ships_the_bundle_files(tmp_path: Path) -> None:
    output = tmp_path / "hol-guard.mcpb"
    assert pack_bundle(BUNDLE, output) == list(EXPECTED)
    with zipfile.ZipFile(output) as packed:
        for name in EXPECTED:
            assert packed.read(name) == (BUNDLE / name).read_bytes()
    again = tmp_path / "again.mcpb"
    pack_bundle(BUNDLE, again)
    assert output.read_bytes() == again.read_bytes()


def test_cli_packs_without_site_packages(tmp_path: Path) -> None:
    output = tmp_path / "hol-guard.mcpb"
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(ROOT / "scripts/ci/pack_mcpb.py"), str(BUNDLE), str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert _members(output) == list(EXPECTED)
    assert "server/main.py" in completed.stdout


def test_cache_files_are_left_out(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    cache = bundle / "server" / "__pycache__"
    cache.mkdir()
    (cache / "main.cpython-311.pyc").write_bytes(b"cached")
    (bundle / ".DS_Store").write_bytes(b"junk")
    output = tmp_path / "hol-guard.mcpb"
    assert pack_bundle(bundle, output) == list(EXPECTED)


def test_symlink_is_refused(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (bundle / "linked.txt").symlink_to(outside)
    with pytest.raises(PackError, match="refuse symlink"):
        pack_bundle(bundle, tmp_path / "hol-guard.mcpb")


def test_extra_file_is_refused(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    (bundle / "README.md").write_text("notes", encoding="utf-8")
    with pytest.raises(PackError, match="extra="):
        pack_bundle(bundle, tmp_path / "hol-guard.mcpb")


def test_entry_point_escape_is_refused(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["server"]["entry_point"] = "../outside.py"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(PackError, match="inside the bundle"):
        pack_bundle(bundle, tmp_path / "hol-guard.mcpb")


def test_project_file_accepts_equivalent_toml(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    version = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))["version"]
    text = (bundle / "pyproject.toml").read_text(encoding="utf-8")
    text = text.replace(f'version = "{version}"', f"version = '{version}'")
    text = text.replace(f'"hol-guard=={version}"', f"'hol-guard=={version}'")
    (bundle / "pyproject.toml").write_text(text, encoding="utf-8")
    assert pack_bundle(bundle, tmp_path / "hol-guard.mcpb") == list(EXPECTED)


def test_dependency_text_outside_the_dependency_list_is_refused(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    version = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))["version"]
    (bundle / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "hol-guard-mcpb-runtime"',
                f'version = "{version}"',
                "dependencies = []",
                "",
                "[tool.note]",
                f'comment = "hol-guard=={version}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(PackError, match="depend on the manifest version"):
        pack_bundle(bundle, tmp_path / "hol-guard.mcpb")


def test_partial_symlink_does_not_replace_its_target(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    output = tmp_path / "hol-guard.mcpb"
    target = tmp_path / "target.txt"
    target.write_text("keep", encoding="utf-8")
    output.with_name(output.name + ".partial").symlink_to(target)
    pack_bundle(bundle, output)
    assert target.read_text(encoding="utf-8") == "keep"
    assert output.is_file() and not output.is_symlink()


def test_pyproject_version_must_match_the_manifest(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "9.9.9"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(PackError, match="version must match the manifest"):
        pack_bundle(bundle, tmp_path / "hol-guard.mcpb")


def test_tool_list_is_bounded(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tools"] = [{"name": f"tool-{index}", "description": "x"} for index in range(MAX_LIST + 1)]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(PackError, match="tools must be a list"):
        pack_bundle(bundle, tmp_path / "hol-guard.mcpb")


def test_duplicate_manifest_key_is_refused(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    (bundle / "manifest.json").write_text('{"manifest_version": "0.4", "manifest_version": "0.4"}\n', encoding="utf-8")
    with pytest.raises(PackError, match="duplicate manifest key"):
        pack_bundle(bundle, tmp_path / "hol-guard.mcpb")


def test_oversized_manifest_is_refused(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    (bundle / "manifest.json").write_bytes(b"{" + b" " * (MAX_MANIFEST_BYTES + 1))
    with pytest.raises(PackError, match="64 KiB"):
        pack_bundle(bundle, tmp_path / "hol-guard.mcpb")


def test_release_workflows_pack_without_the_mcpb_cli() -> None:
    workflows = ROOT / ".github" / "workflows"
    combined = "\n".join(path.read_text(encoding="utf-8") for path in workflows.glob("*.yml"))
    assert ".github/tools/mcpb-cli" not in combined
    assert "@anthropic-ai/mcpb" not in combined
    assert combined.count("python3 scripts/ci/pack_mcpb.py") == 3
    gates = (workflows / "security-gates.yml").read_text(encoding="utf-8")
    assert "harden-forge" not in gates
    assert "--vex" not in gates
    ignore = (ROOT / ".trivyignore").read_text(encoding="utf-8")
    assert "CVE-2026-85393" not in ignore
    assert "@anthropic-ai/mcpb" not in ignore
    dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert "mcpb-cli" not in dependabot
