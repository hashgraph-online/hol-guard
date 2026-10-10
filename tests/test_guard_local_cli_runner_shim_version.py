from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.local_cli_runner import installed_package_version, shim_bin_target


def _write_shim_workspace(workspace: Path, package_name: str, version: str) -> Path:
    package_dir = workspace / "node_modules" / Path(*package_name.split("/"))
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text(
        f'{{"name":"{package_name}","version":"{version}"}}\n',
        encoding="utf-8",
    )
    bin_dir = workspace / "node_modules" / ".bin"
    bin_dir.mkdir()
    shim = bin_dir / package_name.rsplit("/", 1)[-1]
    # npm on Windows and pnpm write regular-file shims, not symlinks.
    shim.write_text('#!/bin/sh\nexec node "$basedir/../pkg/bin.js" "$@"\n', encoding="utf-8")
    return shim


def test_regular_file_bin_shim_reads_sibling_package_version(tmp_path: Path) -> None:
    shim = _write_shim_workspace(tmp_path, "wrangler", "4.149.0")

    assert installed_package_version(shim, "wrangler") == "4.149.0"


def test_regular_file_bin_shim_reads_scoped_package_version(tmp_path: Path) -> None:
    shim = _write_shim_workspace(tmp_path, "@scope/tool", "1.2.3")

    assert installed_package_version(shim, "@scope/tool") == "1.2.3"


def test_regular_file_bin_shim_rejects_mismatched_or_unsafe_package(tmp_path: Path) -> None:
    shim = _write_shim_workspace(tmp_path, "wrangler", "4.149.0")

    assert installed_package_version(shim, "other") is None
    assert installed_package_version(shim, "../wrangler") is None


def _write_bin_package(node_modules: Path, bin_field: object) -> Path:
    import json

    package_dir = node_modules / "wrangler"
    (package_dir / "bin").mkdir(parents=True)
    script = package_dir / "bin" / "wrangler.js"
    script.write_text("console.log('v1')\n", encoding="utf-8")
    (package_dir / "package.json").write_text(
        json.dumps({"name": "wrangler", "version": "4.149.0", "bin": bin_field}),
        encoding="utf-8",
    )
    return script


def test_shim_bin_target_hashes_the_launched_script_and_tracks_changes(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    script = _write_bin_package(node_modules, {"wrangler": "./bin/wrangler.js"})

    first = shim_bin_target(node_modules, "wrangler", "wrangler")
    assert first is not None
    assert first["resolved_path"] == str(script.resolve())
    script.write_text("console.log('v2')\n", encoding="utf-8")
    second = shim_bin_target(node_modules, "wrangler", "wrangler")
    assert second is not None
    assert second["content_hash"] != first["content_hash"]


def test_shim_bin_target_accepts_string_bin_for_the_package_name(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    _write_bin_package(node_modules, "bin/wrangler.js")

    assert shim_bin_target(node_modules, "wrangler", "wrangler") is not None
    assert shim_bin_target(node_modules, "wrangler", "other") is None


def test_shim_bin_target_rejects_missing_or_escaping_entries(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    (tmp_path / "outside.js").write_text("x\n", encoding="utf-8")
    _write_bin_package(node_modules, {"wrangler": "../../outside.js", "w2": "./bin/missing.js"})

    assert shim_bin_target(node_modules, "wrangler", "wrangler") is None
    assert shim_bin_target(node_modules, "wrangler", "w2") is None
    assert shim_bin_target(node_modules, "wrangler", "absent") is None
