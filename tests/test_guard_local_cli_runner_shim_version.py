from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.local_cli_runner import installed_package_version


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
