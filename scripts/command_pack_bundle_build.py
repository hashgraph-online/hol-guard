"""Automatic Hatch bundle preparation and compiler-free frozen archive verification."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

DIRECTORY = "contracts/extensions/command-pack-bundle"
MANIFEST = "contracts/extensions/command-pack-bundle-build.v1.json"


def _hash(path):
    if any(parent.is_symlink() for parent in (path, *path.parents)) or not path.is_file():
        raise ValueError("bundle build input must be a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs(root):
    """Bind authored policy/security and every implementation used to package it."""
    paths = set()
    for relative, pattern in (
        ("contributions/command-sources", "*.json"),
        ("contributions/mcp-servers", "*.json"),
        ("contracts/extensions/trust", "*.json"),
        ("contracts/extensions/revocations", "*.json"),
        ("contracts/extensions", "*.schema.json"),
        ("contracts/mcp-servers", "*.json"),
        ("contracts/catalog-delivery", "*.json"),
        ("tests/fixtures", "**/*"),
        ("scripts", "*.py"),
        ("src/codex_plugin_scanner", "**/*.py"),
        ("rust/build_support", "**/*.rs"),
        ("rust/build_support", "**/*.json"),
    ):
        for path in (root / relative).glob(pattern):
            if path.is_symlink():
                raise ValueError("bundle build input cannot be a symlink")
            if not path.is_dir() and "target" not in path.relative_to(root).parts:
                paths.add(path)
    paths.update(root / name for name in ("rust/Cargo.toml", "rust/Cargo.lock", "pyproject.toml"))
    core = root / "contracts/extensions/core-defaults.v1.json"
    if core.exists() or core.is_symlink():
        paths.add(core)
    paths.update(path for path in (root / "rust/crates").glob("*/Cargo.toml"))
    paths.update(path for path in (root / "rust/crates").glob("*/build.rs"))
    for pattern in ("*/src/**/*.rs", "*/src/**/*.json"):
        paths.update((root / "rust/crates").glob(pattern))
    paths.update(path for path in (root / "rust/crates/guard-command/tests/fixtures").glob("command-source-*.v1.json"))
    return {path.relative_to(root).as_posix(): _hash(path) for path in sorted(paths)}


def inventory(directory):
    result = {}
    total = 0
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("frozen bundle cannot contain symlinks")
        if path.is_dir():
            continue
        size = path.stat().st_size
        total += size
        if not 0 < size <= 32 * 1024 * 1024 or total > 512 * 1024 * 1024 or len(result) >= 8193:
            raise ValueError("frozen bundle exceeds package bounds")
        result[path.relative_to(directory).as_posix()] = {"sha256": _hash(path), "length": size}
    if "command-pack-bundle.v1.json" not in result:
        raise ValueError("frozen bundle is missing Root")
    return result


def frozen_manifest(root, directory):
    return {"schema": "guard.command-pack-bundle-build.v1", "inputs": inputs(root), "files": inventory(directory)}


def prepare(root: Path, *, source_archive: bool):
    """Return bundle and fingerprint paths plus a temporary-directory owner."""
    if source_archive:
        directory = root / DIRECTORY
        manifest = root / MANIFEST
        # Strict decoding is independent of application initialization.
        sys.path.insert(0, str(root / "src"))
        from codex_plugin_scanner.guard.catalog_delivery.authority import decode
        from codex_plugin_scanner.guard.extension_builder.io import read_bytes

        if decode(read_bytes(manifest, limit=8 * 1024 * 1024)) != frozen_manifest(root, directory):
            raise ValueError("source-distribution command pack bundle differs from its build inputs")
        return directory, manifest, None
    owner = tempfile.TemporaryDirectory(prefix="guard-release-bundle-")
    try:
        directory = Path(owner.name).resolve() / "command-pack-bundle"
        target_directory = Path(os.environ.get("CARGO_TARGET_DIR", str(root / "rust/target")))
        if not target_directory.is_absolute():
            target_directory = root / target_directory
        default_compiler = (
            target_directory / "debug" / ("guard-command-source.exe" if os.name == "nt" else "guard-command-source")
        )
        compiler = Path(os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER", str(default_compiler)))
        if not compiler.is_absolute():
            compiler = root / compiler
        source = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
        ).stdout.strip()
        arguments = []
        asset_output = os.environ.get("HOL_GUARD_BUNDLE_ASSET_OUTPUT")
        if asset_output:
            arguments = ["--assets-output", str(Path(asset_output).absolute())]
        subprocess.run(
            [
                sys.executable,
                str(root / "scripts/build_command_pack_bundle.py"),
                "--compiler",
                str(compiler),
                "--output",
                str(directory),
                "--source-sha",
                source,
                "--source-root",
                str(root),
                *arguments,
            ],
            cwd=root,
            check=True,
        )
        manifest = Path(owner.name).resolve() / "command-pack-bundle-build.v1.json"
        manifest.write_text(json.dumps(frozen_manifest(root, directory), sort_keys=True, separators=(",", ":")) + "\n")
        return directory, manifest, owner
    except BaseException:
        owner.cleanup()
        raise
