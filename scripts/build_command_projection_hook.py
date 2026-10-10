"""Build package projections from authored sources with the native compiler."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def _archive_support():
    """Load archive verification beside the hook without importing the application."""
    spec = importlib.util.spec_from_file_location(
        "command_projection_sdist", Path(__file__).with_name("command_projection_sdist.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CommandProjectionBuildHook(BuildHookInterface):
    """Ship frozen, validated metadata without keeping copies in Git."""

    def initialize(self, version: str, build_data: dict) -> None:
        """Validate packaged projections; dependency setup alone does not require Rust."""
        # CI stages resources before imports, after downloading its native outputs.
        # Compiling here would rebuild Rust independently in every coverage shard.
        if version == "editable":
            return
        root = Path(self.root)
        archive = _archive_support()
        descriptors = root / "contributions/extensions"
        trust_map = root / "contracts/extensions/trust-class-map.v1.json"
        if (root / "PKG-INFO").is_file():
            # Hatch source archives carry frozen projections plus a fingerprint
            # of all authored inputs. Verify those without requiring Cargo.
            archive.verify_projection_manifest(root)
        else:
            descriptors = root / "contracts/extensions/build-descriptors"
            trust_map = root / "contracts/extensions/build-trust-class-map.v1.json"
            command = [
                sys.executable,
                str(root / "scripts/build_native_command_program.py"),
                "--descriptor-dir",
                str(descriptors),
            ]
            compiler = os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER")
            if compiler:
                compiler_path = Path(compiler)
                if not compiler_path.is_absolute():
                    compiler_path = root / compiler_path
                command.extend(["--compiler", str(compiler_path)])
            subprocess.run(command, cwd=root, check=True)
            subprocess.run([*command, "--check"], cwd=root, check=True)
        # Keep legacy tracked copies available to existing PRs. Only compiler
        # outputs become package metadata; do not overwrite the contributor tree.
        build_data["force_include"].pop("contributions/extensions", None)
        build_data["force_include"].pop(str(root / "contributions/extensions"), None)
        build_data["force_include"][str(descriptors)] = (
            "contributions/extensions"
            if self.target_name == "sdist"
            else "codex_plugin_scanner/guard/contracts/data/extensions/contributions"
        )
        build_data["force_include"].pop("contracts/extensions/trust-class-map.v1.json", None)
        # Register only after generation so editable dependency setup works
        # with absent outputs. Ignored files still travel in both artifacts.
        for name in archive.NAMES:
            relative = f"contracts/extensions/{name}"
            destination = (
                relative
                if self.target_name == "sdist"
                else f"codex_plugin_scanner/guard/contracts/data/extensions/{name}"
            )
            source = trust_map if name == "trust-class-map.v1.json" else root / relative
            build_data["force_include"][str(source)] = destination
        if self.target_name == "sdist":
            archive.write_projection_manifest(root, descriptors=descriptors, trust_map=trust_map)
            build_data["force_include"][str(root / archive.MANIFEST)] = archive.MANIFEST
