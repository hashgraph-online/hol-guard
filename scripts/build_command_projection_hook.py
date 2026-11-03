"""Build package projections from authored sources with the native compiler."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface  # pyright: ignore[reportMissingImports]


def _support(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    if spec is None or spec.loader is None:
        raise ValueError("build support module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _archive_support():
    """Load archive verification beside the hook without importing the application."""
    return _support("command_projection_sdist")


def _bundle_support():
    return _support("command_pack_bundle_build")


def _verify_core(root):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, str(root / "src"))
    from installed_bundle_assets import validate_resident_core

    validate_resident_core(root)


class CommandProjectionBuildHook(BuildHookInterface):
    """Ship frozen, validated metadata without keeping copies in Git."""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """Validate packaged projections; dependency setup alone does not require Rust."""
        # CI stages resources before imports, after downloading its native outputs.
        # Compiling here would rebuild Rust independently in every coverage shard.
        if version == "editable":
            return
        root = Path(self.root)
        core_profile = (root / "contracts/extensions/core-defaults.v1.json").is_file()
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
            if core_profile:
                command.append("--projections-only")
            compiler = os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER")
            if compiler:
                compiler_path = Path(compiler)
                if not compiler_path.is_absolute():
                    compiler_path = root / compiler_path
                command.extend(["--compiler", str(compiler_path)])
            subprocess.run(command, cwd=root, check=True)
            subprocess.run([*command, "--check"], cwd=root, check=True)
        _verify_core(root)
        bundle_support = _bundle_support()
        bundle, bundle_manifest, self._bundle_owner = bundle_support.prepare(
            root, source_archive=(root / "PKG-INFO").is_file()
        )
        build_data["force_include"][str(bundle)] = (
            bundle_support.DIRECTORY
            if self.target_name == "sdist"
            else "codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle"
        )
        if self.target_name == "sdist":
            build_data["force_include"][str(bundle_manifest)] = bundle_support.MANIFEST
            build_data["force_include"][str(root / "tests/fixtures")] = "tests/fixtures"
        # Keep legacy tracked copies available to existing PRs. Only compiler
        # outputs become package metadata; do not overwrite the contributor tree.
        build_data["force_include"].pop("contributions/extensions", None)
        build_data["force_include"].pop(str(root / "contributions/extensions"), None)
        if core_profile:
            # Metadata is authenticated inside the bundle, not thousands of
            # loose optional records. Also remove old per-entry Builder maps.
            configured = getattr(self, "build_config", None)
            mappings = [build_data["force_include"]]
            if configured is not None:
                mappings.append(configured.force_include)
            for mapping in mappings:
                for source, destination in tuple(mapping.items()):
                    relative = Path(source)
                    if relative.is_absolute() and relative.is_relative_to(root):
                        relative = relative.relative_to(root)
                    if relative.as_posix().startswith(
                        ("contributions/extensions", "contracts/extensions/build-descriptors")
                    ) or (
                        self.target_name == "wheel"
                        and (
                            relative.as_posix().startswith(
                                ("contributions/mcp-servers", "contributions/command-sources")
                            )
                            or destination.startswith(
                                (
                                    "codex_plugin_scanner/guard/contracts/data/extensions/contributions",
                                    "codex_plugin_scanner/guard/contracts/data/extensions/command-sources",
                                    "codex_plugin_scanner/guard/contracts/data/mcp_servers/contributions",
                                )
                            )
                        )
                    ):
                        mapping.pop(source)
        else:
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
            archive.write_projection_manifest(
                root, descriptors=None if core_profile else descriptors, trust_map=trust_map
            )
            build_data["force_include"][str(root / archive.MANIFEST)] = archive.MANIFEST

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        owner = getattr(self, "_bundle_owner", None)
        if owner is not None:
            owner.cleanup()
