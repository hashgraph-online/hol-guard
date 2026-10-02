"""Package build-owned native projections; contributors maintain no generated copies."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict) -> None:
        """Stage editable resources or include them explicitly in a distribution."""
        # A CI dependency-install step can precede the same-run artifact download.
        # The source test bootstrap validates resources before importing Guard.
        if version == "editable" and os.environ.get("HOL_GUARD_CI_DEFER_RESOURCE_BUILD") == "1":
            return
        root = Path(self.root)
        spec = importlib.util.spec_from_file_location(
            "guard_resource_builder", root / "scripts/build_guard_resources.py"
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("resource builder is missing")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        manifest = module.prepare(root)
        if version == "editable":
            # Force-including a regular package can shadow the editable source.
            # Resources have already been staged into the source package.
            return
        prefix = "src/" if self.target_name == "sdist" else ""
        for name in manifest["outputs"]:
            if name.startswith("src/codex_plugin_scanner/"):
                build_data["force_include"][str(root / name)] = prefix + name.removeprefix("src/")
