"""Shared validation helpers for native DeepSeek Harness packages."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ecosystems.types import NormalizedPackage
from .path_support import is_safe_relative_path

DSH_SEMVER_RE = re.compile(
    "".join(
        (
            r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)",
            r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?",
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
        )
    )
)
APPLY_EXPORT_RE = re.compile(
    r"(?:\bexport\s+(?:async\s+)?function\s+apply\b|\bexport\s*\{[^}]*\bapply\b|\bexports\.apply\s*=|\bmodule\.exports\.apply\s*=)",
    re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class DshValidation:
    metadata_ok: bool
    bundle_ok: bool
    patch_ok: bool
    runtime_ok: bool
    runtime_path: str | None


def _runtime_path(manifest: dict[str, object]) -> str | None:
    main = manifest.get("main")
    if isinstance(main, str) and main.strip():
        return main
    exports = manifest.get("exports")
    if isinstance(exports, str) and exports.strip():
        return exports
    if isinstance(exports, dict):
        root_export = exports.get(".")
        if isinstance(root_export, str) and root_export.strip():
            return root_export
        if isinstance(root_export, dict):
            default = root_export.get("default")
            if isinstance(default, str) and default.strip():
                return default
    return None


def validate_dsh_package(package: NormalizedPackage) -> DshValidation:
    """Validate shared DSH metadata, bundle assets, and Cordis runtime surface."""

    manifest = package.raw_manifest
    name = manifest.get("name")
    version = manifest.get("version")
    metadata_ok = (
        isinstance(name, str)
        and bool(name.strip())
        and isinstance(version, str)
        and bool(DSH_SEMVER_RE.fullmatch(version))
    )
    dsh = manifest.get("dsh")
    bundle = dsh.get("bundle") if isinstance(dsh, dict) else None
    bundle_ok = isinstance(bundle, dict) and bool(bundle)
    patch = bundle.get("patch") if isinstance(bundle, dict) else None
    patch_target = package.root_path / patch if isinstance(patch, str) else None
    patch_ok = patch is None or (
        isinstance(patch, str)
        and bool(patch.strip())
        and is_safe_relative_path(package.root_path, patch, require_exists=True)
        and patch_target is not None
        and patch_target.is_file()
        and not patch_target.is_symlink()
    )
    runtime_path = _runtime_path(manifest)
    runtime_target = package.root_path / runtime_path if runtime_path is not None else None
    runtime_ok = False
    if (
        runtime_path is not None
        and runtime_target is not None
        and is_safe_relative_path(package.root_path, runtime_path, require_exists=True)
        and runtime_target.is_file()
        and not runtime_target.is_symlink()
    ):
        try:
            runtime_ok = APPLY_EXPORT_RE.search(runtime_target.read_text(encoding="utf-8")) is not None
        except OSError:
            runtime_ok = False
    return DshValidation(metadata_ok, bundle_ok, patch_ok, runtime_ok, runtime_path)
