"""Repository layout detection for plugin and marketplace roots."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .checks.manifest import load_manifest
from .marketplace_support import (
    extract_marketplace_source,
    load_marketplace_context,
    validate_marketplace_path_requirements,
)
from .models import ScanSkipTarget


@dataclass(frozen=True, slots=True)
class LocalPluginTarget:
    """A local plugin discovered from a repo marketplace."""

    name: str
    plugin_dir: Path
    source_path: str


@dataclass(frozen=True, slots=True)
class ScanDiscovery:
    """Resolved scan targets for a path."""

    scope: str
    root_dir: Path
    marketplace_file: Path | None = None
    local_plugins: tuple[LocalPluginTarget, ...] = ()
    skipped_targets: tuple[ScanSkipTarget, ...] = ()


def _manifest_name(plugin_dir: Path) -> str | None:
    manifest = load_manifest(plugin_dir)
    name = manifest.get("name") if isinstance(manifest, dict) else None
    return name if isinstance(name, str) and name else None


def discover_scan_targets(target_dir: str | Path) -> ScanDiscovery:
    """Detect whether a path is a single plugin or a repo marketplace root."""

    resolved = Path(target_dir).resolve()
    manifest_path = resolved / ".codex-plugin" / "plugin.json"
    if manifest_path.exists():
        return ScanDiscovery(
            scope="plugin",
            root_dir=resolved,
            local_plugins=(
                LocalPluginTarget(
                    name=_manifest_name(resolved) or resolved.name,
                    plugin_dir=resolved,
                    source_path="./",
                ),
            ),
        )

    try:
        context = load_marketplace_context(resolved)
    except (json.JSONDecodeError, OSError, ValueError):
        context = None

    if context is None:
        return ScanDiscovery(scope="plugin", root_dir=resolved)

    plugins = context.payload.get("plugins")
    if not isinstance(plugins, list):
        return ScanDiscovery(
            scope="repository",
            root_dir=resolved,
            marketplace_file=context.file_path,
            skipped_targets=(ScanSkipTarget(name="plugins", reason="marketplace plugins array missing"),),
        )

    local_plugins: list[LocalPluginTarget] = []
    skipped_targets: list[ScanSkipTarget] = []
    for index, plugin in enumerate(plugins):
        entry_name = f"plugin[{index}]"
        if not isinstance(plugin, dict):
            skipped_targets.append(ScanSkipTarget(name=entry_name, reason="marketplace entry is not an object"))
            continue

        name = plugin.get("name")
        if isinstance(name, str) and name:
            entry_name = name

        source_ref, source_path = extract_marketplace_source(plugin)
        if source_ref and source_ref != "local":
            skipped_targets.append(
                ScanSkipTarget(
                    name=entry_name,
                    reason=f"non-local marketplace source: {source_ref}",
                    source_path=source_path,
                )
            )
            continue

        issue = validate_marketplace_path_requirements(context, plugin)
        if issue is not None:
            skipped_targets.append(ScanSkipTarget(name=entry_name, reason=issue, source_path=source_path))
            continue

        if source_path is None:
            skipped_targets.append(ScanSkipTarget(name=entry_name, reason='missing "source.path"'))
            continue

        plugin_dir = (context.repo_root / source_path).resolve()
        plugin_manifest = plugin_dir / ".codex-plugin" / "plugin.json"
        if not plugin_manifest.exists():
            skipped_targets.append(
                ScanSkipTarget(
                    name=entry_name,
                    reason="local plugin manifest not found",
                    source_path=source_path,
                )
            )
            continue

        local_plugins.append(
            LocalPluginTarget(
                name=_manifest_name(plugin_dir) or entry_name,
                plugin_dir=plugin_dir,
                source_path=source_path,
            )
        )

    return ScanDiscovery(
        scope="repository",
        root_dir=resolved,
        marketplace_file=context.file_path,
        local_plugins=tuple(local_plugins),
        skipped_targets=tuple(skipped_targets),
    )
