"""Safe deterministic autofixes for plugin repositories."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .marketplace_support import LEGACY_MARKETPLACE_PATH, PREFERRED_MARKETPLACE_PATH
from .path_support import normalize_codex_relative_path

_TEMPLATE_FILES: dict[str, str] = {
    ".codexignore": "# Local Codex scanner ignore list\n",
    "README.md": "# Plugin\n\nDescribe your Codex plugin here.\n",
    "SECURITY.md": "# Security Policy\n\nPlease report security issues privately.\n",
    "LICENSE": "MIT License\n",
}

_JSON_FILES = (Path(".codex-plugin/plugin.json"), PREFERRED_MARKETPLACE_PATH, LEGACY_MARKETPLACE_PATH)


def _normalize_manifest_json(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    skills = normalized.get("skills")
    if isinstance(skills, str):
        normalized["skills"] = normalize_codex_relative_path(skills)

    apps = normalized.get("apps")
    if isinstance(apps, str):
        normalized["apps"] = normalize_codex_relative_path(apps)
    elif isinstance(apps, list):
        normalized["apps"] = [normalize_codex_relative_path(item) if isinstance(item, str) else item for item in apps]

    interface = normalized.get("interface")
    if isinstance(interface, dict):
        interface = dict(interface)
        for key in ("composerIcon", "logo"):
            value = interface.get(key)
            if isinstance(value, str):
                interface[key] = normalize_codex_relative_path(value)
        screenshots = interface.get("screenshots")
        if isinstance(screenshots, list):
            interface["screenshots"] = [
                normalize_codex_relative_path(item) if isinstance(item, str) else item for item in screenshots
            ]
        normalized["interface"] = interface
    return normalized


def _normalize_marketplace_json(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    plugins = normalized.get("plugins")
    if not isinstance(plugins, list):
        return normalized
    normalized_plugins: list[Any] = []
    for plugin in plugins:
        if not isinstance(plugin, dict):
            normalized_plugins.append(plugin)
            continue
        next_plugin = dict(plugin)
        source = next_plugin.get("source")
        if isinstance(source, dict):
            source = dict(source)
            path_value = source.get("path")
            if isinstance(path_value, str):
                source["path"] = normalize_codex_relative_path(path_value)
            next_plugin["source"] = source
        elif isinstance(source, str):
            next_plugin["source"] = normalize_codex_relative_path(source)
        normalized_plugins.append(next_plugin)
    normalized["plugins"] = normalized_plugins
    return normalized


def apply_safe_autofixes(plugin_dir: Path) -> list[str]:
    changes: list[str] = []

    for relative_path, template in _TEMPLATE_FILES.items():
        target = plugin_dir / relative_path
        if not target.exists():
            target.write_text(template, encoding="utf-8")
            changes.append(f"created {relative_path}")

    for relative_path in _JSON_FILES:
        target = plugin_dir / relative_path
        if not target.exists():
            continue
        try:
            original = target.read_text(encoding="utf-8")
            parsed = json.loads(original)
        except (json.JSONDecodeError, OSError):
            continue

        if relative_path == Path(".codex-plugin/plugin.json") and isinstance(parsed, dict):
            normalized = _normalize_manifest_json(parsed)
        elif relative_path in {PREFERRED_MARKETPLACE_PATH, LEGACY_MARKETPLACE_PATH} and isinstance(parsed, dict):
            normalized = _normalize_marketplace_json(parsed)
        else:
            normalized = parsed
        rendered = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
        if rendered != original:
            target.write_text(rendered, encoding="utf-8")
            changes.append(f"normalized {relative_path}")

    return changes
