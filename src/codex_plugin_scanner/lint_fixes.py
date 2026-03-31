"""Safe deterministic autofixes for plugin repositories."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_TEMPLATE_FILES: dict[str, str] = {
    ".codexignore": "# Local Codex scanner ignore list\n",
    "README.md": "# Plugin\n\nDescribe your Codex plugin here.\n",
    "SECURITY.md": "# Security Policy\n\nPlease report security issues privately.\n",
    "LICENSE": "MIT License\n",
}


_JSON_FILES = ("plugin.json", "marketplace.json")


def _normalize_json_paths(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _normalize_json_paths(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_json_paths(item) for item in value]
    if isinstance(value, str) and value.startswith("./"):
        return value[2:]
    return value


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

        normalized = _normalize_json_paths(parsed)
        rendered = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
        if rendered != original:
            target.write_text(rendered, encoding="utf-8")
            changes.append(f"normalized {relative_path}")

    return changes
