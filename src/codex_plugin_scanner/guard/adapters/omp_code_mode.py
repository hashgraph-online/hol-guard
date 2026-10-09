"""Detect Oh My Pi's Codex code mode, which routes every tool call through ``eval``."""

from __future__ import annotations

from pathlib import Path

import yaml

OMP_CODE_MODE_KEY = "providers.openai-codex.codeMode"
OMP_CODE_MODE_WARNING = (
    "Oh My Pi Codex code mode sends every tool call through eval, which Guard reviews. "
    "Set providers.openai-codex.codeMode to off in ~/.omp/agent/config.yml so Guard can "
    "allow ordinary reads and edits."
)
_ACTIVE_VALUES = frozenset({"on", "auto"})


def omp_code_mode_value(config_path: Path) -> str | None:
    """Return the configured code mode, or None when unset or unreadable."""

    try:
        if not config_path.is_file() or config_path.stat().st_size > 1_000_000:
            return None
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    value = data.get(OMP_CODE_MODE_KEY)
    if value is None:
        node: object = data
        for part in ("providers", "openai-codex", "codeMode"):
            node = node.get(part) if isinstance(node, dict) else None
        value = node
    if value is True:
        return "on"
    if isinstance(value, str):
        return value.strip().lower()
    return None


def omp_code_mode_warnings(config_path: Path) -> list[str]:
    return [OMP_CODE_MODE_WARNING] if omp_code_mode_value(config_path) in _ACTIVE_VALUES else []
