"""Detect Oh My Pi's Codex code mode, which routes every tool call through ``eval``."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

import yaml

from .base import HarnessContext

OMP_CODE_MODE_KEY = "providers.openai-codex.codeMode"
OMP_CODE_MODE_WARNING = (
    "Oh My Pi Codex code mode sends every tool call through eval, which Guard reviews. "
    "Set providers.openai-codex.codeMode to off in {path} so Guard can allow ordinary reads and edits."
)
_ACTIVE_VALUES = frozenset({"on", "auto"})
_MAX_CONFIG_BYTES = 1_000_000
_USER_CONFIG_NAMES = ("config.yml", "config.yaml")


def omp_code_mode_value(config_path: Path) -> str | None:
    """Return the configured code mode, or None when unset or unreadable."""

    try:
        if not config_path.is_file() or config_path.stat().st_size > _MAX_CONFIG_BYTES:
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
    if value is False:
        return "off"
    if isinstance(value, str):
        return value.strip().lower()
    return None


def omp_config_layers(
    home_dir: Path, workspace_dir: Path | None, environ: Mapping[str, str] | None = None
) -> list[Path]:
    """Return the Oh My Pi settings files that can set code mode, lowest precedence first.

    Mirrors Oh My Pi's loader: the agent directory comes from ``PI_CODING_AGENT_DIR`` or
    ``<home>/<PI_CONFIG_DIR or .omp>/agent`` and uses the first of ``config.yml`` and
    ``config.yaml``; a project ``.omp/config.yml`` overrides it.
    """

    env = os.environ if environ is None else environ
    override = env.get("PI_CODING_AGENT_DIR")
    agent_dir = Path(override).expanduser() if override else home_dir / (env.get("PI_CONFIG_DIR") or ".omp") / "agent"
    layers = [next((agent_dir / name for name in _USER_CONFIG_NAMES if (agent_dir / name).is_file()), None)]
    if workspace_dir is not None:
        layers.append(workspace_dir / ".omp" / "config.yml")
    return [path for path in layers if path is not None]


def omp_code_mode_warnings(
    home_dir: Path, workspace_dir: Path | None = None, environ: Mapping[str, str] | None = None
) -> list[str]:
    effective: tuple[str, Path] | None = None
    for path in omp_config_layers(home_dir, workspace_dir, environ):
        value = omp_code_mode_value(path)
        if value is not None:
            effective = (value, path)
    if effective is None or effective[0] not in _ACTIVE_VALUES:
        return []
    return [OMP_CODE_MODE_WARNING.format(path=effective[1])]


def with_omp_code_mode_warnings(payload: dict[str, object], context: HarnessContext) -> dict[str, object]:
    # An explicit doctor home describes another installation, so the caller's OMP env does not apply.
    environ: Mapping[str, str] | None = {} if context.home_override_explicit else None
    extra = omp_code_mode_warnings(context.home_dir, context.workspace_dir, environ)
    if extra:
        existing = payload.get("warnings")
        payload["warnings"] = [*(existing if isinstance(existing, list) else []), *extra]
    return payload
